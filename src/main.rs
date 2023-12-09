#![feature(decl_macro)]

use std::collections::HashSet;
use std::future::Future;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::process::{exit, Command, Stdio};
use std::{fs::File, io::Read, os::fd::AsFd, path::PathBuf};

use anyhow::anyhow;
use capctl::prctl;
use clap::{Parser, Subcommand};
use daggy::petgraph::data::Build;
use ipnetwork::IpNetwork;
use libc::SIGTERM;
use log::LevelFilter::{self, Debug};
use netlink_ops::netlink::{nl_ctx, NLDriver, NLHandle, VethConn};
use netlink_ops::rtnetlink::netlink_proto::{new_connection_from_socket, NetlinkCodec};
use netlink_ops::rtnetlink::netlink_sys::protocols::NETLINK_ROUTE;
use netlink_ops::rtnetlink::netlink_sys::{AsyncSocket, Socket, TokioSocket};
use netlink_ops::rtnetlink::Handle;
use netlink_ops::state::{Existence, ExpCollection};
use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::waitpid;
use nix::unistd::{fork, getpid, getppid, sethostname, setresuid, ForkResult, Pid, Uid};
use nsproxy::data::{Graphs, NodeI, ObjectNode, PassFD, ProcNS, Relation, TUNC};
use nsproxy::managed::{Indexed, ItemAction, ItemCreate, NodeWDeps, ServiceM, Socks2TUN, SrcNode};
use nsproxy::paths::{PathState, Paths};
use nsproxy::sys::{check_capsys, your_shell, UserNS};
use nsproxy::*;
use nsproxy::{data::Ix, systemd};
use nsproxy_common::{ExactNS, PidPath};
use passfd::FdPassingExt;
use std::os::unix::net::{UnixListener, UnixStream};
use tun::Layer;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "an alternative to proxychains based on linux kernel namespaces"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// One of the many methods, use TUN2Proxy and pass a device FD to it.
    /// TUN2proxy will connect to a SOCKS5 proxy in its NS, and serve a TUN in the app NS.
    SOCKS2TUN {
        #[arg(long, short)]
        pid: Option<pid_t>,
        /// Config file for Tun2proxy
        #[arg(long, short)]
        tun2proxy: PathBuf,
        /// Command to run
        cmd: Option<String>,
    },
    /// Start as watcher daemon
    Watch {},
    /// Run probe process acccording to the graph. ID for Node ID
    Probe {
        id: Ix,
    },
    /// Run TUN2Proxy daemon.
    /// This must be run as a systemd service
    TUN2proxy {
        conf: PathBuf,
    },
    /// Requires root or equivalent.
    /// Initiatializes user and mount namespaces.
    /// Actions other than this may be performed (also usually) rootlessly
    /// It's recommend to use SUDO because I need the deprivileged UID
    Init {
        /// Deinit
        #[arg(long, short)]
        undo: bool,
    },
    Info,
    /// Enter the initialized user&mnt ns
    Userns {
        #[arg(long, short)]
        rmall: bool,
        /// You can not set to UIDs that have not been mapped in uid_map
        #[arg(long, short)]
        uid: Option<u32>,
        #[arg(long, short)]
        node: Option<Ix>,
    },
    Node {
        id: Ix,
        /// Command to run
        cmd: Option<String>,
    },
    Veth {
        #[arg(long, short)]
        uid: Option<u32>,
        /// Command to run
        cmd: Option<String>,
    },
}

fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(LevelFilter::Info)
        .parse_default_env()
        .init();
    let cli = Cli::parse();
    let paths: Paths = PathState::default()?.into();
    let mut graphs = Graphs::load_file(&paths)?;
    // We must use a one thread runtime to not mess up NS.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match cli.command {
        Commands::SOCKS2TUN {
            pid,
            mut tun2proxy,
            cmd,
        } => {
            let capsys = check_capsys();
            tun2proxy = tun2proxy.canonicalize()?;
            // Connect and authenticate to systemd before entering userns
            let pre = rt.block_on(async { zbus::Connection::session().await })?;
            let mut uns = None;
            match capsys {
                Ok(_) => {
                    // The user is using SUID or sudo, or we are alredy in a userns, or user did setcap.
                    // Probably intentional
                }
                _ => {
                    log::warn!("CAP_SYS_ADMIN not available, entering user NS (I assume you want to use UserNS)");
                    uns = Some(paths.userns().procns()?);
                    uns.as_ref().unwrap().enter()?;
                    log::info!("Entered user, mnt NS");
                    check_capsys()?;
                }
            }
            graphs.retain()?;
            let (mut sp, mut sc) = UnixStream::pair()?;
            let mut buf = [0; 1];
            // NS by Pid --send fd of TUN/socket--> NS of TUN2proxy
            let src = if let Some(pid) = pid {
                graphs.add_object(PidPath::N(pid), &paths, uns.as_ref())?
            } else {
                match unsafe { fork() }? {
                    ForkResult::Child => {
                        unshare(CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUTS)?;
                        sc.write_all(&[0])?;
                        sethostname("proxied")?;
                        sc.read_exact(&mut buf)?;
                        let mut cmd = Command::new(your_shell(cmd)?.ok_or(anyhow!(
                            "--cgomd must be specified when --pid is not provided"
                        ))?);
                        // NOTE: when parent process crashed, the child process fish shell got broken stdout and stderr
                        // It probably dead looped on it and ate up the CPU.
                        // TODO: crash test, and make sure child process doesnt get broken pipe.
                        // Alternatively kill child processes.
                        // let mut cmd: tokio::process::Command = cmd.into();
                        prctl::set_pdeathsig(Some(SIGTERM))?;
                        sc.read_exact(&mut buf)?;
                        let mut ch = cmd.spawn()?;
                        ch.wait()?;
                        exit(0);
                    }
                    ForkResult::Parent { child } => {
                        sp.read_exact(&mut buf)?;
                        let k =
                            graphs.add_object(PidPath::N(child.as_raw()), &paths, uns.as_ref())?;
                        sp.write_all(&[1])?;
                        k
                    }
                }
            }; // Source of TUNFD/SocketFD
            let out = graphs.add_object(PidPath::Selfproc, &paths, uns.as_ref())?;
            // dbg!(&graphs.data.node_indices().collect::<Vec<_>>());
            let edge = graphs.data.add_edge(src, out, None);
            rt.block_on(async move {
                let socks2t = Socks2TUN::new(&tun2proxy, edge)?;
                let serv = systemd::Systemd::new(&paths, pre).await?;
                let ctx = serv.ctx().await?;
                // TODO: TUN2proxy when TAP
                let rel = socks2t.write(Layer::L3, &serv).await?;
                graphs.data[edge].replace(rel);
                graphs.dump_file(&paths)?;
                graphs.write_probes(&serv).await?;
                serv.reload(&ctx).await?;
                let (probe, deps) = graphs.nodewdeps(src)?;
                deps.restart(&serv, &ctx).await?;
                probe.restart(&serv, &ctx).await?;
                aok!()
            })?;
            sp.write_all(&[2])?;
            // Wait for the child, or it gets orphaned.
            waitpid(Some(Pid::from_raw(-1)), None)?;
        }
        Commands::Probe { id } => {
            // Load graphs, send FDs over socket
            let (node, deps) = graphs.nodewdeps(NodeI::from(id))?;
            node.item.validate()?;
            node.item.main.enter()?;
            for edge in deps {
                match edge.item {
                    Relation::SendSocket(p) => p.pass()?,
                    Relation::SendTUN(p) => p.pass()?,
                }
            }
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let wh = NLDriver::new(NLHandle::new_self_proc_tokio()?);
                // let mut nl = NLStateful::new(&wh);
                // nl.fill().await?;
                let li = wh.conn.get_link("tun0".parse()?).await?;
                wh.conn
                    .ip_add_route(li.header.index, None, Some(true))
                    .await?;
                wh.conn
                    .ip_add_route(li.header.index, None, Some(false))
                    .await?;
                wh.conn
                    .add_addr_dev(IpNetwork::new("100.64.0.2".parse()?, 16)?, li.header.index)
                    .await?;
                // It must have a source addr so the TUN driver can send packets back.
                // It shows as 0.0.0.0 if there isn't an ddress
                let li = wh.conn.get_link("lo".parse()?).await?;
                wh.conn.set_link_up(li.header.index).await?;
                aok!()
            })?;
        }
        Commands::TUN2proxy { conf } => {
            // Setns, recv FD, start daemon
            // Recv a TUN FD, and/or a upstream socket FD
            // Socket activation
            let mut fds = libsystemd::activation::receive_descriptors(true)?;
            let fdx = fds.pop().unwrap();
            let fdx = unsafe { UnixListener::from_raw_fd(fdx.into_raw_fd()) };
            log::info!("Waiting for device FD");
            let (conn, _addr) = fdx.accept()?;
            let devfd: RawFd = conn.recv_fd()?;
            log::info!("Got FD");
            let args = tun2proxy::load_conf(conf)?;
            log::info!("{:?}", args);
            tun2proxy::tuntap(args, devfd)?;
        }
        Commands::Watch {} => {}
        Commands::Init { undo } => {
            let usern = UserNS(&paths);
            // Fuck smart-anything.
            // Will not do anything unanticipated. Init means init
            check_capsys()?;
            paths.create_dirs_priv()?;
            if undo {
                usern.deinit()?;
            } else {
                if usern.exist()? {
                    log::error!("UserNS has already been initialized");
                } else {
                    let owner = std::env::var("SUDO_UID")?.parse()?;
                    usern.init(owner)?;
                    log::info!("{:?}", usern.paths());
                }
            }
        }
        Commands::Userns { rmall, uid, node } => {
            let usern = UserNS(&paths);
            if usern.exist()? {
                usern.procns()?.enter()?;
                if rmall {
                    ProcNS::rmall(&paths)?;
                } else {
                    // This process gains full caps after setns, so we can do whatever.
                    if let Some(uid) = uid {
                        let u = Uid::from_raw(uid);
                        setresuid(u, u, u)?;
                    }

                    let mut cmd =
                        Command::new(your_shell(None)?.ok_or(anyhow!("specify env var SHELL"))?);
                    cmd.spawn()?.wait()?;
                }
            } else {
                log::error!("UserNS does not exist");
            }
        }
        Commands::Node { id, cmd } => {
            let ix = NodeI::from(id);

            let node = graphs
                .data
                .node_weight(ix)
                .ok_or(anyhow!("Specified node does not exist"))?
                .as_ref() // Second one is an invariant
                .unwrap();
            node.main.enter()?;
            let mut cmd = Command::new(your_shell(None)?.ok_or(anyhow!("specify env var SHELL"))?);
            cmd.spawn()?.wait()?;
        }
        Commands::Info => {
            log::info!("{:?}", &paths);
            log::info!(
                "UserNS, {:?}, mounted: {}",
                paths.userns().paths(),
                paths.userns().exist()?
            );
        }
        Commands::Veth { mut uid, cmd } => {
            // sysctl net.ipv4.ip_forward=1
            check_capsys()?;
            let mut k = [0; 1];
            let (mut sp, mut sc) = UnixStream::pair()?;
            match unsafe { fork() }? {
                ForkResult::Child => {
                    unshare(CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUTS)?;
                    sethostname("proxied")?;
                    let nl = Socket::new(NETLINK_ROUTE)?;
                    nl.set_non_blocking(true)?;
                    sc.send_fd(nl.as_raw_fd())?;
                    if uid.is_none() {
                        let sudoid = std::env::var("SUDO_UID");
                        if let Ok(id) = sudoid {
                            uid = Some(id.parse()?);
                        } else {
                            uid = Some(1000)
                        }
                    }
                    let u = Uid::from_raw(uid.unwrap());
                    setresuid(u, u, u)?;
                    // sp.write_all(&[0])?;
                    // sp.read_exact(&mut k)?;
                    prctl::set_pdeathsig(Some(SIGTERM))?;
                    let mut cmd =
                        Command::new(your_shell(cmd)?.ok_or(anyhow!("specify env var SHELL"))?);
                    cmd.spawn()?.wait()?;
                }
                ForkResult::Parent { child } => {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    rt.block_on(async {
                        let fd = sp.recv_fd()?;
                        let (conn, h, _) =
                            new_connection_from_socket::<_, _, NetlinkCodec>(unsafe {
                                TokioSocket::from_raw_fd(fd)
                            });
                        rt.spawn(conn);
                        let h = NLHandle::new(
                            Handle::new(h),
                            ExactNS::from_pid(nsproxy_common::PidPath::N(child.as_raw()), "net")?,
                        );
                        let mut nl_ch = NLDriver::new(h);
                        let mut nl = NLDriver::new(NLHandle::new_self_proc_tokio()?);
                        nl_ch.fill().await?;
                        nl.fill().await?;
                        let mut addrset: HashSet<IpNetwork> = HashSet::default(); // find unused subnet
                        {
                            nl_ctx!(link, conn, nl_ch);
                            conn.set_up(link.map.get_mut(&"lo".parse()?).unwrap().exist_mut()?)
                                .await?;
                            for (k, ex) in link.map {
                                if let Existence::Exist(li) = ex {
                                    match &li.addrs {
                                        ExpCollection::Filled(addr) => {
                                            addrset.extend(addr.keys().into_iter());
                                        }
                                        _ => (),
                                    }
                                }
                            }
                        }

                        let vc = VethConn {
                            subnet_veth: "100.67.0.0/24".parse()?,
                            subnet6_veth: "fe80:2e::/24".parse()?,
                            ip_va: "100.67.0.1/24".parse()?,
                            ip_vb: "100.67.0.2/24".parse()?,
                            ip6_va: "fe80:2e::1/24".parse()?,
                            ip6_vb: "fe80:2e::2/24".parse()?,
                            key: "ve".parse()?,
                        };
                        vc.apply(&mut nl_ch, &mut nl).await?;
                        let mut nl_ch = NLDriver::new(nl_ch.conn);
                        let mut nl = NLDriver::new(nl.conn);
                        nl_ch.fill().await?;
                        nl.fill().await?;
                        vc.apply_addr_up(&mut nl_ch, &mut nl).await?;
                        aok!()
                    })?;
                    waitpid(Some(Pid::from_raw(-1)), None)?;
                }
            }
        }
    }
    Ok(())
}
