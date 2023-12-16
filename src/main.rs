#![feature(decl_macro)]
#![feature(iter_next_chunk)]
#![feature(array_try_map)]

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::future::Future;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{exit, Command, Stdio};
use std::{fs::File, io::Read, os::fd::AsFd, path::PathBuf};

use anyhow::{anyhow, bail, ensure};
use capctl::prctl;
use clap::{Parser, Subcommand};
use daggy::petgraph::data::Build;
use id_alloc::NetRange;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use libc::{uid_t, SIGTERM};
use log::LevelFilter::{self, Debug};
use netlink_ops::netlink::{nl_ctx, NLDriver, NLHandle, VethConn};
use netlink_ops::rtnetlink::netlink_proto::{new_connection_from_socket, NetlinkCodec};
use netlink_ops::rtnetlink::netlink_sys::protocols::NETLINK_ROUTE;
use netlink_ops::rtnetlink::netlink_sys::{AsyncSocket, Socket, TokioSocket};
use netlink_ops::rtnetlink::Handle;
use netlink_ops::state::{Existence, ExpCollection};
use nix::sched::{setns, unshare, CloneFlags};
use nix::sys::wait::waitpid;
use nix::unistd::{fork, getgid, getpid, getppid, sethostname, setresuid, ForkResult, Pid, Uid};
use nsproxy::data::{
    FDRecver, Graphs, NSAdd, NSGroup, NSSlot, NSState, NodeAddr, NodeI, ObjectNode, PassFD,
    Relation, Validate, ValidateR, TUNC,
};
use nsproxy::managed::{
    Indexed, ItemAction, ItemCreate, NodeIDPrint, NodeIndexed, NodeWDeps, ServiceM, Socks2TUN,
};
use nsproxy::paths::{PathState, Paths};
use nsproxy::sys::{
    check_capsys, cmd_uid, enable_ping_all, enable_ping_gid, what_uid, your_shell, UserNS,
};
use nsproxy::systemd::UnitName;
use nsproxy::*;
use nsproxy::{data::Ix, systemd};
use nsproxy_common::NSSource::Unavail;
use nsproxy_common::{ExactNS, NSFrom, PidPath, VaCache};
use owo_colors::OwoColorize;
use passfd::FdPassingExt;
use petgraph::visit::IntoNodeReferences;
use std::os::unix::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tracing::instrument::WithSubscriber;
use tracing::{info, warn, Level};
use tracing_log::LogTracer;
use tracing_subscriber::FmtSubscriber;
use tun::{AsyncDevice, Configuration, Layer};

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
        #[arg(long, short)]
        uid: Option<uid_t>,
        #[arg(long, short)]
        name: Option<String>,
        /// Create a new user NS, instead of using an existing one.
        #[arg(long)]
        new_userns: bool,
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
        #[arg(long, short, value_parser=parse_node)]
        node: Option<NodeAddr>,
    },
    Node {
        #[arg(value_parser=parse_node)]
        id: Option<NodeAddr>,
        #[command(subcommand)]
        op: Option<NodeOps>,
    },
    /// It's recommended to use this through "sproxy" the SUID wrapper
    Veth {
        #[arg(long, short)]
        uid: Option<u32>,
        /// Command to run
        cmd: Option<String>,
    },
    Setns {
        pid: u32,
        cmd: Option<String>,
        #[arg(long, short)]
        uid: Option<u32>,
    },
}

fn parse_node(addr: &str) -> Result<NodeAddr> {
    if let Ok(ix) = addr.parse::<Ix>() {
        Ok(NodeAddr::Ix(ix.into()))
    } else {
        Ok(NodeAddr::Name(addr.into()))
    }
}

#[derive(Subcommand)]
enum NodeOps {
    Logs {
        #[arg(long, short = 'n', default_value = "30")]
        lines: u32,
    },
    Run {
        /// Command to run
        cmd: Option<String>,
        #[arg(long, short)]
        uid: Option<u32>,
    },
    Reboot,
}

fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .compact()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    LogTracer::init()?;
    info!("SHA1: {}", env!("VERGEN_GIT_SHA"));

    let cli = Cli::parse();
    let paths: Paths = PathState::default()?.into();

    // We must use a one thread runtime to not mess up NS.

    match cli.command {
        Commands::SOCKS2TUN {
            pid,
            mut tun2proxy,
            cmd,
            uid,
            name,
            new_userns,
        } => {
            let mut graphs = Graphs::load_file(&paths)?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let capsys = check_capsys();
            let uid = what_uid(uid, true)?;
            tun2proxy = tun2proxy.canonicalize()?;
            // Connect and authenticate to systemd before entering userns
            let pre = rt.block_on(async { zbus::Connection::session().await })?;
            let mut uns = None;
            let mut va = VaCache::default();
            graphs.prune(&mut va)?;
            let gid = getgid();

            match capsys {
                Ok(_) => {
                    // The user is using SUID or sudo, or we are alredy in a userns, or user did setcap.
                    // Probably intentional
                }
                _ => {
                    log::warn!("CAP_SYS_ADMIN not available, entering user NS (I assume you want to use UserNS)");
                    if !new_userns {
                        uns = Some(paths.userns().procns()?);
                        if !paths.userns().exist()? {
                            println!(
                                "User NS does not exist. Create it as root with command {}",
                                "nsproxy init".bright_yellow()
                            );
                            exit(-1);
                        }
                        let ctx = NSGroup::proc_path(PidPath::Selfproc, None)?;
                        uns.as_ref().unwrap().enter(&ctx)?;
                        log::info!("Entered user, mnt NS");
                    } else {
                        log::warn!(
                            "Unsharing into a new UserNS. This method currently has limitations."
                        );
                        unshare(CloneFlags::CLONE_NEWUSER)?;

                        let mut f = OpenOptions::new()
                            .write(true)
                            .open(format!("/proc/self/uid_map"))?;
                        f.write_all(format!("{uid} {uid} 1").as_bytes())?;

                        let mut f = OpenOptions::new()
                            .write(true)
                            .open(format!("/proc/self/setgroups"))?;
                        f.write_all(b"deny")?;

                        let mut f = OpenOptions::new()
                            .write(true)
                            .open(format!("/proc/self/gid_map"))?;
                        f.write_all(format!("{gid} {gid} 1",).as_bytes())?;
                        // let spid = getpid();
                        uns = Some(NSGroup {
                            /// we have unshared user ns
                            user: NSSlot::from_source(PidPath::Selfproc)?,
                            ..Default::default()
                        });
                    }
                    check_capsys()?;
                }
            }
            let ns_add = if new_userns {
                NSAdd::RecordProcfsPaths
            } else {
                NSAdd::RecordMountedPaths
            };
            graphs.prune(&mut va)?;
            let (mut sp, mut sc) = UnixStream::pair()?;
            let mut buf = [0; 1];
            // NS by Pid --send fd of TUN/socket--> NS of TUN2proxy
            let src = if let Some(pid) = pid {
                graphs.add_ns(PidPath::N(pid), &paths, uns.as_ref(), ns_add)?
            } else {
                match unsafe { fork() }? {
                    ForkResult::Child => {
                        unshare(CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUTS)?;
                        sc.write_all(&[0])?;
                        sethostname("proxied")?;
                        if new_userns {
                            enable_ping_gid(gid)?
                        } else {
                            enable_ping_all()?;
                        }
                        sc.read_exact(&mut buf)?;
                        let mut cmd = Command::new(your_shell(cmd)?.ok_or(anyhow!(
                            "--cmd must be specified when --pid is not provided"
                        ))?);
                        // We don't change uid of this process.
                        // Otherwise probe might fail due to perms

                        cmd.uid(uid);
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
                        let k = graphs.add_ns(
                            PidPath::N(child.as_raw()),
                            &paths,
                            uns.as_ref(),
                            // We have no privs to mount with when new_userns==true
                            ns_add,
                        )?;
                        sp.write_all(&[1])?;
                        k
                    }
                }
            }; // Source of TUNFD/SocketFD
            if let Some(na) = name {
                graphs.name.insert(na, src);
            }
            let out = graphs.add_ns(
                PidPath::Selfproc,
                &paths,
                uns.as_ref(),
                NSAdd::RecordNothing,
            )?;
            // dbg!(&graphs.data.node_indices().collect::<Vec<_>>());
            let edge = graphs.data.add_edge(src, out, None);
            log::info!(
                "Src/Probe {src:?} {}, OutNode(This process), Src -> Out {edge:?}",
                graphs.data[src].as_ref().unwrap().main.key()
            );
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
            let graphs = Graphs::load_file(&paths)?;
            // Load graphs, send FDs over socket
            let (node, deps) = graphs.nodewdeps(NodeI::from(id))?;
            let mut va = VaCache::default();
            let mut nss = NSState {
                target: &node.item.main,
                va: &mut va,
            };
            log::info!("{:?}", &node.item.main);
            nss.validated_enter()?;

            for rel in deps {
                match rel.edge.item {
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
                let li = wh.conn.get_link(crate::PROBE_TUN.parse()?).await?;
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
            let mut cf = File::open(&conf)?;
            let args: tun2socks5::IArgs = serde_json::from_reader(&mut cf)?;
            log::info!("{:?}", args);
            let devconf = Configuration::default();
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let dev = tun::platform::linux::Device::from_raw_fd(devfd, &devconf)?;
                let dev = AsyncDevice::new(dev)?;
                let (sx, rx) = mpsc::channel(1);
                tun2socks5::main_entry(dev, 1500, true, args, rx).await?;

                aok!()
            })?;
        }
        Commands::Watch {} => {}
        Commands::Init { undo } => {
            let usern = UserNS(&paths);
            check_capsys()?;
            paths.create_dirs_priv()?;
            if undo {
                usern.deinit()?;
                std::fs::remove_file(Graphs::path(&paths))?;
            } else {
                if usern.exist()? {
                    log::error!("UserNS has already been initialized");
                } else {
                    let mut graphs = Graphs::load_file(&paths)?;
                    let ctx = NSGroup::proc_path(PidPath::Selfproc, None)?;
                    let owner = std::env::var("SUDO_UID")?.parse()?;
                    usern.init(owner)?;
                    graphs.dump_file(&paths)?;
                    log::info!("{:?}", usern.paths());
                }
            }
        }
        Commands::Userns { rmall, uid, node } => {
            let usern = UserNS(&paths);
            if usern.exist()? {
                let ctx = NSGroup::proc_path(PidPath::Selfproc, None)?;
                usern.procns()?.enter(&ctx)?;
                if rmall {
                    NSGroup::rmall(&paths)?;
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
        Commands::Node { id, op } => {
            let graphs = Graphs::load_file(&paths)?;
            let require_id = || {
                if let Some(id) = id {
                    graphs.resolve(&id)
                } else {
                    bail!("Node operation requires a node address (name/id)")
                }
            };
            // We gain full caps after setns
            if let Some(op) = op {
                match op {
                    NodeOps::Run { cmd, uid } => {
                        let ix = require_id()?;
                        let node = graphs
                            .data
                            .node_weight(ix)
                            .ok_or(anyhow!("Specified node does not exist"))?
                            .as_ref() // Second one is an invariant
                            .unwrap();
                        let ctx = NSGroup::proc_path(PidPath::Selfproc, None)?;
                        node.main.enter(&ctx)?;
                        cmd_uid(uid, true)?;
                        let mut cmd =
                            Command::new(your_shell(cmd)?.ok_or(anyhow!("specify env var SHELL"))?);
                        cmd.spawn()?.wait()?;
                    }
                    NodeOps::Logs { lines } => {
                        let ix = require_id()?;
                        let mut cmd = Command::new("journalctl");
                        let (node, deps) = graphs.nodewdeps(ix)?;
                        if deps.len() == 0 {
                            println!("No dependencies. No logs to show");
                        } else {
                            let serv = match deps[0].edge.item.fd_recver() {
                                FDRecver::TUN2Proxy(ref path) => {
                                    Socks2TUN::new(path, deps[0].edge.id)?.service()?
                                }
                                FDRecver::Systemd(serv) => serv.to_owned(),
                                _ => {
                                    warn!("No dependency known");
                                    return Ok(());
                                }
                            };
                            cmd.args(
                                format!("-n{lines} -o cat --follow -b --user-unit")
                                    .split(" ")
                                    .chain([serv.as_str()]),
                            );
                            let mut ch = cmd.spawn()?;
                            ch.wait()?;
                        }
                    }
                    NodeOps::Reboot => {
                        let ix = require_id()?;
                        let (node, deps) = graphs.nodewdeps(ix)?;
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?;
                        rt.block_on(async {
                            let conn = zbus::Connection::session().await?;
                            let serv = systemd::Systemd::new(&paths, conn).await?;
                            let ctx = serv.ctx().await?;
                            deps.restart(&serv, &ctx).await?;
                            node.restart(&serv, &ctx).await?;
                            aok!()
                        })?;
                    }
                }
            } else {
                match op {
                    Some(op) => unimplemented!(),
                    None => {
                        summarize_graph(&graphs)?;
                    }
                }
            }
        }
        Commands::Info => {
            log::info!("{:?}", &paths);
            log::info!(
                "UserNS, {:?}, mounted: {}",
                paths.userns().paths(),
                paths.userns().exist()?
            );
            let graphs = Graphs::load_file(&paths);
            match graphs {
                Ok(g) => summarize_graph(&g)?,
                Err(e) => println!("graphs not available, {:?}", e),
            }
        }
        Commands::Veth { mut uid, cmd } => {
            // sysctl net.ipv4.ip_forward=1
            let mut k = [0; 1];
            let (mut sp, mut sc) = UnixStream::pair()?;
            match unsafe { fork() }? {
                ForkResult::Child => {
                    unshare(CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUTS)?;
                    sethostname("proxied")?;
                    enable_ping_all()?;
                    let nl = Socket::new(NETLINK_ROUTE)?;
                    nl.set_non_blocking(true)?;
                    sc.send_fd(nl.as_raw_fd())?;
                    cmd_uid(uid, true)?;
                    // sp.write_all(&[0])?;
                    // sp.read_exact(&mut k)?;
                    prctl::set_pdeathsig(Some(SIGTERM))?;
                    log::info!("In-netns process, {:?} (fork child)", getpid());
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
                            ExactNS::from_source((
                                nsproxy_common::PidPath::N(child.as_raw()),
                                "net",
                            ))?,
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
                        let (p4, p6) = (30, 126);
                        let (mut v4, mut v6, h4, h6) = id_alloc::from_ipnet(&addrset, p4, p6);
                        let dom4: Ipv4Network = "100.67.0.0/16".parse()?;
                        let r4 = dom4.range(h4);
                        let dom6: Ipv6Network = "fe80:2e::/24".parse()?;
                        let r6 = dom6.range(h6);
                        let net4: Ipv4Network = v4.alloc_or(&r4)?.try_into()?;
                        let net6: Ipv6Network = v6.alloc_or(&r6)?.try_into()?;
                        let n6: [_; 2] = net6.iter().next_chunk().unwrap();
                        let n6net: [_; 2] =
                            n6.try_map(|n| Ipv6Network::new(n, p6))?.map(|n| n.into());
                        let vc = VethConn {
                            subnet_veth: net4.into(),
                            subnet6_veth: net6.into(),
                            ip_va: Ipv4Network::new(net4.nth(0).unwrap(), p4)?.into(),
                            ip_vb: Ipv4Network::new(net4.nth(1).unwrap(), p4)?.into(),
                            ip6_va: n6net[0],
                            ip6_vb: n6net[1],
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
        Commands::Setns { pid, cmd, uid } => {
            let f = unsafe { pidfd::PidFd::open(pid.try_into().unwrap(), 0) }?;
            setns(f, CloneFlags::CLONE_NEWNET)?;
            cmd_uid(uid, true)?;
            let mut cmd = Command::new(your_shell(cmd)?.ok_or(anyhow!("specify env var SHELL"))?);
            cmd.spawn()?.wait()?;
        }
    }
    Ok(())
}

fn summarize_graph(graphs: &Graphs) -> Result<()> {
    Ok(for ni in graphs.data.node_indices() {
        let nwdeps = graphs.nodewdeps(ni)?;
        print!("{}", nwdeps.0);
        for rel in nwdeps.1.iter() {
            println!("      {}", rel.edge.item);
            let idp = NodeIDPrint(rel.dst.id, rel.dst.item.name.as_ref().map(|k| k.as_str()));
            println!("          => {}", idp);
        }
        if nwdeps.1.len() == 0 {
            println!("      {}", "No dependencies".red());
        }
    })
}
