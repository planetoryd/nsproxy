#![feature(decl_macro)]
#![feature(async_closure)]
#![feature(iter_next_chunk)]
#![feature(array_try_map)]
#![feature(ip_bits)]

use std::collections::HashSet;
use std::env::var;
use std::fs::{OpenOptions, Permissions};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{exit, Command, Stdio};
use std::{fs::File, io::Read, os::fd::AsFd, path::PathBuf};

use anyhow::{anyhow, bail, ensure};
use capctl::prctl;
use clap::{Parser, Subcommand};
use id_alloc::NetRange;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use libc::{uid_t, SIGTERM};
use log::LevelFilter::{self, Debug};
use netlink_ops::netlink::{nl_ctx, NLDriver, NLHandle, VPairKey, VethConn};
use netlink_ops::rtnetlink::netlink_proto::{new_connection_from_socket, NetlinkCodec};
use netlink_ops::rtnetlink::netlink_sys::protocols::NETLINK_ROUTE;
use netlink_ops::rtnetlink::netlink_sys::{Socket, TokioSocket};
use netlink_ops::rtnetlink::Handle;
use netlink_ops::state::{Existence, ExpCollection};
use nix::sched::{setns, unshare, CloneFlags};
use nix::sys::wait::waitpid;
use nix::unistd::{
    fork, geteuid, getgid, getpid, getppid, getuid, sethostname, setresuid, ForkResult, Pid, Uid,
};
use nsproxy::data::{
    FDRecver, Graphs, NSAdd, NSAddRes, NSGroup, NSSlot, NSState, NodeAddr, NodeI, ObjectNode,
    PassFD, Relation, Validate, ValidateR, TUNC,
};
use nsproxy::flatpak::FlatpakID;
use nsproxy::graph::{check_veths, FResult};
use nsproxy::managed::{
    Indexed, ItemAction, ItemCreate, NodeIDPrint, NodeIndexed, NodeWDeps, ServiceM, Socks2TUN,
};
use nsproxy::paths::{PathState, Paths};
use nsproxy::sys::{
    check_capsys, cmd_uid, connect_ns_veth, enable_ping_all, enable_ping_gid, systemd_connection,
    unshare_user_standalone, what_uid, your_shell, UserNS,
};
use nsproxy::systemd::{match_root, UnitName};
use nsproxy::watcher::FlatpakWatcher;
use nsproxy::*;
use nsproxy::{data::Ix, systemd};
use nsproxy_common::NSSource::{self, Unavail};
use nsproxy_common::{ExactNS, NSFrom, PidPath, VaCache};
use owo_colors::OwoColorize;
use passfd::FdPassingExt;
use petgraph::visit::IntoNodeReferences;
use std::os::unix::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tracing::instrument::WithSubscriber;
use tracing::{info, warn, Level};
use tracing_log::LogTracer;
use tracing_subscriber::FmtSubscriber;
use tun::{AsyncDevice, Configuration, Device, Layer};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "an alternative to proxychains based on linux kernel namespaces"
)]
struct Cli {
    #[arg(long, short)]
    log: Option<Level>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    New {
        #[arg(long, short)]
        pid: Option<pid_t>,
        /// Config file for Tun2proxy
        #[arg(long, short)]
        tun2proxy: Option<PathBuf>,
        /// Command to run
        cmd: Option<String>,
        #[arg(long, short)]
        uid: Option<uid_t>,
        #[arg(long, short)]
        name: Option<String>,
        /// Mount the new NS or not.
        #[arg(long, short)]
        mount: bool,
        #[arg(long, short, value_parser=parse_node)]
        out: Option<NodeAddr>,
        #[arg(long, short)]
        veth: bool,
    },
    /// Start as watcher daemon. This uses the socks2tun method.
    Watch {
        /// And you can only specify one config
        path: PathBuf,
        #[arg(long, short)]
        dryrun: bool,
    },
    /// Run probe process acccording to the graph. ID for Node ID
    Probe {
        id: Ix,
    },
    /// Run TUN2Proxy daemon.
    /// This must be run as a systemd service
    TUN2proxy {
        conf: PathBuf,
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
        #[arg(long, short)]
        deinit: bool,
    },
    Node {
        #[arg(value_parser=parse_node)]
        id: Option<NodeAddr>,
        #[command(subcommand)]
        op: Option<NodeOps>,
    },
    Setns {
        pid: u32,
        cmd: Option<String>,
        #[arg(long, short)]
        uid: Option<u32>,
    },
    Sync,
    /// Install nsproxy to your system.
    Install {
        #[arg(long, short)]
        sproxy: bool,
        #[arg(long, short)]
        dstdir: Option<PathBuf>,
    },
    Noop,
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
    Deps {
        #[arg(long, short = 'n', default_value = "30")]
        lines: u32,
        #[arg(long, short)]
        index: Option<usize>,
    },
    Run {
        /// Command to run
        cmd: Option<String>,
        #[arg(long, short)]
        uid: Option<u32>,
    },
    Reboot,
    Prune,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Noop => exit(0),
        _ => (),
    }

    let subscriber = FmtSubscriber::builder()
        .compact()
        .without_time()
        .with_max_level(cli.log.unwrap_or(Level::INFO))
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    LogTracer::init()?;
    info!("SHA1: {}", env!("VERGEN_GIT_SHA"));
    let cwd = std::env::current_dir()?;

    match cli.command {
        Commands::New {
            pid,
            mut tun2proxy,
            cmd,
            uid,
            name,
            mount,
            out,
            veth,
        } => {
            let (pspath, paths): (PathBuf, PathState) = PathState::load(what_uid(None, true)?)?;
            let paths: Paths = paths.into();

            let mut graphs = Graphs::load_file(&paths)?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let capsys = check_capsys();

            let wuid = what_uid(uid, true)?;
            let (pspath, paths): (PathBuf, PathState) = PathState::load(wuid)?;
            let paths: Paths = paths.into();

            if let Some(ref mut tun2proxy) = tun2proxy {
                *tun2proxy = tun2proxy.canonicalize()?;
            }
            // Connect and authenticate to systemd before entering userns
            let rootful = geteuid().is_root();
            let pre = rt.block_on(async { systemd_connection(rootful).await })?;
            let priv_ns;
            let mut va = VaCache::default();
            let mut serv = systemd::Systemd::new(&paths, Some(pre), rootful)?;
            let mut rmnode = Default::default();

            rt.block_on(async {
                let mut nl = NLDriver::new(NLHandle::new_self_proc_tokio()?);
                let ctx = graphs
                    .prune(&mut va, &mut serv, &mut rmnode, &mut nl)
                    .await?;
                graphs.do_prune(&ctx, &serv, rmnode, &mut nl).await?;
                aok!()
            })?;

            let gid = getgid();
            let mut depriv_userns = false;
            match capsys {
                Ok(_) => {
                    // The user is using SUID or sudo, or we are alredy in a userns, or user did setcap.
                    // Probably intentional
                    priv_ns = Some(NSGroup::proc_path(
                        PidPath::Selfproc,
                        Some(NSSource::Unavail(false)),
                    )?);
                }
                _ => {
                    log::warn!("CAP_SYS_ADMIN not available, entering user NS (I assume you want to use UserNS)");
                    if mount {
                        // It only makes sense when we have a persistent userns to mount
                        priv_ns = Some(paths.userns().procns()?);
                        if !paths.userns().exist()? {
                            println!(
                                "User NS does not exist. Create it as root with command {}",
                                "sproxy userns".bright_yellow()
                            );
                            exit(-1);
                        }
                        let ctx = NSGroup::proc_path(PidPath::Selfproc, None)?;
                        priv_ns.as_ref().unwrap().enter(&ctx)?;
                        log::info!("Entered user, mnt NS");
                    } else {
                        // Not mounting defaults to use a new userns
                        priv_ns = Some(unshare_user_standalone(wuid, gid.as_raw())?);
                        depriv_userns = true;
                    }
                    check_capsys()?;
                }
            }
            let ns_add = if mount {
                NSAdd::RecordMountedPaths
            } else {
                NSAdd::RecordProcfsPaths
            };
            let mut rmnode = Default::default();
            rt.block_on(async {
                let mut nl = NLDriver::new(NLHandle::new_self_proc_tokio()?);
                let ctx = graphs
                    .prune(&mut va, &mut serv, &mut rmnode, &mut nl)
                    .await?;
                graphs.do_prune(&ctx, &serv, rmnode, &mut nl).await?;
                aok!()
            })?;
            // Prune is called twice because some NSes are visible only in userns
            let (mut sp, mut sc) = UnixStream::pair()?;
            let mut buf = [0; 1];
            let mut nl_fd = None;
            // NS by Pid --send fd of TUN/socket--> NS of TUN2proxy
            let (src_res, src) = if let Some(pid) = pid {
                graphs.add_ns(
                    PidPath::N(pid),
                    &paths,
                    priv_ns.as_ref(),
                    ns_add,
                    name,
                    rootful,
                )?
            } else {
                match unsafe { fork() }? {
                    ForkResult::Child => {
                        drop(sp);
                        prctl::set_pdeathsig(Some(SIGTERM))?;
                        unshare(CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUTS)?;
                        sc.write_all(&[0])?;
                        sethostname("proxied")?;
                        if depriv_userns {
                            enable_ping_gid(gid)?
                        } else {
                            enable_ping_all()?;
                        }
                        if veth {
                            let nl = Socket::new(NETLINK_ROUTE)?;
                            sc.send_fd(nl.as_raw_fd())?;
                        }
                        sc.read_exact(&mut buf)?;
                        let mut cmd = Command::new(your_shell(cmd)?.ok_or(anyhow!(
                            "--cmd must be specified when --pid is not provided"
                        ))?);
                        // We don't change uid of this process.
                        // Otherwise probe might fail due to perms
                        cmd.current_dir(cwd);
                        cmd_uid(Some(wuid), true, false)?;
                        cmd.uid(wuid);

                        sc.read_exact(&mut buf)?;
                        let mut ch = cmd.spawn()?;
                        ch.wait()?;
                        exit(0);
                    }
                    ForkResult::Parent { child } => {
                        drop(sc);
                        sp.read_exact(&mut buf)?;
                        nl_fd = if veth { Some(sp.recv_fd()?) } else { None };
                        let k = graphs.add_ns(
                            PidPath::N(child.as_raw()),
                            &paths,
                            priv_ns.as_ref(),
                            // We have no privs to mount with when new_userns==true
                            ns_add,
                            name,
                            rootful,
                        )?;
                        sp.write_all(&[1])?;
                        k
                    }
                }
            }; // Source of TUNFD/SocketFD

            rt.block_on(async move {
                graphs.clear_ns(src, &serv).await?;

                let out = if let Some(out) = &out {
                    graphs.resolve(out)?
                } else {
                    let (_, out) = graphs.add_ns(
                        PidPath::Selfproc,
                        &paths,
                        priv_ns.as_ref(),
                        NSAdd::RecordNothing,
                        None,
                        rootful,
                    )?;
                    out
                };

                if let Some(tun2proxy) = tun2proxy {
                    let edge = graphs.data.add_edge(src, out, None);
                    log::info!(
                        "Src/Probe {src:?} {}, OutNode(This process), Src --TUN--> Out {edge:?}",
                        graphs.data[src].as_ref().unwrap().main.key()
                    );
                    let socks2t = Socks2TUN::new(&tun2proxy, edge)?;
                    let rel = socks2t
                        .write((Layer::L3, Some(pspath.clone())), &serv)
                        .await?;
                    graphs.data[edge].replace(rel);
                }

                let mut nl = NLHandle::new_self_proc_tokio()?;

                if let Some(nl_fd) = nl_fd {
                    let veth_key: Option<VPairKey>;
                    veth_key = Some(format!("v{}to{}", src.index(), out.index()).try_into()?);
                    let (nl_ch_conn, handle_ch, _) =
                        new_connection_from_socket::<_, _, NetlinkCodec>(unsafe {
                            TokioSocket::from_raw_fd(nl_fd)
                        });
                    tokio::spawn(nl_ch_conn);
                    let mut nlh_ch = NLHandle::new(
                        Handle::new(handle_ch),
                        graphs.data[src]
                            .as_ref()
                            .unwrap()
                            .main
                            .net
                            .must()?
                            .to_owned(),
                    );

                    let vc = connect_ns_veth(nlh_ch, nl.clone(), veth_key).await?;
                    let edge = graphs.data.add_edge(src, out, None);
                    graphs.data[edge].replace(Relation::Veth(vc));
                }

                let ctx = serv.ctx().await?;
                graphs.dump_file(&paths, wuid)?;
                let nw = graphs.nodewdeps(src)?;
                nw.write(Some(pspath.clone()), &serv).await?;
                serv.reload(&ctx).await?;
                nw.1.restart(&serv, &ctx).await?;
                nw.0.restart(&serv, &ctx).await?;
                aok!()
            })?;
            sp.write_all(&[2])?;
            // Wait for the child, or it gets orphaned.
            waitpid(Some(Pid::from_raw(-1)), None)?;
        }
        Commands::Probe { id } => {
            let (pspath, paths): (PathBuf, PathState) = PathState::load(what_uid(None, true)?)?;
            let paths: Paths = paths.into();

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
                    _ => (),
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
            let devfd = conn.recv_fd()?;
            log::info!("Got FD");
            let mut cf = File::open(&conf)?;
            let mut args: tun2socks5::IArgs = serde_json::from_reader(&mut cf)?;
            let devconf = Configuration::default();
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let dev = tun::platform::linux::Device::from_raw_fd(devfd.as_raw_fd(), &devconf)?;
                if let Some(ref mut p) = args.state {
                    let mut f = p.file_name().unwrap().to_owned();
                    let netns = ExactNS::from_source((PidPath::Selfproc, "net"))?;
                    f.push(format!("_ns_{}", netns.unique));
                    // WARN This will cause problems when you have multiple TUNs in one NS, and use one config
                    p.set_file_name(f);
                }
                log::info!("{:?}", args);
                let dev = AsyncDevice::new(dev)?;

                let (sx, rx) = mpsc::channel(1);
                tun2socks5::main_entry(dev, DEFAULT_MTU.try_into()?, true, args, rx, sx).await?;

                aok!()
            })?;
        }
        Commands::Watch { mut path, dryrun } => {
            // I think there is no root flatpak /run/ dir. therefore false.
            let uid = what_uid(None, false)?;
            let (pspath, paths): (PathBuf, PathState) = PathState::load(uid)?;
            let paths: Paths = paths.into();
            let fpwatch = FlatpakWatcher::default();
            let fpath = paths.flatpak();
            path = path.canonicalize()?;
            if !fpath.exists() {
                tracing::error!("You must specify a list of apps to proxy at {:?}", &fpath);
                return Ok(());
            }
            // TODO, weird enoguh, for a flatpak process the mnt ns cant be entered EPERM
            info!("Load {:?}", &fpath);
            let mut fapps = std::fs::File::open(&fpath)?;
            let list_apps: Vec<FlatpakID> = serde_json::from_reader(&mut fapps)?;
            let brred: Vec<_> = list_apps.iter().map(|k| k).collect();
            crate::flatpak::adapt_flatpak(brred, dryrun)?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let (sx, mut rx) = mpsc::channel(5);
                let rootful = geteuid().is_root();
                let pre = systemd_connection(rootful).await?;
                let dae = tokio::spawn(fpwatch.daemon(uid, sx));
                let looper = async move {
                    let serv = systemd::Systemd::new(&paths, Some(pre), rootful)?;
                    let ctx = serv.ctx().await?;
                    while let Some(fe) = rx.recv().await {
                        if dryrun {
                            continue;
                        }
                        let mut graphs = Graphs::load_file(&paths)?;
                        let (_, out) = graphs.add_ns(
                            PidPath::Selfproc,
                            &paths,
                            None,
                            NSAdd::RecordNothing,
                            None,
                            rootful,
                        )?;
                        let (r, src) = graphs.add_ns(
                            PidPath::N(fe.pid.try_into()?),
                            &paths,
                            None,
                            NSAdd::Flatpak,
                            Some(fe.name()),
                            rootful,
                        )?;
                        if matches!(r, NSAddRes::Found) {
                            log::warn!("Net NS exists in state file");
                            // TODO: skip if everything is up
                            continue;
                        } else {
                            let edge = graphs.data.add_edge(src, out, None);
                            log::info!(
                                "Src/Probe {src:?} {}, OutNode(This process), Src -> Out {edge:?}",
                                graphs.data[src].as_ref().unwrap().main.key()
                            );
                            let socks2t = Socks2TUN::new(&path, edge)?;
                            let rel = socks2t
                                .write((Layer::L3, Some(pspath.clone())), &serv)
                                .await?;
                            graphs.data[edge].replace(rel);
                            graphs.dump_file(&paths, uid)?;
                        }
                        let nw = graphs.nodewdeps(src)?;
                        nw.write(Some(pspath.clone()), &serv).await?;

                        serv.reload(&ctx).await?;
                        nw.1.restart(&serv, &ctx).await?;
                        nw.0.restart(&serv, &ctx).await?;
                    }

                    aok!()
                };
                tokio::select! { h = dae => h??, h = looper => h?};

                aok!()
            })?;
        }
        Commands::Userns {
            rmall,
            uid,
            node,
            deinit,
        } => {
            let wuid = what_uid(None, false)?;
            let (pspath, paths): (PathBuf, PathState) = PathState::load(wuid)?;
            let paths: Paths = paths.into();
            let usern = UserNS(&paths);
            let rootful = geteuid().is_root();
            if usern.exist()? {
                let ctx = NSGroup::proc_path(PidPath::Selfproc, None)?;
                usern.procns()?.enter(&ctx)?;
                if rmall {
                    NSGroup::rmall(&paths, false)?;
                } else if deinit {
                    usern.deinit()?;
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
                log::warn!("UserNS does not exist");
                check_capsys()?;
                usern.init(wuid)?;
            }
        }
        Commands::Node { id, op } => {
            let (pspath, paths): (PathBuf, PathState) = PathState::load(what_uid(None, true)?)?;
            let paths: Paths = paths.into();
            let mut graphs = Graphs::load_file(&paths)?;
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
                        let mut va = VaCache::default();
                        let mut nss = NSState {
                            target: &node.main,
                            va: &mut va,
                        };
                        let cwd = std::env::current_dir()?;
                        nss.validated_enter()?;
                        drop(graphs);
                        cmd_uid(uid, true, true)?;
                        let mut cmd =
                            Command::new(your_shell(cmd)?.ok_or(anyhow!("specify env var SHELL"))?);
                        cmd.current_dir(cwd);
                        cmd.spawn()?.wait()?;
                    }
                    NodeOps::Deps { lines, index } => {
                        let ix = require_id()?;
                        let mut cmd = Command::new("journalctl");
                        let (node, deps) = graphs.nodewdeps(ix)?;
                        if deps.len() == 0 {
                            println!("No dependencies.");
                        } else {
                            if let Some(index) = index {
                                let fdrc = deps[index].edge.item.fd_recver();
                                if let Some(recver) = fdrc {
                                    let serv = match recver {
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
                                        format!(
                                            "-n{lines} -o cat --follow -b {}",
                                            if node.item.root {
                                                "--unit"
                                            } else {
                                                "--user-unit"
                                            }
                                        )
                                        .split(" ")
                                        .chain([serv.as_str()]),
                                    );
                                    let mut ch = cmd.spawn()?;
                                    ch.wait()?;
                                } else {
                                    log::error!("No FD receiver at {}", index)
                                }
                            } else {
                                summarize_graph(&graphs)?;
                            }
                        }
                    }
                    NodeOps::Reboot => {
                        let ix = require_id()?;
                        let (node, deps) = graphs.nodewdeps(ix)?;
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?;
                        rt.block_on(async {
                            let rootful = geteuid().is_root();
                            let pre = systemd_connection(rootful).await?;
                            let serv = systemd::Systemd::new(&paths, Some(pre), rootful)?;
                            let ctx = serv.ctx().await?;
                            match_root(&serv, node.item.root)?;
                            // A node is root implies deps are located in root systemd directories too
                            deps.restart(&serv, &ctx).await?;
                            node.restart(&serv, &ctx).await?;
                            aok!()
                        })?;
                    }
                    NodeOps::Prune => {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?;
                        let mut va = VaCache::default();
                        let rootful = geteuid().is_root();
                        let mut serv = systemd::Systemd::new(&paths, None, rootful)?;
                        let mut rmnode = Default::default();
                        rt.block_on(async {
                            let mut nl = NLDriver::new(NLHandle::new_self_proc_tokio()?);
                            let ctx = graphs
                                .prune(&mut va, &mut serv, &mut rmnode, &mut nl)
                                .await?;
                            graphs.do_prune(&ctx, &serv, rmnode, &mut nl).await?;
                            aok!()
                        })?;
                        graphs.dump_file(&paths, what_uid(None, true)?)?;
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
            let (pspath, paths): (PathBuf, PathState) = PathState::load(what_uid(None, true)?)?;
            let paths: Paths = paths.into();
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
        Commands::Setns { pid, cmd, uid } => {
            let f = unsafe { pidfd::PidFd::open(pid.try_into().unwrap(), 0) }?;
            setns(f, CloneFlags::CLONE_NEWNET)?;
            cmd_uid(uid, true, true)?;
            let mut cmd = Command::new(your_shell(cmd)?.ok_or(anyhow!("specify env var SHELL"))?);
            cmd.current_dir(cwd);
            cmd.spawn()?.wait()?;
        }
        Commands::Sync => {
            let (pspath, paths): (PathBuf, PathState) = PathState::load(what_uid(None, true)?)?;
            let paths: Paths = paths.into();
            let graphs = Graphs::load_file(&paths)?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let rootful = geteuid().is_root();
                let pre = systemd_connection(rootful).await?;
                let serv = systemd::Systemd::new(&paths, Some(pre), rootful)?;
                // let ctx = serv.ctx().await?;
                graphs.write_probes(&serv, Some(pspath), rootful).await?;
                aok!()
            })?;
        }
        Commands::Install { sproxy, dstdir } => {
            let selfprog = std::env::current_exe()?;
            let mut sproxyf = selfprog.clone();
            let dstdir: PathBuf = dstdir.unwrap_or("/usr/local/bin".parse()?);
            sproxyf.set_file_name("sproxy");
            let overwrite = |src: &Path, path: &Path| {
                if path.exists() {
                    std::fs::remove_file(path)?;
                }
                std::fs::copy(src, path)?;
                aok!()
            };
            let selfprogdst = dstdir.join(selfprog.file_name().unwrap());
            overwrite(&selfprog, &selfprogdst)?;
            if sproxy {
                let fd = dstdir.join(sproxyf.file_name().unwrap());
                overwrite(&sproxyf, &fd)?;
                let f = std::fs::File::open(&fd)?;
                let perms = Permissions::from_mode(0o6755);
                f.set_permissions(perms)?;
            }
        }
        _ => todo!(),
    }
    Ok(())
}

fn summarize_graph(graphs: &Graphs) -> Result<()> {
    Ok(for ni in graphs.data.node_indices() {
        let nwdeps = graphs.nodewdeps(ni)?;
        print!("{}", nwdeps.0);
        for rel in nwdeps.1.iter() {
            println!("      {}", rel.edge.item);
            let fdrc = rel.edge.item.fd_recver();
            if let Some(recver) = fdrc {
                match recver {
                    FDRecver::TUN2Proxy(ref path) => {
                        let serv = Socks2TUN::new(path, rel.edge.id)?.service()?;
                        println!("      Tun2proxy {}", serv.bright_purple());
                    }
                    FDRecver::Systemd(serv) => {
                        println!("      Service {}", serv.bright_purple());
                    }
                    _ => (),
                };
            }
            let serv = rel.dst.service()?;
            let idp = NodeIDPrint(
                rel.dst.id,
                rel.dst.item.name.as_ref().map(|k| k.as_str()),
                &serv,
            );
            println!("          => {}", idp);
        }
        if nwdeps.1.len() == 0 {
            println!("      {}", "No dependencies".red());
        }
    })
}
