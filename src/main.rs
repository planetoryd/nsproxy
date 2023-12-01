#![feature(decl_macro)]

use std::future::Future;
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::process::{exit, Command};
use std::{fs::File, io::Read, os::fd::AsFd, path::PathBuf};

use amplify::empty;
use anyhow::anyhow;
use clap::{Parser, Subcommand};
use clone3::Clone3;
use daggy::petgraph::data::Build;
use log::LevelFilter::Debug;
use nix::sched::{unshare, CloneFlags};
use nix::sys::prctl;
use nix::unistd::{fork, sethostname, ForkResult};
use nsproxy::data::{Graphs, NodeI, ObjectNode, PassFD, ProcNS, Relation, TUNC};
use nsproxy::managed::{Indexed, ItemAction, ItemCreate, NodeWDeps, ServiceM, Socks2TUN, SrcNode};
use nsproxy::paths::{PathState, Paths};
use nsproxy::sys::{check_capsys, UserNS};
use nsproxy::*;
use nsproxy::{data::Ix, systemd};
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
    Probe { id: Ix },
    /// Run TUN2Proxy daemon.
    /// This must be run as a systemd service
    TUN2Proxy { conf: PathBuf },
    /// Requires root or equivalent.
    /// Initiatializes user and mount namespaces.
    /// Actions other than this may be performed (also usually) rootlessly
    Init {
        /// Deinit
        #[arg(long, short)]
        undo: bool,
    },
    Info
}

fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(Debug)
        .parse_default_env()
        .init();
    let cli = Cli::parse();
    let paths: Paths = PathState::default()?.into();
    let mut graphs = Graphs::load_file(&paths)?;
    match cli.command {
        Commands::SOCKS2TUN {
            pid,
            tun2proxy,
            cmd,
        } => {
            let capsys = check_capsys();
            match capsys {
                Ok(_) => {
                    // The user is using SUID or sudo, or we are alredy in a userns, or user did setcap.
                    // Probably intentional
                }
                _ => {
                    let uns = paths.userns().procns()?;
                    log::warn!("CAP_SYS_ADMIN not available, entering user NS (I assume you want to use UserNS)");
                    uns.enter()?;
                    check_capsys()?;
                }
            }

            // NS by Pid --send fd of TUN/socket--> NS of TUN2proxy
            let src = if let Some(pid) = pid {
                graphs.add_object(PidPath::N(pid), &paths)?
            } else {
                match unsafe { fork() }? {
                    ForkResult::Child => {
                        unshare(CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUTS)?;
                        sethostname("proxied")?;
                        let mut cmd = Command::new(
                            cmd.ok_or(anyhow!("--cmd must be specified when --pid is not provided"))?,
                        );
                        cmd.spawn()?.wait()?;
                        exit(0)
                    }
                    ForkResult::Parent { child } => {
                        graphs.add_object(PidPath::N(child.as_raw()), &paths)?
                    }
                }
            }; // Source of TUNFD/SocketFD
            let out = graphs.add_object(PidPath::Selfproc, &paths)?;
            let edge = graphs.data.add_edge(src, out, None);
            asyncexe(async move {
                let socks2t = Socks2TUN::new(&tun2proxy, edge)?;
                let serv = systemd::Systemd::new().await?;
                let ctx = serv.ctx().await?;
                // TODO: TUN2proxy when TAP
                let rel = socks2t.write(Layer::L2, &serv).await?;
                graphs.data[edge].replace(rel);
                graphs.dump_file(&paths)?;
                graphs.write_probes(&serv).await?;
                let (probe, deps) = graphs.nodewdeps(src);
                probe.start(&serv, &ctx).await?;
                aok!()
            })?;
        }
        Commands::Probe { id } => {
            // Load graphs, send FDs over socket
            let (node, deps) = graphs.nodewdeps(NodeI::from(id));
            node.item.main.enter()?;
            for edge in deps {
                match edge.item {
                    Relation::SendSocket(p) => p.pass()?,
                    Relation::SendTUN(p) => p.pass()?,
                }
            }
        }
        Commands::TUN2Proxy { conf } => {
            // Setns, recv FD, start daemon
            // Recv a TUN FD, and/or a upstream socket FD
            // Socket activation
            let mut fds = libsystemd::activation::receive_descriptors(true)?;
            let fdx = fds.pop().unwrap();
            let fdx = unsafe { UnixListener::from_raw_fd(fdx.into_raw_fd()) };
            let (conn, _addr) = fdx.accept()?;
            let devfd: RawFd = conn.recv_fd()?;
            let args = tun2proxy::load_conf(conf)?;
            tun2proxy::tuntap(args, devfd)?;
        }
        Commands::Watch {} => {}
        Commands::Init { undo } => {
            let usern = UserNS(&paths);
            // Fuck smart-anything.
            // Will not do anything unanticipated. Init means init
            if undo {
                usern.deinit()?;
            } else {
                usern.init()?;
                log::info!("{:?}", usern.paths());
            }
        }
        Commands::Info => {
            log::info!("{:?}", &paths);
            log::info!("UserNS, {:?}", paths.userns().paths());
        }
    }
    Ok(())
}

fn asyncexe<F>(fut: F) -> Result<tokio::task::JoinHandle<F::Output>>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let k = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .spawn(fut);
    Ok(k)
}
