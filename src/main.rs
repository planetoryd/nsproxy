#![feature(decl_macro)]

use std::future::Future;
use std::process::{exit, Command};
use std::{fs::File, io::Read, os::fd::AsFd, path::PathBuf};

use amplify::empty;
use clap::{Parser, Subcommand};
use clone3::Clone3;
use daggy::petgraph::data::Build;
use nix::sched::{unshare, CloneFlags};
use nix::sys::prctl;
use nix::unistd::{fork, sethostname, ForkResult};
use nsproxy::data::{Graphs, ObjectNode, PassFD, ProcNS, Relation, TUNC};
use nsproxy::managed::{Indexed, ItemAction, ItemCreate, NodeWDeps, ServiceM, Socks2TUN, SrcNode};
use nsproxy::paths::{PathState, Paths};
use nsproxy::sys::check_capsys;
use nsproxy::*;
use nsproxy::{data::Ix, systemd};
use schematic::ConfigLoader;
use std::os::unix::net::UnixStream;
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
    /// TUN2proxy will connect to a SOCKS5 proxy in current NS, and serve a TUN in the app NS.
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
    /// Run TUN2Proxy daemon
    TUN2Proxy { conf: PathBuf },
    /// Requires root or equivalent.
    /// Initiatializes user and mount namespaces
    Init,
}

fn main() -> Result<()> {
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
                    log::warn!("CAP_SYS_ADMIN not available, entering user NS");
                    uns.enter(CloneFlags::empty())?;
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
                        let mut cmd = Command::new(cmd.unwrap());
                        cmd.spawn()?.wait()?;
                        exit(0)
                    }
                    ForkResult::Parent { child } => {
                        graphs.add_object(PidPath::N(child.as_raw()), &paths)?
                    }
                }
            }; // Source of TUNFD/SocketFD
            let out = graphs.add_object(PidPath::Selfproc, &paths)?;
            let ex = graphs.data.add_edge(src, out, None);
            asyncexe(async move {
                let socks2t = Socks2TUN::new(&tun2proxy, ex)?;
                let serv = systemd::Systemd::new().await?;
                let ctx = serv.ctx().await?;
                let rel = socks2t.write(Layer::L2, &serv).await?;
                graphs.data[ex].replace(rel);
                graphs.dump_file(&paths)?;
                graphs.write_all(&serv).await?;
                let (probe, deps) = graphs.nodewdeps(src);
                probe.start(&serv, &ctx).await?;
                aok!()
            })?;
        }
        _ => unimplemented!(),
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
