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
use nsproxy::managed::ServiceManaged;
use nsproxy::paths::{PathState, Paths};
use nsproxy::sys::check_capsys;
use nsproxy::*;
use nsproxy::{data::NodeID, systemd};
use schematic::ConfigLoader;
use std::os::unix::net::UnixStream;

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
    SOCKS2TUN {
        #[arg(long, short)]
        pid: Option<pid_t>,
        /// Config file for Tun2proxy
        #[arg(long, short)]
        tun2proxy: Option<PathBuf>,
        /// Command to run
        cmd: Option<String>,
    },
    /// Start as watcher daemon
    Watch {},
    /// Run probe process acccording to the graph
    Probe { id: NodeID },
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

            let rels: Vec<Relation> = Default::default();
            // NS by Pid --send fd of TUN/socket--> NS of TUN2proxy
            let src = if let Some(pid) = pid {
                let ni = graphs.data.add_node(None);
                let proc = ProcNS::mount(&pid.to_string(), &paths, ni)?;
                let node = &mut graphs.data[ni];
                node.replace(ObjectNode { main: proc });
                ni
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
                        let ni = graphs.data.add_node(None);
                        let proc = ProcNS::mount(&child.as_raw().to_string(), &paths, ni)?;
                        let node = &mut graphs.data[ni];
                        node.replace(ObjectNode { main: proc });
                        ni
                    }
                }
            }; // Source of TUNFD/SocketFD
            
            let pass = Relation::SendTUN(PassFD {
                creation: TUNC {
                    layer: tun::Layer::L2,
                    name: None,
                },
            });
        }
        _ => unimplemented!(),
    }
    Ok(())
}
