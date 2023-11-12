use std::{fs::File, io::Read, os::fd::AsFd, path::PathBuf};

use clap::{Parser, Subcommand};
use clone3::Clone3;
use nsproxy::data::{PNode, ProcNS};
use nsproxy::managed::ServiceManaged;
use nsproxy::*;
use nsproxy::{data::NodeID, systemd, tun2proxy::PNodeConf};
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
    /// Instrument a process. If a pid is not provided, a new netns is created.
    Inst {
        #[arg(long, short)]
        pid: Option<pid_t>,
        /// Path to [PNodeConf]
        conf: PathBuf,
        /// Command to run
        cmd: Option<String>,
    },
    /// Start as watcher daemon
    Watch {},
    /// Typically you shouldn't run this manually
    Probe { id: NodeID },
    /// Typically you shouldn't run this manually
    TUN2Proxy {
        /// Path to [PNodeConf]
        conf: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Inst { pid, conf, cmd } => {
            let con = load_conf(conf)?;
            // make two systemd services. one for prober, one for proxy.
            // for cmd, we setns and run it.
            let serv = systemd::Managed::new()?;

            if let Some(pid) = pid {
                // let mounted = ProcNS::mount(pid)?;
                // let node = PNode {
                //     main: mounted,
                //     out: None,
                // };

            }
        }
        _ => (),
    }

    // No forking needed if we don't run tun2proxy.
    // Read conf.
    // If it's socket passing, create service, setns, get fd, send fd, and finish.

    let mut pidfd = -1;
    let mut clone3 = Clone3::default();
    clone3.flag_pidfd(&mut pidfd);

    let (socka, sockb) = UnixStream::pair()?;
    match unsafe { clone3.call() }? {
        0 => {
            // pidfd is -1 here
            // start tun2proxy
        }
        child => {
            // pidfd is usable here

            // run a shell process, send fd
            // or setns into target process, send fd, and exit
            // If I get FDs and fork, I get the FD for free, but the child may have problem setns-ing.
            // Otherwise I have to use sockets.
        }
    }

    Ok(())
}

fn load_conf(conf: PathBuf) -> Result<PNodeConf> {
    let loaded = ConfigLoader::<PNodeConf>::new().file(conf)?.load()?;
    Ok(loaded.config)
}
