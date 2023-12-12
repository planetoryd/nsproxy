//! NSProxy (net namespace proxy)
//! SProxy (S for SUID)

#![feature(decl_macro)]
#![feature(iter_next_chunk)]
#![feature(array_try_map)]

use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::process::{exit, Command, Stdio};

use anyhow::anyhow;
use capctl::prctl;
use clap::{Parser, Subcommand};
use id_alloc::{Ipv4A, NetRange};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use libc::SIGTERM;
use log::LevelFilter::{self, Debug};
use netlink_ops::netlink::{nl_ctx, NLDriver, NLHandle, VethConn};
use netlink_ops::rtnetlink::netlink_proto::{new_connection_from_socket, NetlinkCodec};
use netlink_ops::rtnetlink::netlink_sys::protocols::NETLINK_ROUTE;
use netlink_ops::rtnetlink::netlink_sys::{AsyncSocket, Socket, TokioSocket};
use netlink_ops::rtnetlink::Handle;
use netlink_ops::state::{Existence, ExpCollection};
use nix::sched::{setns, unshare, CloneFlags};
use nix::sys::wait::waitpid;
use nix::unistd::{fork, getpid, getppid, sethostname, setresuid, ForkResult, Pid, Uid};
use nsproxy::paths::{PathState, Paths};
use nsproxy::sys::{check_capsys, enable_ping, your_shell, UserNS, cmd_uid};
use nsproxy::*;
use nsproxy_common::{ExactNS, PidPath};
use passfd::FdPassingExt;
use std::os::unix::net::{UnixListener, UnixStream};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "an alternative to proxychains based on linux kernel namespaces. SProxy is the SUID counterpart of NSProxy"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// It's recommended to set this program to use SUID
    /// SUDO messes the environment up which causes some programs to misbehave
    /// But we only want proxying, and maintain maximal compatibility.
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

fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(LevelFilter::Info)
        .parse_default_env()
        .init();
    let cli = Cli::parse();
    // let paths: Paths = PathState::default()?.into();
    check_capsys()?;

    // let mut graphs = Graphs::load_file(&paths)?;
    // We must use a one thread runtime to not mess up NS.
    match cli.command {
        Commands::Veth { mut uid, cmd } => {
            // sysctl net.ipv4.ip_forward=1
            let mut k = [0; 1];
            let (mut sp, mut sc) = UnixStream::pair()?;
            match unsafe { fork() }? {
                ForkResult::Child => {
                    unshare(CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUTS)?;
                    sethostname("proxied")?;
                    enable_ping()?;
                    let nl = Socket::new(NETLINK_ROUTE)?;
                    nl.set_non_blocking(true)?;
                    sc.send_fd(nl.as_raw_fd())?;
                    cmd_uid(uid)?;
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
            cmd_uid(uid)?;
            let mut cmd = Command::new(your_shell(cmd)?.ok_or(anyhow!("specify env var SHELL"))?);
            cmd.spawn()?.wait()?;
        }
    }
    Ok(())
}

