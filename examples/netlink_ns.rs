use std::{
    error::Error,
    fs::File,
    io::Read,
    os::{fd::AsFd, unix::net::UnixStream},
};

use netlink_ops::{
    netlink::{NLDriver, NLHandle},
    rtnetlink::{
        netlink_proto::{new_connection_from_socket, NetlinkCodec},
        netlink_sys::{protocols::NETLINK_ROUTE, Socket, TokioSocket},
        Handle,
    },
};
use nix::{unistd::{fork, ForkResult}, sys::{prctl, signal::Signal::SIGTERM}};
use nsproxy_common::{ExactNS, NSFrom};
use withfd::WithFdExt;

// https://github.com/planetoryd/withfd

fn main() -> Result<(), Box<dyn Error>> {
    let (mut sp, mut sc) = UnixStream::pair()?;
    let mut k = [0; 1];
    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            let mut sp = sp.with_fd();

            sp.read_exact(&mut k)?;
            let f = sp.take_fds().next().unwrap();
            println!("fd {:?}", f);

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let (nl_ch_conn, handle_ch, _) =
                    new_connection_from_socket::<_, _, NetlinkCodec>(TokioSocket::from(f));
                tokio::spawn(nl_ch_conn);
                let nlh_ch = NLHandle::new(
                    Handle::new(handle_ch),
                    ExactNS::from_source((nsproxy_common::PidPath::N(child.as_raw()), "net"))?,
                );
                let mut nl_ch = NLDriver::new(nlh_ch);
                nl_ch.fill().await?;
                dbg!(&nl_ch);
                Ok::<_, Box<dyn Error>>(())
            })?;
        }
        ForkResult::Child => {
            prctl::set_pdeathsig(Some(SIGTERM))?;
            let nl = Socket::new(NETLINK_ROUTE)?;
            let mut sc = sc.with_fd();
            sc.write_with_fd(&[0], &[nl.as_fd()])?;
            sc.read_exact(&mut k)?;
        }
    }
    Ok(())
}
