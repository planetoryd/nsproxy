use std::{
    error::Error,
    fs::File,
    io::Read,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::net::UnixStream,
    },
};

use netlink_ops::{
    netlink::{NLDriver, NLHandle},
    rtnetlink::{
        netlink_proto::{new_connection_from_socket, NetlinkCodec},
        netlink_sys::{protocols::NETLINK_ROUTE, Socket, TokioSocket},
        Handle,
    },
};
use nix::{
    sys::{prctl, signal::Signal::SIGTERM},
    unistd::{fork, ForkResult},
};
use nsproxy_common::{ExactNS, NSFrom};
use passfd::FdPassingExt;
use withfd::WithFdExt;

fn main() -> Result<(), Box<dyn Error>> {
    let (mut sp, mut sc) = UnixStream::pair()?;
    let mut k = [0; 1];
    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            let f = sp.recv_fd()?.as_raw_fd();
            println!("fd {:?}", f);

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let (nl_ch_conn, handle_ch, _) =
                    new_connection_from_socket::<_, _, NetlinkCodec>(unsafe {
                        TokioSocket::from_raw_fd(f)
                    });
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
            sc.send_fd(nl.as_raw_fd())?;
            sc.read_exact(&mut k)?;
        }
    }
    Ok(())
}
