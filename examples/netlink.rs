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
        netlink_sys::{protocols::NETLINK_ROUTE, Socket, TokioSocket, AsyncSocket},
        Handle,
    },
};
use nix::{
    sys::{prctl, signal::Signal::SIGTERM},
    unistd::{fork, ForkResult},
};
use nsproxy_common::{ExactNS, NSFrom};
use withfd::WithFdExt;

fn main() -> Result<(), Box<dyn Error>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let (nl_ch_conn, handle_ch, _) =
            new_connection_from_socket::<_, _, NetlinkCodec>(TokioSocket::new(NETLINK_ROUTE)?);
        tokio::spawn(nl_ch_conn);
        let nlh_ch = NLHandle::new(
            Handle::new(handle_ch),
            ExactNS::from_source((nsproxy_common::PidPath::Selfproc, "net"))?,
        );
        let mut nl_ch = NLDriver::new(nlh_ch);
        nl_ch.fill().await?;
        dbg!(&nl_ch);
        Ok::<_, Box<dyn Error>>(())
    })?;

    Ok(())
}
