//! Pass TUNTAP / TCP socket FDs to proxies, and the creation thereof

use std::os::{
    fd::{AsRawFd, RawFd},
    unix::net::UnixStream,
};

use nix::sys::socket::{socket, AddressFamily, SockFlag, SockProtocol, SockType};
use passfd::FdPassingExt;
use tun::{Configuration, Device};

use crate::data::{PassFD, SocketC, TUNC};

use super::*;

#[test]
fn tun() -> Result<()> {
    let mut conf: Configuration = Default::default();
    conf.name("t0");
    conf.layer(tun::Layer::L2);
    let mut dev = tun::create(&conf)?;
    dev.persist()?; // This is called on an FD
                    // how much should prober do ?
                    // create a device with a sensible default name
                    // ig Layer can only be specified before getting the FD
    Ok(())
}

impl PassFD<TUNC> {
    pub fn pass(&self) -> Result<()> {
        let mut conf: Configuration = Default::default();

        #[cfg(target_os = "linux")]
        conf.platform(|config| {
            config.packet_information(true);
            config.apply_settings(false);
        });

        conf.layer(self.creation.layer);
        if let Some(na) = &self.creation.name {
            conf.name(na);
        }
        let mut dev = tun::create(&conf)?;
        dev.enabled(true)?;
        dev.set_nonblock()?;
        dev.persist()?;
        self.connect_and_pass(&dev)?;
        Ok(())
    }
}

impl PassFD<SocketC> {
    pub fn pass(&self) -> Result<()> {
        let sock = socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::Tcp,
        )?;
        self.connect_and_pass(&sock)?;

        Ok(())
    }
}

impl<K> PassFD<K> {
    pub fn connect_and_pass(&self, fd: &impl AsRawFd) -> Result<()> {
        log::info!("connect {:?}", &self.listener);
        let conn = UnixStream::connect(&self.listener)?;
        conn.send_fd(fd.as_raw_fd())?;

        Ok(())
    }
}
