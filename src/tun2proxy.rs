use std::{net::IpAddr, os::fd::RawFd, path::PathBuf};

use nix::sched::CloneFlags;
use schematic::Config;
use serde::{Deserialize, Serialize};
use tun2proxy::{tun_to_proxy, NetworkInterface, Options, Proxy};

use anyhow::Result;

use crate::int_repr;

/// Runtime config
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Config)]
pub struct PNodeConf {
    #[serde(default)]
    pub tap: bool,
    pub daemon: ProxyDaemon
}


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Config)]
pub enum ProxyDaemon {
    /// For this out NS, we also start a systemd .service of user supplied proxy process in out NS
    /// It listens on a unix socket. This process should connect to it and pass an FD.
    FDPassing(PathBuf),
    /// Here we interface with the proxy program through socks5, the most well-known one.
    Socks5(TUN2Proxy)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Config)]
pub struct TUN2Proxy {
    /// Url to upstream proxy
    #[setting(default = "socks5://127.0.0.1:9909")]
    pub url: String,
    pub dns: TUN2DNS,
    /// Disabling will remove Ipv6 entries from DNS (when TUN2DNS::Upstream is enabled)
    #[serde(default)]
    pub ipv6: bool,
    /// Treat the FD as Tap
    #[serde(default)]
    pub tap: bool,
    #[setting(default = 1500)]
    pub mtu: usize,
    // CloneFlags to setns
    // #[serde(default)]
    // pub setns: WCloneFlags,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub enum TUN2DNS {
    /// Resolve names by the proxy. This is usually better
    #[default]
    Proxy,
    /// Resolve names *through* the proxy. 
    /// It does DNS lookups through the proxy, the channel it provides.
    Upstream(IpAddr),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Copy)]
pub struct WCloneFlags(#[serde(with = "int_repr")] pub CloneFlags);

impl Default for WCloneFlags {
    fn default() -> Self {
        // default value suited for flatpak, and typically other rootless use cases
        Self(CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUSER)
    }
}

pub fn tuntap(args: TUN2Proxy, dev: RawFd) -> Result<()> {
    let proxy = Proxy::from_url(&args.url)?;
    let mut opts = Options::new();
    match args.dns {
        TUN2DNS::Proxy => opts = opts.with_virtual_dns(),
        TUN2DNS::Upstream(a) => opts = opts.with_dns_over_tcp().with_dns_addr(Some(a)),
    }
    if args.ipv6 {
        opts = opts.with_ipv6_enabled()
    }

    opts = opts.with_mtu(args.mtu as usize);

    let mut ttp = tun_to_proxy(&NetworkInterface::Fd(dev), &proxy, opts)?;
    ttp.run()?; // starts the event loop

    Ok(())
}