use std::{net::IpAddr, os::fd::RawFd, path::PathBuf};

use nix::sched::CloneFlags;
use schematic::{Config, ConfigLoader};
use serde::{Deserialize, Serialize};
use tun2proxy::{tun_to_proxy, NetworkInterface, Options, Proxy};

use anyhow::Result;
use super::public;

#[public]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Config)]
pub struct TUN2Proxy {
    /// Url to upstream proxy
    #[setting(default = "socks5://127.0.0.1:9909")]
    url: String,
    dns: TUN2DNS,
    /// Disabling will remove Ipv6 entries from DNS (when TUN2DNS::Upstream is enabled)
    #[serde(default)]
    ipv6: bool,
    /// Treat the FD as Tap
    #[serde(default)]
    tap: bool,
    #[setting(default = 1500)]
    mtu: usize,
}

#[test]
fn emptyconf() -> Result<()> {
    let conf = TUN2Proxy::default();
    let st = serde_json::to_string_pretty(&conf)?;
    println!("{}", &st);
    Ok(())
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub enum TUN2DNS {
    /// Resolve names *by* the proxy. This is usually better
    #[default]
    Handled,
    /// Resolve names *through* the proxy. 
    /// It does DNS lookups through the proxy, the channel it provides.
    Upstream(IpAddr),
}

pub fn tuntap(args: TUN2Proxy, dev: RawFd) -> Result<()> {
    let proxy = Proxy::from_url(&args.url)?;
    let mut opts = Options::new();
    match args.dns {
        TUN2DNS::Handled => opts = opts.with_virtual_dns(),
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

pub fn load_conf(conf: PathBuf) -> Result<TUN2Proxy> {
    let loaded = ConfigLoader::<TUN2Proxy>::new().file(conf)?.load()?;
    Ok(loaded.config)
}
