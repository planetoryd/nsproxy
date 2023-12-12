use serde_json::to_string_pretty;
use clap::Parser;
use tun2socks5::{ArgProxy, IArgs, ArgDns};
use anyhow::Result;


fn main() -> Result<()> {
    let ia = IArgs {
        proxy: ArgProxy::from_url("socks5://127.0.0.1:9909")?,
        ipv6_enabled: true,
        dns: ArgDns::Handled,
        dns_addr: "127.0.0.1".parse()?,
        bypass: Default::default()
    };
    let s = to_string_pretty(&ia)?;
    println!("{}", &s);
    Ok(())
}