use std::{time::Duration, env::args};

use tun::{Configuration, Device};

fn main() -> anyhow::Result<()> {
    let mut ar = args();
    ar.next();
    let mut conf: Configuration = Default::default();

    #[cfg(target_os = "linux")]
    conf.platform(|config| {
        config.packet_information(true);
        config.apply_settings(false);
    });
    conf.layer(tun::Layer::L3);
    conf.name("testtun");
    let mut dev = tun::create(&conf)?;
    dev.enabled(true)?;
    dev.set_nonblock()?;
    let n = ar.next().unwrap().parse()?;
    dev.set_mtu(n)?; // even 10000 works

    std::thread::sleep(Duration::from_secs(1000));

    Ok(())
}
