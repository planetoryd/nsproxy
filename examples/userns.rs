use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::net::UnixStream,
    process::{exit, Command},
};

use anyhow::Result;
use nix::{
    mount::{mount, umount, MsFlags},
    sched::{setns, unshare, CloneFlags},
    sys::{signal::kill, stat::fstat},
    unistd::{fork, getuid, seteuid, setresgid, setresuid, setuid, ForkResult, Gid, Uid, getresuid},
};
use nsproxy::{paths::PathState, sys::UserNS};

fn main() -> Result<()> {
    let path = PathState::default()?;
    let usern = UserNS(&path);
    // let _deinit = usern.deinit();
    dbg!(getresuid()?);
    let mut a = std::env::args();
    a.next();
    match a.next().unwrap().as_str() {
        "i" => {
            // Unshare and mount, requires root
            // Weird it doesn't work
            usern.init()?;
        }
        "s" => {
            usern.procns()?.enter()?;
        },
        "n" => {
            // Requires no root. This works.
            let u = Uid::from_raw(1000);
            seteuid(u)?;
            unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS)?;
            let mut f = OpenOptions::new().write(true).open("/proc/self/uid_map")?;
            f.write_all(b"0 1000 1")?; // map 0 (in user ns) to uid (outside)
        }
        _ => (),
    }
    bash()?;

    Ok(())
}

fn bash() -> Result<()> {
    let mut cmd = Command::new("/usr/bin/bash");
    let mut sp = cmd.spawn()?;
    sp.wait()?;
    Ok(())
}
