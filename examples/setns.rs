use std::{
    fs::{File, OpenOptions, Permissions},
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::PathBuf,
    process::{exit, Command},
};

use anyhow::Result;
use nix::{
    mount::{mount, umount, MsFlags},
    sched::{setns, unshare, CloneFlags},
    sys::{signal::kill, stat::fstat, wait::waitpid},
    unistd::{
        fork, getresuid, getuid, seteuid, setresgid, setresuid, setuid, ForkResult, Gid, Pid, Uid,
    },
};
use nsproxy::{paths::PathState, sys::UserNS};

fn main() -> Result<()> {
    let f = File::open("/etc/nsproxy/user")?;
    setns(f, CloneFlags::CLONE_NEWUSER)?;
    let caps = capctl::CapState::get_current().unwrap();
    dbg!(caps);

    bash()?;

    Ok(())
}

fn f2() -> Result<()> {
    // let u = Uid::from_raw(1001);
    // setresuid(u, u, u)?;
    let f = File::open("/tmp/usermnt")?;
    setns(f, CloneFlags::CLONE_NEWUSER)?;
    let caps = capctl::CapState::get_current().unwrap();
    dbg!(caps);
    let u = Uid::from_raw(0);
    setresuid(u, u, u)?;
    let caps = capctl::CapState::get_current().unwrap();
    dbg!(caps);

    bash()?;

    Ok(())
}


fn bash() -> Result<()> {
    let mut cmd = Command::new("/usr/bin/bash");
    let mut sp = cmd.spawn()?;
    sp.wait()?;
    Ok(())
}
