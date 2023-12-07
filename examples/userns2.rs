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
    let path = PathState::default()?;
    let (mut sa, mut sb) = UnixStream::pair()?;
    let mut b = [0; 1];
    match unsafe { fork()? } {
        ForkResult::Child => {
            let u = Uid::from_raw(1000);
            setresuid(u, u, u)?;
            capctl::prctl::set_dumpable(true)?;
            unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS)?;
            sa.write_all(&[0])?;
            sa.read_exact(&mut b)?;
            
            let caps = capctl::CapState::get_current().unwrap();
            dbg!(caps);
            let u = Uid::from_raw(0);
            setresuid(u, u, u)?;
            let caps = capctl::CapState::get_current().unwrap();
            dbg!(caps);
            
            bash()?;
        }
        ForkResult::Parent { child } => {
            sb.read_exact(&mut b)?;
            let mut f = OpenOptions::new()
                .write(true)
                .open(format!("/proc/{}/uid_map", child.as_raw()))?;
            f.write_all(b"1000 1000 1 \n 0 1001 1 ")?;
            let mut f = OpenOptions::new()
                .write(true)
                .open(format!("/proc/{}/gid_map", child.as_raw()))?;
            f.write_all(b"0 0 4294967295")?;
            let puser: PathBuf = ["/proc", &child.as_raw().to_string(), "ns", "user"]
                .iter()
                .collect();
            let up = "/tmp/usermnt";
            mount(
                Some(&puser),
                up,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )?;
            sb.write_all(&[1])?;

            waitpid(Some(Pid::from_raw(-1)), None)?;
        }
    }

    Ok(())
}

fn bash() -> Result<()> {
    let mut cmd = Command::new("/usr/bin/bash");
    let mut sp = cmd.spawn()?;
    sp.wait()?;
    Ok(())
}
