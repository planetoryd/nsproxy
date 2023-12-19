use std::{
    fs::File,
    os::fd::{AsRawFd, FromRawFd, OwnedFd}, process::Command,
};

use anyhow::Result;
use linux_raw_sys::ioctl::{NS_GET_OWNER_UID, NS_GET_PARENT, NS_GET_USERNS};
use nix::sched::{setns, CloneFlags};
use nsproxy::sys::your_shell;

fn main() -> Result<()> {
    let f = std::fs::File::open("/proc/456684/ns/net")?;
    let f2 = unsafe { libc::ioctl(f.as_raw_fd(), NS_GET_USERNS.into()) };
    // let sta = nix::sys::stat::fstat(f2)?;
    // dbg!(sta);
    let f2 = unsafe { File::from_raw_fd(f2) };
    setns(&f2, CloneFlags::CLONE_NEWUSER)?;
    setns(&f, CloneFlags::CLONE_NEWNET)?;
    // Okay, this works for a flatpak process
    let mut cmd = Command::new(your_shell(Some("fish".to_owned()))?.unwrap());
    cmd.spawn()?.wait()?;
    Ok(())
}
