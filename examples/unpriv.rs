#![feature(iterator_try_collect)]

use std::{
    env::{args, vars},
    ffi::{CStr, CString},
    fs::OpenOptions,
    io::Write,
    os::unix::process::CommandExt,
    process::Command,
};

use anyhow::Result;
use capctl::{caps::Cap, CapSet};
use nix::{
    sched::{unshare, CloneFlags, clone},
    unistd::{execve, Pid}, sys::wait::waitpid,
};
use nsproxy::sys::your_shell;


// I want to have the same NETNS (USER + NET) enterable by a non-root user
// as both normal unprivileged user (for usual programs) and privileged user (for like wireshark) in the namespace
// I can't yet do this.
fn main() -> Result<()> {

    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET)?;
    let mut f = OpenOptions::new()
        .write(true)
        .open(format!("/proc/self/uid_map"))?;
    f.write_all(format!("1000 1000 1").as_bytes())?;
    // setcap(0);
    // setcap(1000);
    let _ = capctl::ambient::raise(Cap::NET_ADMIN);
    let amb = capctl::ambient::probe();
    let bo = capctl::bounding::probe();
    dbg!(&amb, &bo);

    // let caps = capctl::CapState::get_current().unwrap();
    // dbg!(&caps);

    // let mut cmd = Command::new(your_shell(None)?.unwrap());
    // let mut ch = cmd.spawn()?;
    // ch.wait()?;

    let args: Vec<CString> = vec![];
    let vars: Vec<_> = vars()
        .map(|(x, y)| CString::new(format!("{x}={y}").into_bytes()))
        .try_collect()?;
    println!("exec");
    execve(&CString::new(SHOW_CAPS)?, &args, &vars)?;
    
    waitpid(Some(Pid::from_raw(-1)), None)?;

    Ok(())
}

fn setcap(u: u32) -> Result<()> {
    let mut fc = capctl::FileCaps::empty();
    let mut cs = CapSet::empty();
    cs.add(Cap::NET_ADMIN);
    fc.permitted = cs;
    fc.effective = true;
    fc.rootid = Some(u); 
    // This is the absolute uid_t (that is, the uid_t in user
    //     namespace which mounted the filesystem, usually init_user_ns) of the
    //     root id in whose namespaces the file capabilities may take effect.
    fc.set_for_file(SHOW_CAPS)?;
    Ok(())
}

static SHOW_CAPS: &'static str = "/space/nsproxy/target/debug/examples/caps";
