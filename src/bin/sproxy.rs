//! NSProxy (net namespace proxy)
//! SProxy (S for SUID)
//! This is an SUID wrapper that just starts nsproxy
//! It currently requires SUDO and password for all operations

#![feature(iterator_try_collect)]

use std::{
    env::{args, vars},
    ffi::CString,
    os::unix::ffi::OsStrExt,
    path::Path,
    process::Command,
};

use anyhow::{anyhow, bail};
use nix::unistd::execve;
use nsproxy::{aok, UID_HINT_VAR};

fn main() -> anyhow::Result<()> {
    let mut ce = std::env::current_exe()?;
    ce.set_file_name("nsproxy");
    if !ce.exists() {
        println!("can not find nsproxy binary. It must exist in the same directory as sproxy.")
    }
    let puid = nsproxy::sys::what_uid(None, true)?; // This may take an env-var-supplied UID as the non-root uid
    sudo_check(&ce)?;
    let args: Vec<_> = args().map(|k| CString::new(k.into_bytes())).try_collect()?;
    let mut vars: Vec<_> = vars()
        .map(|(x, y)| CString::new(format!("{x}={y}").into_bytes()))
        .try_collect()?;
    vars.push(CString::new(format!("{UID_HINT_VAR}={puid}"))?);
    execve(&CString::new(ce.as_os_str().as_bytes())?, &args, &vars)?;
    Ok(())
}

fn sudo_check(nsp: &Path) -> anyhow::Result<()> {
    let mut cmd = Command::new("/usr/bin/sudo");
    cmd.arg(nsp).arg("noop");
    let mut ch = cmd.spawn()?;
    let status = ch.wait()?;
    if status.success() {
        Ok(())
    } else {
        bail!("Authentication failed")
    }
}
