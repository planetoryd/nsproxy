//! Misc low-level code

use std::{fs::File, os::fd::AsRawFd, path::PathBuf};

use anyhow::{bail, ensure};
use libc::{pid_t, stat};
use nsproxy_common::Validate;

use super::*;
use crate::{
    data::*,
    paths::{PathState, Paths},
};

use nix::{
    mount::{mount, MsFlags},
    sys::{signal::kill, stat::fstat},
};

impl ProcNS {
    /// Pin down namespaces of a process.
    pub fn mount(pi: &str, paths: Paths, id: NodeID) -> Result<Self> {
        let mut nsg: NSGroup<ExactNS<PathBuf>> = NSGroup::default();
        let binds = paths.mount(id)?;
        for (val, name) in nsg.list() {
            if name == "mnt" {
                // This one is special
                continue;
            }
            let path: PathBuf = ["/proc", pi, "ns", name].iter().collect();
            let stat = nix::sys::stat::stat(&path)?;
            let bindat = binds.ns(name);
            let _ = File::create(&bindat)?;
            dbg!(&path, &bindat);
            mount(
                Some(&path),
                &bindat,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )?;

            *val = Some(ExactNS {
                source: path,
                unique: stat.into(),
            });
        }
        Ok(Self::ByPath(nsg))
    }
}

// cargo test mount_self -- --nocapture
// use no capture to avoid rust hiding stdout
// test this with ./unshare.sh
#[test]
fn mount_self() -> Result<()> {
    let path = PathState::default()?;
    let path: Paths = path.into();
    dbg!(path.clone());
    let mounted = ProcNS::mount("self", path.clone(), 3)?;
    dbg!(mounted);

    Ok(())
}

// On the assumption that default NSes do not change across boots;
// Otherwise, we will have one new 'default node' each reboot.
impl PNode {
    pub fn this() {}
}

impl From<stat> for UniqueFile {
    fn from(value: stat) -> Self {
        Self {
            ino: value.st_ino,
            dev: value.st_dev,
        }
    }
}

impl ExactNS<pid_t> {
    pub fn from(pid: pid_t, name: &str) -> Result<Self> {
        let path = PathBuf::from(format!("/proc/{}/ns/{}", pid, name));
        let stat = nix::sys::stat::stat(&path)?;
        Ok(Self {
            unique: stat.into(),
            source: pid,
        })
    }
}

impl UniqueFile {
    fn validate(&self, fst: stat) -> Result<()> {
        ensure!(fst.st_ino == self.ino && fst.st_dev == self.dev);
        Ok(())
    }
}

impl Validate for ExactNS<pid_t> {
    fn validate(&self) -> Result<()> {
        let f = unsafe { pidfd::PidFd::open(self.source, 0) }?;
        let fd = f.as_raw_fd();
        let st = fstat(fd)?;
        self.unique.validate(st)?;
        Ok(())
    }
}

impl Validate for ExactNS<PathBuf> {
    fn validate(&self) -> Result<()> {
        let st = nix::sys::stat::stat(&self.source)?;
        self.unique.validate(st)?;
        Ok(())
    }
}
