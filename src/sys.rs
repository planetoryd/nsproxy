//! Misc low-level code

use std::{
    fs::{create_dir, create_dir_all, remove_dir_all, remove_file, File, OpenOptions},
    io::{Read, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::PathBuf,
    process::exit,
    sync::mpsc::sync_channel,
};

use amplify::default;
use anyhow::{bail, ensure};
use daggy::NodeIndex;
use libc::{pid_t, stat, syscall};
use nsproxy_common::Validate;

use super::*;
use crate::{
    data::*,
    paths::{Binds, PathState, Paths},
};

use nix::{
    mount::{mount, umount, MsFlags},
    sched::{setns, unshare, CloneFlags},
    sys::{signal::kill, stat::fstat},
    unistd::{fork, setresgid, setresuid, setuid, ForkResult, Gid, Uid, getuid, seteuid},
};

use std::{mem::size_of, os::fd::RawFd};

use anyhow::Result;
use nix::{
    errno::Errno,
    libc::{c_int, SYS_mount_setattr, AT_FDCWD, MS_PRIVATE},
    NixPath,
};

#[public]
impl<K: NSTrait> NSSlot<ExactNS<PathBuf>, K> {
    fn mount(pid: PidPath, binds: &Binds) -> Result<Self> {
        let name = K::NAME;
        let path: PathBuf = ["/proc", pid.to_str().as_ref(), "ns", name]
            .iter()
            .collect();
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

        Ok(NSSlot::Provided(
            ExactNS {
                source: path,
                unique: stat.into(),
            },
            default!(),
        ))
    }
}

pub macro mount_by_pid( $pid:expr,$binds:expr,$group:ident,[$($name:ident),*] ) {
    $(
        $group.$name = NSSlot::mount($pid, $binds)?;
    )*
}

pub macro ns_call( $group:ident, $func:ident,[$($name:ident),*] ) {
    $(
        $group.$name.$func()?;
    )*
}

#[public]
impl ProcNS {
    /// Pin down namespaces of a process.
    fn mount(pid: PidPath, paths: &PathState, id: NodeI) -> Result<Self> {
        let mut nsg: NSGroup<ExactNS<PathBuf>> = NSGroup::default();
        let binds = paths.mount(id)?;
        mount_by_pid!(pid, &binds, nsg, [net, uts, pid]);

        Ok(Self::ByPath(nsg))
    }
    /// Identify the key as in the map
    fn key_ident(pid: PidPath) -> Result<ExactNS<PathBuf>> {
        ExactNS::<PathBuf>::from_pid(pid, "net")
    }
    // fn enter(&self, _f: CloneFlags) -> Result<()> {
    fn enter(&self) -> Result<()> {
        match &self {
            ProcNS::ByPath(ng) => {
                // Order matters
                ns_call!(ng, enter_if, [user, mnt, net]);
                // TODO: Because I am not sure what are the needs here
                // 1. Rootful mode
                // 2. Rootless mode
                // 3. Handling of other NSes ?
            }
            _ => todo!(),
        }
        Ok(())
    }
    fn key(&self) -> UniqueFile {
        match self {
            ProcNS::ByPath(p) => match &p.net {
                NSSlot::Provided(a, _) => a.unique,
                _ => unreachable!(),
            },
            ProcNS::PidFd(p) => p.unique,
        }
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
    let mounted = ProcNS::mount(PidPath::Selfproc, &path, 3.into())?;
    dbg!(mounted);

    Ok(())
}

// On the assumption that default NSes do not change across boots;
// Otherwise, we will have one new 'default node' each reboot.
impl ObjectNode {
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
    /// Uses Pid FD
    pub fn from(pid: pid_t) -> Result<Self> {
        let f = unsafe { pidfd::PidFd::open(pid, 0) }?;
        let fd = f.as_raw_fd();
        let st = fstat(fd)?;
        Ok(ExactNS {
            unique: st.into(),
            source: pid,
        })
    }
}

#[public]
impl ExactNS<PathBuf> {
    fn from(path: PathBuf) -> Result<Self> {
        let stat = nix::sys::stat::stat(&path)?;
        Ok(Self {
            unique: stat.into(),
            source: path,
        })
    }
    pub fn from_pid(pid: PidPath, name: &str) -> Result<Self> {
        let path = PathBuf::from(format!("/proc/{}/ns/{}", pid.to_str(), name));
        let stat = nix::sys::stat::stat(&path)?;
        Ok(Self {
            unique: stat.into(),
            source: path,
        })
    }
}

impl NSEnter for ExactNS<PathBuf> {
    fn enter(&self, f: CloneFlags) -> Result<()> {
        let fd = File::open(&self.source)?;
        setns(fd, f)?;
        Ok(())
    }
}

pub trait NSEnter {
    fn enter(&self, f: CloneFlags) -> Result<()>;
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

impl Validate for ProcNS {
    fn validate(&self) -> Result<()> {
        match &self {
            Self::ByPath(p) => p.validate(),
            Self::PidFd(p) => p.validate(),
        }
    }
}

pub struct UserNS<'p>(pub &'p PathState);

#[test]
fn sockpairfork() -> Result<()> {
    let (mut sa, mut sb) = UnixStream::pair()?;

    match unsafe { fork() }? {
        ForkResult::Child => {
            sa.write_all(&[2])?;
        }
        ForkResult::Parent { child } => {
            let mut k: [u8; 1] = [0];
            sb.read_exact(&mut k)?;
            dbg!(k);
        }
    }

    Ok(())
}

#[public]
impl<'p> UserNS<'p> {
    fn mapid(&self, uid: u32) -> Result<()> {

        Ok(())
    }
    fn init(&self) -> Result<()> {
        let private = self.0.private();
        create_dir_all(&private)?; // doesnt error when dir exists
        mount(
            // CAP_SYS_ADMIN
            Some(&private),
            &private,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )?;

        let mut att = MountAttr::default();
        att.propagation = MS_PRIVATE;
        unsafe { mount_setattr(AT_FDCWD, &private, 0, &att as *const _) }?;
        let (user, mnt) = self.paths();
        let _ = File::create(&mnt)?;
        let _ = File::create(&user)?;

        let (mut sa, mut sb) = UnixStream::pair()?;

        match unsafe { fork() }? {
            ForkResult::Child => {
                let u = Uid::from_raw(1000);
                seteuid(u)?;

                unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS)?;
                let mut f = OpenOptions::new().write(true).open("/proc/self/uid_map")?;
                f.write_all(b"0 1000 1")?; // map 0 (in user ns) to uid (outside)
        

                sa.write_all(&[0])?;
                let mut k: [u8; 1] = [0];
                sa.read_exact(&mut k)?;
                exit(0);
            }
            ForkResult::Parent { child } => {
                let puser: PathBuf = ["/proc", &child.as_raw().to_string(), "ns", "user"]
                    .iter()
                    .collect();
                let pmnt: PathBuf = ["/proc", &child.as_raw().to_string(), "ns", "mnt"]
                    .iter()
                    .collect();
                let mut k: [u8; 1] = [0];
                sb.read_exact(&mut k)?;
                mount(
                    Some(&puser),
                    &self.0.user(),
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                )?;
                mount(
                    Some(&pmnt),
                    &mnt,
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                )?;
                sa.write_all(&[0])?;
                log::info!("UserNS inited")
            }
        }

        Ok(())
    }
    fn deinit(&self) -> Result<()> {
        let (user, mnt) = self.paths();
        let private = mnt.parent().unwrap();
        if private.exists() {
            if let Err(k) = umount(private) {
                if k == Errno::EINVAL {
                    // maybe no mount. ok
                } else {
                    // try umounting mnt, which is also ok
                    if let Err(x) = umount(&mnt) {
                        if x == Errno::EINVAL {
                            // maybe no mount. ok
                        } else {
                            bail!(x);
                        }
                    } else {
                        remove_file(&mnt)?;
                    }
                }
            } else {
                remove_dir_all(&private)?;
            }
        }
        if user.exists() {
            if let Err(k) = umount(&user) {
                if k == Errno::EINVAL {
                    // maybe no mount
                } else {
                    bail!(k);
                }
            }
            remove_file(&user)?;
        }
        log::info!("UserNS deinited");
        Ok(())
    }
    fn paths(&self) -> (PathBuf, PathBuf) {
        (self.0.user(), self.0.private().join("mnt"))
    }
    /// Generate a [ProcNS]
    fn procns(&self) -> Result<ProcNS> {
        let (user, mnt) = self.paths();
        Ok(ProcNS::ByPath(NSGroup {
            user: NSSlot::Provided(ExactNS::<PathBuf>::from(user)?, default!()),
            mnt: NSSlot::Provided(ExactNS::<PathBuf>::from(mnt)?, default!()),
            ..Default::default()
        }))
    }
}

#[test]
fn show_userns_path() -> Result<()> {
    let path = PathState::default()?;
    let usern = UserNS(&path);
    dbg!(usern.paths());

    Ok(())
}

#[test]
fn test_userns() -> Result<()> {
    let path = PathState::default()?;
    let usern = UserNS(&path);
    dbg!(usern.paths());
    usern.init()?;

    Ok(())
}

#[test]
fn userns_deinit() -> Result<()> {
    let path = PathState::default()?;
    let usern = UserNS(&path);
    dbg!(usern.paths());
    usern.deinit()?;

    Ok(())
}

#[derive(Default)]
#[repr(C, align(8))]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    unserns_fd: u64,
}

unsafe fn mount_setattr(
    dirfd: RawFd,
    path: &impl NixPath,
    flags: c_int,
    attr: *const MountAttr,
) -> Result<(), Errno> {
    let k = path.with_nix_path(|pa| unsafe {
        syscall(
            SYS_mount_setattr,
            dirfd,
            pa.as_ptr(),
            flags,
            attr,
            size_of::<MountAttr>(),
        )
    })?;

    Errno::result(k).map(drop)
}

pub fn check_capsys() -> Result<()> {
    let caps = capctl::CapState::get_current().unwrap();
    if !caps.effective.has(capctl::Cap::SYS_ADMIN) {
        bail!("requires CAP_SYS_ADMIN. You can run this program as root, or use a user-namespace, or set it to SUID ");
    }

    Ok(())
}
