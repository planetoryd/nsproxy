#![feature(associated_type_defaults)]

use std::borrow::Borrow;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::hash::Hash;
use std::io::ErrorKind;
use std::path::Path;
use std::{borrow::Cow, os::fd::AsRawFd, path::PathBuf};

use anyhow::ensure;
use anyhow::Result;
use derive_new::new;
use fully_pub::fully_pub as public;
use indexmap::{Equivalent, IndexMap};
use libc::stat;
use nix::errno::Errno;
use nix::{libc::pid_t, unistd::getpid};
use owo_colors::OwoColorize;
use serde::{de::Visitor, Deserialize, Serialize};

/// Represents an NS anchored to a process, or a file
/// Equality iff .unique equals
#[public]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct ExactNS {
    unique: UniqueFile,
    source: NSSource,
}

impl Display for ExactNS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("File {} ", self.unique.yellow()))?;
        match self.source {
            NSSource::Pid(ref p) => f.write_fmt(format_args!("from pid {}", p.bright_purple())),
            NSSource::Path(ref p) => f.write_fmt(format_args!("at {:?}", p.yellow())),
            NSSource::Unavail(b) => f.write_fmt(format_args!("{}", "Unavailable".magenta())),
        }
    }
}

/// We don't care about the means.
/// We want to uniquely identify a file so we don't get into a wrong NS.
/// IIRC ino and dev uniquely identifies a file
#[public]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord, new)]
struct UniqueFile {
    ino: u64,
    dev: u64,
}

impl From<stat> for UniqueFile {
    fn from(value: stat) -> Self {
        Self {
            ino: value.st_ino,
            dev: value.st_dev,
        }
    }
}

impl Serialize for UniqueFile {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self { ino, dev } = self;
        serializer.serialize_str(&format!("{dev}_{ino}"))
    }
}

impl core::fmt::Display for UniqueFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { ino, dev } = self;
        f.write_fmt(format_args!("{dev}_{ino}"))
    }
}

impl<'de> Deserialize<'de> for UniqueFile {
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(UFVisitor)
    }
}

struct UFVisitor;

impl<'de> Visitor<'de> for UFVisitor {
    type Value = UniqueFile;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("string representation of UniqueFile")
    }
    fn visit_str<E>(self, v: &str) -> std::prelude::v1::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let mut sp = v.split("_");
        Ok(UniqueFile {
            dev: sp
                .next()
                .ok_or(serde::de::Error::missing_field("dev"))?
                .parse()
                .map_err(serde::de::Error::custom)?,
            ino: sp
                .next()
                .ok_or(serde::de::Error::missing_field("ino"))?
                .parse()
                .map_err(serde::de::Error::custom)?,
        })
    }
}

/// Pid literal
#[derive(Clone, Copy, Debug)]
pub enum PidPath {
    Selfproc,
    N(i32),
}

#[public]
impl PidPath {
    fn to_str(&self) -> Cow<'static, str> {
        match self {
            PidPath::N(n) => n.to_string().into(),
            PidPath::Selfproc => "self".into(),
        }
    }
    /// Convert it to pid number
    fn to_n(&self) -> Self {
        match self {
            PidPath::Selfproc => Self::N(getpid().as_raw()),
            k => *k,
        }
    }
}

pub trait NSFrom<S>: Sized {
    fn from_source(source: S) -> Result<Self>;
}

impl NSFrom<PathBuf> for ExactNS {
    fn from_source(path: PathBuf) -> Result<Self> {
        let stat = nix::sys::stat::stat(&path)?;
        Ok(Self {
            unique: stat.into(),
            source: NSSource::Path(path),
        })
    }
}

impl NSFrom<(PidPath, &str)> for ExactNS {
    fn from_source(source: (PidPath, &str)) -> Result<Self> {
        let path = PathBuf::from(format!(
            "/proc/{}/ns/{}",
            source.0.to_n().to_str(),
            source.1
        ));
        NSFrom::from_source(path)
    }
}

impl NSFrom<pid_t> for ExactNS {
    fn from_source(source: pid_t) -> Result<Self> {
        Ok(Self {
            unique: pidfd_uf(source)?.into(),
            source: NSSource::Pid(source),
        })
    }
}

impl UniqueFile {
    pub fn validate(&self, fst: &stat) -> Result<(), ValidationErr> {
        if fst.st_ino == self.ino && fst.st_dev == self.dev {
            Ok(())
        } else {
            Err(ValidationErr::InoMismatch)
        }
    }
}

use thiserror::Error;

#[derive(Error, Debug)]
#[error("{:?}", self)]
pub enum ValidationErr {
    InoMismatch,
    FileNonExist,
    FileNonExistProc,
    ProcessGone,
    Permission,
}

#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum NSSource {
    Pid(pid_t),
    Path(PathBuf),
    /// Ex. running as an unprivileged process, the root NS can't be stated.
    /// And we don't keep ephemeral proc fs paths either
    /// Treated as path when validating
    /// True for IOCTL-able
    /// False for not (usually root ns)
    Unavail(bool),
}

#[derive(Default)]
#[public]
struct VaCache {
    pid: IndexMap<NSedPid, stat>,
    mnt: IndexMap<NSedPath, stat>,
}

#[test]
fn getbyref() {
    let va = VaCache::default();
    let uq = UniqueFile { ino: 0, dev: 0 };
    va.pid.get(&(0, &uq));
    let pa = PathBuf::new();
    va.mnt.get(&(&pa, &uq));
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct NSedPid(pid_t, UniqueFile);

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct NSedPath(PathBuf, UniqueFile);

pub type NPid<'k> = (pid_t, &'k UniqueFile);
impl Equivalent<NSedPid> for NPid<'_> {
    fn equivalent(&self, key: &NSedPid) -> bool {
        self.0 == key.0 && self.1 == &key.1
    }
}

impl<'a> From<&'a NPid<'a>> for NSedPid {
    fn from(value: &'a NPid) -> Self {
        Self(value.0.to_owned(), value.1.to_owned())
    }
}

pub type NMnt<'k> = (&'k PathBuf, &'k UniqueFile); // Namespaced mount

impl Equivalent<NSedPath> for NMnt<'_> {
    fn equivalent(&self, key: &NSedPath) -> bool {
        self.0 == &key.0 && self.1 == &key.1
    }
}

impl<'a> From<&'a NMnt<'_>> for NSedPath {
    fn from(value: &'a NMnt) -> Self {
        Self(value.0.to_owned(), value.1.to_owned())
    }
}

pub trait CachedMap {
    type K;
    type V;
    fn cached_get<'e, E: Equivalent<Self::K> + Hash + PartialEq>(
        &mut self,
        key: &'e E,
        init: impl FnOnce(&E) -> Result<Self::V>,
    ) -> Result<&Self::V>
    where
        &'e E: Into<Self::K>;
}

impl<K: Hash + Eq, V> CachedMap for IndexMap<K, V> {
    type K = K;
    type V = V;
    fn cached_get<'e, E: Equivalent<Self::K> + Hash + PartialEq>(
        &mut self,
        key: &'e E,
        init: impl FnOnce(&E) -> Result<Self::V>,
    ) -> Result<&Self::V>
    where
        &'e E: Into<Self::K>,
    {
        if !self.contains_key(key) {
            self.insert(key.into(), init(key)?);
        }
        Ok(self.get(key).unwrap())
    }
}

pub fn cached_fstat<'m>(ca: &'m mut VaCache, cp: NPid) -> Result<&'m stat> {
    ca.pid.cached_get(&cp, |k| pidfd_uf(k.0))
}

/// Stat by a pid
pub fn pidfd_uf(k: pid_t) -> Result<stat> {
    match unsafe { pidfd::PidFd::open(k, 0) } {
        Ok(f) => {
            let fd = f.as_raw_fd();
            let st = nix::sys::stat::fstat(fd)?;
            Ok(st)
        }
        Err(eno) => {
            // WARN This should be "no such process", but who knows
            if eno.raw_os_error() == Some(3) {
                return Err(ValidationErr::ProcessGone.into());
            } else {
                return Err(eno.into());
            }
        }
    }
}

pub fn cached_stat<'k>(ca: &'k mut VaCache, path: NMnt) -> Result<&'k stat> {
    ca.mnt.cached_get(&path, |k| {
        let st = nix::sys::stat::stat::<Path>(k.0.as_path());
        if let Err(ref e) = st {
            match e {
                Errno::ENOENT => Err(if k.0.starts_with("/proc/") {
                    ValidationErr::FileNonExistProc.into()
                } else {
                    ValidationErr::FileNonExist.into()
                }),
                Errno::EPERM | Errno::EACCES => Err(ValidationErr::Permission.into()),
                _ => Err(st.unwrap_err().into()),
            }
        } else {
            Ok(st.unwrap())
        }
    })
}

#[test]
fn test_f() {
    let rx = nix::sys::stat::stat("./nonexist");
    let _ = dbg!(rx);
    let rx = unsafe { pidfd::PidFd::open(65532, 0) };
    let ox = rx.err().unwrap();
    let _ = dbg!(ox.raw_os_error());
}
