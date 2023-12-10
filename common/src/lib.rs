#![feature(associated_type_defaults)]

use std::error::Error;
use std::io::ErrorKind;
use std::path::Display;
use std::{borrow::Cow, os::fd::AsRawFd, path::PathBuf};

use anyhow::ensure;
use anyhow::Result;
use fully_pub::fully_pub as public;
use libc::stat;
use nix::errno::Errno;
use nix::{libc::pid_t, unistd::getpid};
use serde::{de::Visitor, Deserialize, Serialize};

pub trait Validate {
    fn validate(&self) -> Result<()>;
}

/// Represents an NS anchored to a process, or a file
/// Equality iff .unique equals
#[public]
#[derive(Serialize, Deserialize, Debug, Clone)]
struct ExactNS<S: Send + Sync> {
    unique: UniqueFile,
    source: S,
}

impl<S: Send + Sync, B: Send + Sync> ::std::cmp::PartialEq<ExactNS<B>> for ExactNS<S> {
    fn eq(&self, other: &ExactNS<B>) -> bool {
        true && match *self {
            ExactNS {
                unique: ref __self_0,
                source: _,
            } => match *other {
                ExactNS {
                    unique: ref __other_0,
                    source: _,
                } => true && &(*__self_0) == &(*__other_0),
            },
        }
    }
}

impl<S: Send + Sync> ::std::cmp::Eq for ExactNS<S> {}

/// We don't care about the means.
/// We want to uniquely identify a file so we don't get into a wrong NS.
/// IIRC ino and dev uniquely identifies a file
#[public]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
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

impl ExactNS<pid_t> {
    /// Uses Pid FD
    pub fn from(pid: pid_t) -> Result<Self> {
        let f = unsafe { pidfd::PidFd::open(pid, 0) }?;
        let fd = f.as_raw_fd();
        let st = nix::sys::stat::fstat(fd)?;
        Ok(ExactNS {
            unique: st.into(),
            source: pid,
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

impl UniqueFile {
    fn validate(&self, fst: stat) -> Result<(), ValidationErr> {
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
    ProcessGone,
}

impl Validate for ExactNS<pid_t> {
    fn validate(&self) -> Result<()> {
        match unsafe { pidfd::PidFd::open(self.source, 0) } {
            Ok(f) => {
                let fd = f.as_raw_fd();
                let st = nix::sys::stat::fstat(fd)?;
                self.unique.validate(st)?;
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

        Ok(())
    }
}

impl Validate for ExactNS<PathBuf> {
    fn validate(&self) -> Result<()> {
        match nix::sys::stat::stat(&self.source) {
            Ok(st) => {
                self.unique.validate(st)?;
            }
            Err(eno) => match eno {
                Errno::ENOENT => {
                    return Err(ValidationErr::FileNonExist.into());
                }
                _ => {
                    return Err(eno.into());
                }
            },
        }

        Ok(())
    }
}

#[test]
fn test_f() {
    let rx = nix::sys::stat::stat("./nonexist");
    let _ = dbg!(rx);
    let rx = unsafe { pidfd::PidFd::open(65532, 0) };
    let ox = rx.err().unwrap();
    let _ = dbg!(ox.raw_os_error());
}
