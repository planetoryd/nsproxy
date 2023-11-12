use std::path::PathBuf;

use crate::tun2proxy::PNodeConf;

use super::*;
use derivative::Derivative;

use nsproxy_common::Validate;
use nsproxy_derive::Validate;

use serde::{Deserialize, Serialize};

#[public]
#[derive(Serialize, Deserialize, Debug)]
struct ExactNS<S> {
    unique: UniqueFile,
    source: S,
}

/// We don't care about the means. 
/// We want to uniquely identify a file so we don't get into a wrong NS.
/// IIRC ino and dev uniquely identifies a file
#[public]
#[derive(Serialize, Deserialize, Debug)]
struct UniqueFile {
    ino: u64,
    dev: u64
}

/// Proxy, as a node in the chain. 
/// Proxy Node.
#[public]
#[derive(Serialize, Deserialize)]
struct PNode {
    /// Proxied NS, or a direct NS like the default namspace
    main: ProcNS,
    out: Option<NodeID>
}

pub type NodeID = u32;

/// Group of NSes; usually belongs to a process.
#[public]
#[derive(Derivative, Serialize, Deserialize, Validate, Debug)]
#[derivative(Default(bound = ""))]
#[va(impl<N: Validate> Validate for NSGroup<N>)]
struct NSGroup<N: Validate> {
    mnt: Option<N>,
    uts: Option<N>,
    net: Option<N>,
    user: Option<N>,
    pid: Option<N>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ProcNS {
    /// Persistant NS. 
    /// You may also use /proc/pid/ here
    ByPath(NSGroup<ExactNS<PathBuf>>),
    PidFd(ExactNS<pid_t>)
}

// I have experimented. The inode number of root netns does not change across reboots.