use std::{default, net::SocketAddr, path::PathBuf};

use crate::sys::NSEnter;

use super::*;
use derivative::Derivative;

use netlink_ops::errors::ProgrammingError;
use nix::sched::CloneFlags;
use nsproxy_common::Validate;
use nsproxy_derive::Validate;

use daggy::{petgraph::stable_graph::StableDiGraph, Dag};
use serde::{Deserialize, Serialize};
use tun::Layer;

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
    dev: u64,
}

#[public]
#[derive(Serialize, Deserialize, Debug)]
struct ObjectNode {
    main: ProcNS,
}

#[public]
#[derive(Serialize, Deserialize, Debug)]
struct RouteNode {
    object: NodeID,
}

/// This is part of object graph (which is not a DAG), for storing data.
#[public]
#[derive(Serialize, Deserialize, Debug)]
pub enum Relation {
    SendSocket(PassFD<SocketC>),
    SendTUN(PassFD<TUNC>),
}

#[public]
#[derive(Serialize, Deserialize, Debug)]
struct SocketC {
    addr: String,
}

#[public]
#[derive(Serialize, Deserialize, Debug)]
struct TUNC {
    layer: Layer,
    name: Option<String>,
}

#[public]
#[derive(Serialize, Deserialize, Debug)]
struct PassFD<C> {
    creation: C,
    listener: PathBuf,
    receiver: FDRecver,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum FDRecver {
    /// Config for TUN2Proxy is kept in a directory
    TUN2Proxy(PathBuf),
    /// Will be added to prober's dependency, if we use systemd. (prober is also a unit)
    Systemd(String),
    /// Just pass FD
    DontCare
}

/// In a directed graph, A ---Route--> B
/// This determines reachability, to prevent routing loops
#[derive(Serialize, Deserialize, Debug)]
pub enum Route {
    /// A TUN FD is created in A, opened and sent to B.
    DefaultRoute,
    /// A socket is created in A, and sent to B, which receives traffic from A at a port.
    ListenedBy,
}

pub type NodeID = u32;

/// Group of NSes; usually belongs to a process.
#[public]
#[derive(Derivative, Serialize, Deserialize, Validate, Debug)]
#[derivative(Default(bound = ""))]
#[va(impl<N: Validate> Validate for NSGroup<N>)]
struct NSGroup<N: Validate> {
    mnt: NSSlot<N, NSMnt>,
    uts: NSSlot<N, NSUts>,
    net: NSSlot<N, NSNet>,
    user: NSSlot<N, NSUser>,
    pid: NSSlot<N, NSPid>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub enum NSSlot<N, K: NSTrait> {
    #[default]
    Absent,
    Provided(N, K),
}

#[public]
impl<N: NSEnter, K: NSTrait> NSSlot<N, K> {
    fn enter(&self) -> Result<()> {
        match self {
            Self::Absent => Err(ProgrammingError)?,
            Self::Provided(ns, ty) => ns.enter(K::FLAG)?,
        }
        Ok(())
    }
    fn enter_if(&self) -> Result<()> {
        match self {
            Self::Absent => (),
            Self::Provided(ns, ty) => ns.enter(K::FLAG)?,
        }
        Ok(())
    }
}

defNS!(NSUser, CLONE_NEWUSER, "user");
defNS!(NSMnt, CLONE_NEWNS, "mnt");
defNS!(NSNet, CLONE_NEWNET, "net");
defNS!(NSUts, CLONE_NEWUTS, "uts");
defNS!(NSPid, CLONE_NEWPID, "pid");

pub macro defNS($name:ident, $flag:ident, $path:expr) {
    #[derive(Default, Debug, Serialize, Deserialize)]
    pub struct $name;
    impl NSTrait for $name {
        const FLAG: CloneFlags = CloneFlags::$flag;
        const NAME: &'static str = $path;
    }
}

impl<N: Validate, K: NSTrait> Validate for NSSlot<N, K> {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Absent => Ok(()),
            Self::Provided(k, _) => k.validate(),
        }
    }
}

pub trait NSTrait: Default {
    const FLAG: CloneFlags;
    const NAME: &'static str;
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ProcNS {
    /// Persistant NS.
    /// You may also use /proc/pid/ here
    ByPath(NSGroup<ExactNS<PathBuf>>),
    PidFd(ExactNS<pid_t>),
}

pub type RouteDAG = Dag<RouteNode, Route, NodeID>;
pub type ObjectGraph = StableDiGraph<Option<ObjectNode>, Relation, NodeID>;

#[derive(Serialize, Deserialize, Debug)]
#[public]
struct Graphs {
    route: RouteDAG,
    data: ObjectGraph,
}

// I have experimented. The inode number of root netns does not change across reboots.
