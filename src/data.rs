use std::{collections::HashMap, default, net::SocketAddr, path::PathBuf};

use crate::sys::NSEnter;

use super::*;
use derivative::Derivative;

use netlink_ops::errors::ProgrammingError;
use nix::sched::CloneFlags;
use nsproxy_common::Validate;
use nsproxy_derive::Validate;

use daggy::{petgraph::stable_graph::StableDiGraph, Dag, EdgeIndex, NodeIndex};
use serde::{de::Visitor, Deserialize, Serialize};
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
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
struct UniqueFile {
    ino: u64,
    dev: u64,
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

#[public]
#[derive(Serialize, Deserialize, Debug)]
struct ObjectNode {
    main: ProcNS,
}

#[public]
#[derive(Serialize, Deserialize, Debug)]
struct RouteNode {
    object: Ix,
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
    DontCare,
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

pub type Ix = u32;
pub type NodeI = NodeIndex<Ix>;
pub type EdgeI = EdgeIndex<Ix>;

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

pub type RouteDAG = Dag<RouteNode, Route, Ix>;
// Allows parallel edges
/// Data are used with [Option] because they are allocated and later filled.
pub type ObjectGraph = StableDiGraph<Option<ObjectNode>, Option<Relation>, Ix>;
/// Maps NETNS inode to object nodes
/// Contract: If and only if a key pair exists, the object exists in the graph
pub type ObjectIno = HashMap<u64, Vec<Ix>>;

#[derive(Serialize, Deserialize, Debug)]
#[public]
struct Graphs {
    route: RouteDAG,
    data: ObjectGraph,
    ino: ObjectIno,
}

#[public]
impl Graphs {
    // fn add_object(&mut self) -> &mut ObjectNode {
    //     let ix = self.data.add_node(None);

    // }
}

// I have experimented. The inode number of root netns does not change across reboots.
