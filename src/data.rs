use std::{
    borrow::Cow,
    collections::{hash_map, HashMap, HashSet},
    default,
    net::SocketAddr,
    path::PathBuf,
};

use crate::{paths::PathState, sys::NSEnter};

use super::*;
use amplify::confinement::Collection;
use derivative::Derivative;

use netlink_ops::errors::ProgrammingError;
use nix::sched::CloneFlags;
use nsproxy_common::Validate;
use nsproxy_derive::Validate;

use daggy::{petgraph::stable_graph::StableDiGraph, Dag, EdgeIndex, NodeIndex};
use serde::{de::Visitor, Deserialize, Serialize};
use tun::Layer;

pub use nsproxy_common::*;

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

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
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
    /// Enter the NS if provided
    fn enter_if(&self) -> Result<()> {
        match self {
            Self::Absent => (),
            Self::Provided(ns, ty) => ns.enter(K::FLAG)?,
        }
        Ok(())
    }
}

defNS!(NSUser, CLONE_NEWUSER, "user", user);
defNS!(NSMnt, CLONE_NEWNS, "mnt", mnt);
defNS!(NSNet, CLONE_NEWNET, "net", net);
defNS!(NSUts, CLONE_NEWUTS, "uts", uts);
defNS!(NSPid, CLONE_NEWPID, "pid", pid);

pub fn nstypes<N: Validate>() -> HashMap<&'static str, fn(&mut NSGroup<N>, N)> {
    let mut map = HashMap::new();
    map.insert(
        NSUser::NAME,
        NSUser::set::<N> as for<'a> fn(&'a mut data::NSGroup<_>, _),
    );
    map.insert(
        NSMnt::NAME,
        NSMnt::set::<N> as for<'a> fn(&'a mut data::NSGroup<_>, _),
    );
    map.insert(
        NSNet::NAME,
        NSNet::set::<N> as for<'a> fn(&'a mut data::NSGroup<_>, _),
    );
    map.insert(
        NSUts::NAME,
        NSUts::set::<N> as for<'a> fn(&'a mut data::NSGroup<_>, _),
    );
    map
}

pub macro defNS($name:ident, $flag:ident, $path:expr, $k:ident) {
    #[derive(Default, Debug, Serialize, Deserialize, Clone, Copy)]
    pub struct $name;
    impl NSTrait for $name {
        const FLAG: CloneFlags = CloneFlags::$flag;
        const NAME: &'static str = $path;
        fn set<N: Validate>(g: &mut NSGroup<N>, v: N) {
            g.$k = NSSlot::Provided(v, Self);
        }
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
    fn set<N: Validate>(g: &mut NSGroup<N>, v: N);
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
/// Maps NETNS to object nodes
/// Contract: If and only if a key pair exists, the object exists in the graph
/// For simplicity, for one netns, only one object may exist, and other NSes are attached to it.
pub type ObjectNS = HashMap<UniqueFile, NodeI>;

#[derive(Serialize, Deserialize, Debug, Default)]
#[public]
struct Graphs {
    route: RouteDAG,
    data: ObjectGraph,
    /// Maps objects to NetNS files
    map: ObjectNS,
    
}

#[public]
impl Graphs {
    /// Attempt to add a new node
    /// Fork: do we enter the userns when mounting (by forking out)
    fn add_object(
        &mut self,
        pid: PidPath,
        paths: &PathState,
        usermnt: Option<&ProcNS>,
    ) -> Result<NodeI> {
        log::info!("Add object {pid:?}");
        let ns = ProcNS::key_ident(pid)?;
        let uf = ns.unique;
        match self.map.entry(uf) {
            hash_map::Entry::Occupied(en) => Ok(*en.get()),
            hash_map::Entry::Vacant(va) => {
                let ix: NodeI = self.data.add_node(None);
                // Always try unmount
                ProcNS::umount(ix, paths)?;
                let mut node = ProcNS::mount(pid, paths, ix)?;
                if let Some(p) = usermnt {
                    node.merge(p);
                }
                self.data[ix].replace(ObjectNode { main: node });
                Ok(*va.insert(ix))
            }
        }
    }
}

// I have experimented. The inode number of root netns does not change across reboots.
