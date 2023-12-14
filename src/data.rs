use std::{
    borrow::Cow,
    collections::{hash_map, HashMap, HashSet},
    default,
    net::SocketAddr,
    ops::AddAssign,
    path::PathBuf,
};

use crate::{paths::PathState, sys::NSEnter};

use super::*;
use amplify::confinement::Collection;
use anyhow::anyhow;
use clap::ValueEnum;
use derivative::Derivative;

use netlink_ops::errors::ProgrammingError;
use nix::sched::CloneFlags;
use nsproxy_derive::Validate;

use daggy::{petgraph::stable_graph::StableDiGraph, Dag, EdgeIndex, NodeIndex};
use serde::{de::Visitor, Deserialize, Serialize};
use tun::Layer;

pub use nsproxy_common::*;

#[public]
#[derive(Serialize, Deserialize, Debug)]
struct ObjectNode {
    main: NSGroup,
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
impl Relation {
    fn fd_recver(&self) -> &FDRecver {
        match self {
            Relation::SendSocket(p) => &p.receiver,
            Relation::SendTUN(p) => &p.receiver,
        }
    }
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
#[derive(Derivative, Serialize, Deserialize, Debug)]
#[derivative(Default(bound = ""))]
struct NSGroup {
    mnt: NSSlot<ExactNS, NSMnt>,
    uts: NSSlot<ExactNS, NSUts>,
    net: NSSlot<ExactNS, NSNet>,
    user: NSSlot<ExactNS, NSUser>,
    pid: NSSlot<ExactNS, NSPid>,
}

impl NCtx for NSGroup {
    fn mnt(&self) -> &UniqueFile {
        match &self.mnt {
            NSSlot::Provided(p, _) => &p.unique,
            _ => unreachable!()
        }
    }
    fn pid(&self) -> &UniqueFile {
        match &self.pid {
            NSSlot::Provided(p, _) => &p.unique,
            _ => unreachable!()
        }
    }
}

pub macro mount_by_pid( $pid:expr,$binds:expr,$group:ident,$v:expr,[$($name:ident),*] ) {
    $(
        $group.$name = NSSlot::mount($pid, $binds, $v)?;
    )*
}

pub fn mount_ns_by_pid(
    pid: PidPath,
    paths: &PathState,
    id: NodeI,
    really: bool,
) -> Result<NSGroup> {
    let binds = paths.mount(id)?;
    let mut nsg: NSGroup = NSGroup::default();
    mount_by_pid!(pid, &binds, nsg, really, [net, uts, pid]);
    Ok(nsg)
}

#[public]
impl NSGroup {
    /// Pin down namespaces of a process.
    /// If [really] is false, the bind mount is not performed, but the paths are returned
    fn enter(&self) -> Result<()> {
        ns_call!(self, [user, mnt, net, uts], enter_if);
        Ok(())
    }
    fn proc_path(pid: PidPath) -> Result<Self> {
        let mut g = Self::default();
        assign!(g, [user, mnt, net], proc_path, pid);
        Ok(g)
    }
    fn key(&self) -> UniqueFile {
        match &self.net {
            NSSlot::Provided(a, _) => a.unique,
            _ => unreachable!(),
        }
    }
}

pub macro ns_call( $group:ident, [$($name:ident),*],  $func:ident) {
    $(
        $group.$name.$func()?;
    )*
}

pub macro assign( $group:ident, [$($name:ident),*],  $func:ident, $arg:expr) {
    $(
        $group.$name = NSSlot::$func($arg)?;
    )*
}

impl AddAssign<&NSGroup> for NSGroup {
    /// Assigns with the user&mnt of rhs
    fn add_assign(&mut self, rhs: &Self) {
        self.user = rhs.user.clone();
        self.mnt = rhs.mnt.clone();
    }
}

impl<C: NCtx> ValidateScoped<C> for NSGroup {
    /// Validation outside userns
    fn validate_out(&self, cache: &mut VaCache, ctx: &C) -> Result<()> {
        self.mnt.validate(cache, ctx)
    }
    fn validate_in(&self, cache: &mut VaCache, ctx: &C) -> Result<()> {
        validate!(self, cache, ctx, [user, net, pid, uts]);
        Ok(())
    }
}

pub macro validate($var:ident, $ca:expr, $ctx:expr, [$($fi:ident),*]) {
    $(
        $var.$fi.validate($ca, $ctx)?;
    )*
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub enum NSSlot<N, K: NSTrait> {
    #[default]
    Absent,
    Provided(N, K),
}

#[public]
impl<K: NSTrait> NSSlot<ExactNS, K> {
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
    fn proc_path(mut pid: PidPath) -> Result<Self> {
        pid = pid.to_n();
        let path: PathBuf = ["/proc", pid.to_str().as_ref(), "ns", K::NAME]
            .iter()
            .collect();
        let stat = nix::sys::stat::stat(&path)?;
        Ok(NSSlot::Provided(
            ExactNS {
                source: NSSource::Path(path),
                unique: stat.into(),
            },
            Default::default(),
        ))
    }
}

defNS!(NSUser, CLONE_NEWUSER, "user", user);
defNS!(NSMnt, CLONE_NEWNS, "mnt", mnt);
defNS!(NSNet, CLONE_NEWNET, "net", net);
defNS!(NSUts, CLONE_NEWUTS, "uts", uts);
defNS!(NSPid, CLONE_NEWPID, "pid", pid);

pub fn nstypes() -> HashMap<&'static str, fn(&mut NSGroup, ExactNS)> {
    let mut map = HashMap::new();
    map.insert(
        NSUser::NAME,
        NSUser::set as for<'a> fn(&'a mut data::NSGroup, _),
    );
    map.insert(
        NSMnt::NAME,
        NSMnt::set as for<'a> fn(&'a mut data::NSGroup, _),
    );
    map.insert(
        NSNet::NAME,
        NSNet::set as for<'a> fn(&'a mut data::NSGroup, _),
    );
    map.insert(
        NSUts::NAME,
        NSUts::set as for<'a> fn(&'a mut data::NSGroup, _),
    );
    map
}

pub macro defNS($name:ident, $flag:ident, $path:expr, $k:ident) {
    #[derive(Default, Debug, Serialize, Deserialize, Clone, Copy)]
    pub struct $name;
    impl NSTrait for $name {
        const FLAG: CloneFlags = CloneFlags::$flag;
        const NAME: &'static str = $path;
        fn set(g: &mut NSGroup, v: ExactNS) {
            g.$k = NSSlot::Provided(v, Self);
        }
    }
}

impl<C: NCtx, N: Validate<C>, K: NSTrait> Validate<C> for NSSlot<N, K> {
    fn validate(&self, cache: &mut VaCache, ctx: &C) -> Result<()> {
        match self {
            Self::Absent => (),
            Self::Provided(k, _) => k.validate(cache, ctx)?,
        }
        Ok(())
    }
}

pub trait NSTrait: Default {
    const FLAG: CloneFlags;
    const NAME: &'static str;
    fn set(g: &mut NSGroup, v: ExactNS);
}

pub type RouteDAG = Dag<RouteNode, Route, Ix>;
// Allows parallel edges
/// Data are used with [Option] because they are allocated and later filled.
pub type NSGraph = StableDiGraph<Option<ObjectNode>, Option<Relation>, Ix>;

#[derive(Serialize, Deserialize, Debug, Default)]
#[public]
struct Graphs {
    route: RouteDAG,
    data: NSGraph,
    /// Maps NETNS to object nodes
    /// Contract: If and only if a key pair exists, the object exists in the graph
    /// For simplicity, for one netns, only one object may exist, and other NSes are attached to it.
    map: HashMap<UniqueFile, NodeI>,
    name: HashMap<String, NodeI>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
/// Ways to address a node
pub enum NodeAddr {
    Name(String),
    Ix(NodeI),
    /// Specifically Netns. All otber NSes are auxiliary
    UF(UniqueFile),
}

#[public]
impl Graphs {
    /// Attempt to add a new node
    /// Fork: do we enter the userns when mounting (by forking out)
    fn add_ns(
        &mut self,
        pid: PidPath,
        paths: &PathState,
        usermnt: Option<&NSGroup>,
        really: bool,
    ) -> Result<NodeI> {
        let ns = NSGroup::key_ident(pid)?;
        let uf = ns.unique;
        match self.map.entry(uf) {
            hash_map::Entry::Occupied(en) => {
                log::info!("NS object {pid:?} exists");
                Ok(*en.get())
            }
            hash_map::Entry::Vacant(va) => {
                log::info!("New NS object {pid:?}");
                let ix: NodeI = self.data.add_node(None);
                // Always try unmount
                NSGroup::umount(ix, paths)?;
                let mut node = mount_ns_by_pid(pid, paths, ix, really)?;
                if let Some(p) = usermnt {
                    node += p;
                }
                self.data[ix].replace(ObjectNode { main: node });
                Ok(*va.insert(ix))
            }
        }
    }
    fn resolve(&self, addr: &NodeAddr) -> Result<NodeI> {
        match addr {
            NodeAddr::Ix(ix) => Ok(*ix),
            NodeAddr::Name(name) => self
                .name
                .get(name)
                .ok_or(anyhow!("specified name does not exist"))
                .map(|k| *k),
            NodeAddr::UF(uf) => self
                .map
                .get(uf)
                .ok_or(anyhow!("specified UniqueFile has no associated node"))
                .map(|k| *k),
        }
    }
}

// I have experimented. The inode number of root netns does not change across reboots.
