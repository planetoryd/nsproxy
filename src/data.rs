use std::{
    borrow::Cow,
    collections::{hash_map, HashMap, HashSet},
    default,
    fmt::{Display, Write},
    net::SocketAddr,
    ops::AddAssign,
    os::fd::{AsRawFd, FromRawFd},
    path::PathBuf,
};

use crate::{paths::PathState, sys::NSEnter};

use super::*;
use anyhow::{anyhow, bail};
use bimap::BiMap;
use clap::ValueEnum;
use derivative::Derivative;

use linux_raw_sys::ioctl::NS_GET_USERNS;
use netlink_ops::errors::ProgrammingError;
use nix::sched::{setns, CloneFlags};
use nsproxy_derive::Validate;

use daggy::{petgraph::stable_graph::StableDiGraph, Dag, EdgeIndex, NodeIndex};
use owo_colors::OwoColorize;
use serde::{de::Visitor, Deserialize, Serialize};
use tracing::info;
use tun::Layer;

pub use nsproxy_common::*;

#[public]
#[derive(Serialize, Deserialize, Debug)]
struct ObjectNode {
    name: Option<String>,
    main: NSGroup<ExactNS>,
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
    // TODO: Veth. The proxy resides in a separate net ns (that may access the outside) in the user ns, apps connect to it with veths.
    // The proxy starts a TUN, and each app routes to the ns
}

impl Display for Relation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::SendSocket(p) => f.write_fmt(format_args!("{}", p)),
            Self::SendTUN(p) => f.write_fmt(format_args!("{}", p)),
        }
    }
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

/// Socket Creation.
#[public]
#[derive(Serialize, Deserialize, Debug)]
struct SocketC {
    /// TCP IP PORT etc.
    addr: String,
}

impl Display for SocketC {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{} at {}",
            "Socket Creation".green(),
            self.addr.underline()
        ))
    }
}

#[public]
#[derive(Serialize, Deserialize, Debug)]
struct TUNC {
    layer: Layer,
    name: Option<String>,
    mtu: Option<u32>,
}

impl Display for TUNC {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{:?}TUN {:?}",
            self.layer.bright_blue(),
            self.name.bold()
        ))
    }
}

#[public]
#[derive(Serialize, Deserialize, Debug)]
struct PassFD<C> {
    creation: C,
    listener: PathBuf,
    receiver: FDRecver,
}

impl<C: Display> Display for PassFD<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{}, passed to {}, at {:?}",
            self.creation,
            self.receiver,
            self.listener.underline()
        ))
    }
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

impl Display for FDRecver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self.bright_purple()))
    }
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
/// Invariant, paths based NSes are only visible in self.mnt
/// Mnt can be entered in after entering User.
#[public]
#[derive(Derivative, Serialize, Deserialize, Debug)]
#[derivative(Default(bound = ""))]
struct NSGroup<N> {
    mnt: NSSlot<N, NSMnt>,
    uts: NSSlot<N, NSUts>,
    net: NSSlot<N, NSNet>,
    user: NSSlot<N, NSUser>,
    pid: NSSlot<N, NSPid>,
}

#[public]
struct NSState<'n> {
    target: &'n NSGroup<ExactNS>,
    va: &'n mut VaCache,
}

impl<'n> NSState<'n> {
    pub fn validated_enter(&mut self) -> Result<()> {
        let cache = &mut self.va;
        let ctx = NSGroup::proc_path(PidPath::Selfproc, None)?;
        let mut val = NSGroup::<[Option<ValidateR>; 2]>::default();
        if ctx.pid.must()?.unique == self.target.pid.must()?.unique {
            if ctx.mnt.must()?.unique == self.target.mnt.must()?.unique {
                val.validate_all(cache, &ctx, self.target, 0)?;
                self.target.enter(&ctx)?;
            } else {
                val.validate_all(cache, &ctx, self.target, 0)?;
                self.target.enter(&ctx)?;
                let ctx = NSGroup::proc_path(PidPath::Selfproc, None)?;
                val.validate_all(cache, &ctx, self.target, 1)?;
            }
        } else {
            if ctx.mnt.must()?.unique == self.target.mnt.must()?.unique {
                val.validate_all(cache, &ctx, self.target, 0)?;
                self.target.enter(&ctx)?;
                let ctx = NSGroup::proc_path(PidPath::Selfproc, None)?;
                val.validate_all(cache, &ctx, self.target, 1)?;
            } else {
                val.validate_all(cache, &ctx, self.target, 0)?;
                self.target.enter(&ctx)?;
                let ctx = NSGroup::proc_path(PidPath::Selfproc, None)?;
                val.validate_all(cache, &ctx, self.target, 1)?;
            }
        }
        log::info!("{}", &val);
        Ok(())
    }
}

impl<const L: usize> NSGroup<[Option<ValidateR>; L]> {
    fn validate<S: NSTrait + PartialEq>(
        &mut self,
        cache: &mut VaCache,
        ctx: &NSGroup<ExactNS>,
        target: &NSGroup<ExactNS>,
        pos: usize,
    ) -> Result<()> {
        let ns = S::get(target);
        let m = S::get_mut(self);
        if *m == NSSlot::Absent {
            *m = NSSlot::Provided([None; L], Default::default());
        }
        if let NSSlot::Provided(ref mut vec, _) = m {
            assert!(vec[pos].is_none());
            vec[pos] = Some(match ns {
                NSSlot::Absent => ValidateR::Impossible,
                NSSlot::Provided(ns, _) => match &ns.source {
                    NSSource::Path(p) => {
                        if (S::NAME == "user")
                            || (target.mnt.map(|m| ctx.mnt.map(|c| m.unique == c.unique))
                                != (S::NAME == "mnt"))
                            || p.starts_with("/proc/")
                        {
                            ns.validate(cache, ctx)?
                        } else {
                            ValidateR::Impossible
                        }
                    }
                    NSSource::Pid(_) => {
                        if target.pid.map(|m| ctx.pid.map(|c| m.unique == c.unique)) {
                            ns.validate(cache, ctx)?
                        } else {
                            ValidateR::Impossible
                        }
                    }
                    NSSource::Unavail => ValidateR::Unspec,
                },
            });
        }
        Ok(())
    }
    fn validate_all(
        &mut self,
        cache: &mut VaCache,
        ctx: &NSGroup<ExactNS>,
        target: &NSGroup<ExactNS>,
        pos: usize,
    ) -> Result<()> {
        self.validate::<NSUser>(cache, ctx, target, pos)?;
        self.validate::<NSMnt>(cache, ctx, target, pos)?;
        self.validate::<NSNet>(cache, ctx, target, pos)?;
        self.validate::<NSPid>(cache, ctx, target, pos)?;
        self.validate::<NSUts>(cache, ctx, target, pos)?;
        Ok(())
    }
}

impl Display for NSGroup<ExactNS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        wns!(f, self, user, mnt, net, uts, pid);
        Ok(())
    }
}

impl<const NUM: usize> Display for NSGroup<[Option<ValidateR>; NUM]> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("Validation Result \n"))?;
        wns_val!(f, self, user, mnt, net, uts, pid);
        Ok(())
    }
}

macro wns($f:ident, $s:ident, $($fi:ident),*) {
    $( $f.write_fmt(format_args!("      {} \n", $s.$fi))?;)*
}

macro wns_val($f:ident, $s:ident, $($fi:ident),*) {
    $( $f.write_fmt(format_args!("      {:?} \n", $s.$fi))?;)*
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
    do_mount: bool,
) -> Result<NSGroup<ExactNS>> {
    let binds = paths.mount(id)?;
    let mut nsg: NSGroup<ExactNS> = NSGroup::default();
    mount_by_pid!(pid, &binds, nsg, do_mount, [net, uts, pid]);
    Ok(nsg)
}

#[public]
impl NSGroup<ExactNS> {
    fn enter(&self, ctx: &NSGroup<ExactNS>) -> Result<()> {
        match &self.user {
            NSSlot::Provided(ns, _) => {
                if matches!(ns.source, NSSource::Unavail) {
                    info!("Enter UserNS by ioctl-ing Net NS");

                    let usr = self.net.user_ns()?;
                    setns(&usr, CloneFlags::CLONE_NEWUSER)?;
                } else {
                    self.user.enter_if(ctx)?;
                }
            }
            _ => (),
        }

        ns_call!(self, [mnt, net, uts], enter_if, ctx);
        Ok(())
    }
    fn proc_path(pid: PidPath, alt: Option<NSSource>) -> Result<Self> {
        let mut g = Self::default();
        assign!(g, [user, mnt, net, pid, uts], proc_path, pid, alt.clone());
        Ok(g)
    }
    fn key(&self) -> UniqueFile {
        match &self.net {
            NSSlot::Provided(a, _) => a.unique,
            _ => unreachable!(),
        }
    }
}

pub macro ns_call( $group:ident, [$($name:ident),*],  $func:ident, $arg:expr) {
    $(
        $group.$name.$func($arg)?;
    )*
}

pub macro assign( $group:ident, [$($name:ident),*],  $func:ident, $arg:expr, $arg1:expr) {
    $(
        $group.$name = NSSlot::$func($arg, $arg1)?;
    )*
}

impl AddAssign<&NSGroup<ExactNS>> for NSGroup<ExactNS> {
    /// Assigns with the user&mnt of rhs
    fn add_assign(&mut self, rhs: &Self) {
        if !rhs.user.absent() {
            self.user = rhs.user.clone();
        }
        if !rhs.mnt.absent() {
            self.mnt = rhs.mnt.clone();
        }
    }
}

pub macro validate($var:expr, $ca:expr, $ctx:expr, [$($fi:ident),*]) {
    $(
        $var.$fi.validate($ca, $ctx)?;
    )*
}

#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum NSSlot<N, K: NSTrait> {
    #[default]
    Absent,
    Provided(N, K),
}

impl<'k, N: NSFrom<(PidPath, &'k str)>, K: NSTrait> NSFrom<PidPath> for NSSlot<N, K> {
    fn from_source(source: PidPath) -> Result<Self> {
        Ok(Self::Provided(
            N::from_source((source, K::NAME))?,
            K::default(),
        ))
    }
}

impl<'k, N: NSFrom<pid_t>, K: NSTrait> NSFrom<pid_t> for NSSlot<N, K> {
    fn from_source(source: pid_t) -> Result<Self> {
        Ok(Self::Provided(N::from_source(source)?, K::default()))
    }
}

impl<N: Display, K: NSTrait> Display for NSSlot<N, K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("NS {} ", K::NAME))?;
        match self {
            Self::Absent => f.write_fmt(format_args!("Absent")),
            Self::Provided(n, _) => f.write_fmt(format_args!("{}", n)),
        }
    }
}

pub trait Validate {
    fn validate(&self, cache: &mut VaCache, ctx: &NSGroup<ExactNS>) -> Result<ValidateR>;
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum ValidateR {
    /// Impossible due to outer circumstances
    Impossible,
    Pass,
    /// Impossible because the NS is not provided
    Unspec,
}

impl Validate for ExactNS {
    /// Checking if the ino and dev of the specified file matches the recorded stat
    fn validate(&self, cache: &mut VaCache, ctx: &NSGroup<ExactNS>) -> Result<ValidateR> {
        match &self.source {
            NSSource::Path(p) => {
                let st = cached_stat(cache, (p, &ctx.mnt.must()?.unique))?;
                self.unique.validate(st)?;
            }
            NSSource::Pid(p) => {
                let st = cached_fstat(cache, (*p, &ctx.pid.must()?.unique))?;
                self.unique.validate(st)?;
            }
            NSSource::Unavail => return Ok(ValidateR::Unspec),
        }
        Ok(ValidateR::Pass)
    }
}

#[public]
impl<K: NSTrait + PartialEq> NSSlot<ExactNS, K> {
    fn enter(&self) -> Result<()> {
        match self {
            Self::Absent => Err(ProgrammingError)?,
            Self::Provided(ns, ty) => ns.enter(K::FLAG)?,
        }
        Ok(())
    }
    /// Enter the NS if provided
    fn enter_if(&self, ctx: &NSGroup<ExactNS>) -> Result<()> {
        match self {
            Self::Absent => Ok(()),
            Self::Provided(ns, _) => {
                if K::get(ctx).must()?.unique == ns.unique {
                    Ok(())
                } else {
                    if ns.source == NSSource::Unavail {
                        Ok(())
                    } else {
                        log::info!("Enter {:?}, {}", K::NAME, ns);
                        ns.enter(K::FLAG)
                    }
                }
            }
        }
    }
    fn must(&self) -> Result<&ExactNS> {
        match &self {
            Self::Absent => bail!(Unviable),
            Self::Provided(ns, ty) => Ok(ns),
        }
    }
    fn map<R: Default>(&self, f: impl FnOnce(&ExactNS) -> R) -> R {
        match &self {
            Self::Absent => R::default(),
            Self::Provided(ns, ty) => f(ns),
        }
    }
    fn proc_path(mut pid: PidPath, altsource: Option<NSSource>) -> Result<Self> {
        let path: PathBuf = ["/proc", pid.to_str().as_ref(), "ns", K::NAME]
            .iter()
            .collect();
        let stat = nix::sys::stat::stat(&path)?;
        Ok(NSSlot::Provided(
            ExactNS {
                source: altsource.unwrap_or(NSSource::Path(path)),
                unique: stat.into(),
            },
            Default::default(),
        ))
    }
    fn user_ns(&self) -> Result<std::fs::File> {
        match &self {
            Self::Absent => bail!(Unviable),
            Self::Provided(ns, ty) => match &ns.source {
                NSSource::Path(p) => {
                    let f = std::fs::File::open(p)?;
                    let fu = unsafe {
                        std::fs::File::from_raw_fd(libc::ioctl(f.as_raw_fd(), NS_GET_USERNS.into()))
                    };
                    Ok(fu)
                }
                _ => bail!(Unviable),
            },
        }
    }
    fn user_ns_slot(&self) -> Result<NSSlot<ExactNS, NSUser>> {
        let fu = self.user_ns()?;
        let stat = nix::sys::stat::fstat(fu.as_raw_fd())?;
        Ok(NSSlot::Provided(
            ExactNS {
                source: NSSource::Unavail,
                unique: stat.into(),
            },
            Default::default(),
        ))
    }
}

/// This represents a kind of error that is due to conditions not met, rather than trying and failing.
#[derive(Error, Debug)]
#[error("{:?}", self)]
struct Unviable;

defNS!(NSUser, CLONE_NEWUSER, "user", user);
defNS!(NSMnt, CLONE_NEWNS, "mnt", mnt);
defNS!(NSNet, CLONE_NEWNET, "net", net);
defNS!(NSUts, CLONE_NEWUTS, "uts", uts);
defNS!(NSPid, CLONE_NEWPID, "pid", pid);

pub fn nstypes() -> HashMap<&'static str, fn(&mut NSGroup<ExactNS>, ExactNS)> {
    let mut map = HashMap::new();
    map.insert(
        <NSUser as NSTrait>::NAME,
        NSUser::set as for<'a> fn(&'a mut data::NSGroup<ExactNS>, _),
    );
    map.insert(
        <NSMnt as NSTrait>::NAME,
        NSMnt::set as for<'a> fn(&'a mut data::NSGroup<ExactNS>, _),
    );
    map.insert(
        <NSNet as NSTrait>::NAME,
        NSNet::set as for<'a> fn(&'a mut data::NSGroup<ExactNS>, _),
    );
    map.insert(
        <NSUts as NSTrait>::NAME,
        NSUts::set as for<'a> fn(&'a mut data::NSGroup<ExactNS>, _),
    );
    map
}

pub macro defNS($name:ident, $flag:ident, $path:expr, $k:ident) {
    #[derive(Default, Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
    pub struct $name;
    impl NSTrait for $name {
        const FLAG: CloneFlags = CloneFlags::$flag;
        const NAME: &'static str = $path;
        fn set<N>(g: &mut NSGroup<N>, v: N) {
            g.$k = NSSlot::Provided(v, Self);
        }
        fn get<N>(g: &NSGroup<N>) -> &NSSlot<N, $name> {
            &g.$k
        }
        fn get_mut<N>(g: &mut NSGroup<N>) -> &mut NSSlot<N, $name> {
            &mut g.$k
        }
    }
}

impl<N: Validate, K: NSTrait> Validate for NSSlot<N, K> {
    fn validate(&self, cache: &mut VaCache, ctx: &NSGroup<ExactNS>) -> Result<ValidateR> {
        match self {
            Self::Absent => Ok(ValidateR::Unspec),
            Self::Provided(k, _) => k.validate(cache, ctx),
        }
    }
}

pub trait NSTrait: Default {
    const FLAG: CloneFlags;
    const NAME: &'static str;
    fn set<N>(g: &mut NSGroup<N>, v: N);
    fn get<N>(g: &NSGroup<N>) -> &NSSlot<N, Self>;
    fn get_mut<N>(g: &mut NSGroup<N>) -> &mut NSSlot<N, Self>;
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
    name: BiMap<String, NodeI>,
    #[serde(skip)]
    file: Option<std::fs::File>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
/// Ways to address a node
pub enum NodeAddr {
    Name(String),
    Ix(NodeI),
    /// Specifically Netns. All otber NSes are auxiliary
    UF(UniqueFile),
}

#[derive(Clone, Copy)]
pub enum NSAdd {
    RecordMountedPaths,
    RecordProcfsPaths,
    RecordNothing,
    Flatpak,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NSAddRes {
    NewNS,
    Found,
}

#[public]
impl Graphs {
    /// Attempt to add a new node
    /// Fork: do we enter the userns when mounting (by forking out)
    fn add_ns(
        &mut self,
        pid: PidPath,
        paths: &PathState,
        usermnt: Option<&NSGroup<ExactNS>>,
        method: NSAdd,
        name: Option<String>,
    ) -> Result<(NSAddRes, NodeI)> {
        let ns = NSGroup::key_ident(pid)?;
        let uf = ns.unique;
        match self.map.entry(uf) {
            hash_map::Entry::Occupied(en) => {
                let ns = *en.get();
                log::info!("NS object {pid:?} {:?} exists", ns);
                Ok((NSAddRes::Found, ns))
            }
            hash_map::Entry::Vacant(va) => {
                let ix: NodeI = self.data.add_node(None);
                log::info!("New NS object {pid:?}, {:?}", ix);
                let mut node = match method {
                    NSAdd::RecordMountedPaths => {
                        // Always try unmount
                        NSGroup::umount(ix, paths)?;
                        mount_ns_by_pid(pid, paths, ix, true)?
                    }
                    NSAdd::RecordProcfsPaths => NSGroup::proc_path(pid.to_n(), None)?,
                    NSAdd::RecordNothing => NSGroup::proc_path(pid, Some(NSSource::Unavail))?,
                    NSAdd::Flatpak => {
                        let mut g = NSGroup::default();
                        // Prevents entering by setting to unavail
                        assign!(g, [pid, mnt], proc_path, pid, Some(NSSource::Unavail));
                        assign!(g, [net, uts], proc_path, pid, None);
                        g.user = g.net.user_ns_slot()?;
                        g
                    }
                };
                if let Some(p) = usermnt {
                    node += p;
                }
                if let Some(ref na) = name {
                    self.name.insert(na.clone(), ix);
                }
                self.data[ix].replace(ObjectNode { name, main: node });
                Ok((NSAddRes::NewNS, *va.insert(ix)))
            }
        }
    }
    fn resolve(&self, addr: &NodeAddr) -> Result<NodeI> {
        match addr {
            NodeAddr::Ix(ix) => Ok(*ix),
            NodeAddr::Name(name) => self
                .name
                .get_by_left(name)
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
