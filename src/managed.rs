//! Executor of ObjectGraph
//! Allow for other means of process/task scheduling, managing.

use std::path::{Path, PathBuf};

use daggy::{
    petgraph::{
        visit::{EdgeRef, IntoEdgesDirected, IntoNodeReferences},
        Direction,
    },
    EdgeIndex, NodeIndex,
};
use tun::Layer;

use super::*;
use crate::{
    data::{EdgeI, FDRecver, Graphs, Ix, NodeI, ObjectNode, Relation},
    paths::PathState,
    systemd::UnitName,
};

// The whole thing should be modeled as as series of CRUD actions building up to the graph
// Therefore we can change the graph by initiating actions at runtime.
// Higer level actions: create nodes, relations
// Lower level actions: create, start, remove systemd services

pub trait ServiceM: Sized {
    type Ctx<'p>;
    async fn new() -> Result<Self>;
    /// Run this before any starts
    async fn reload(&self, ctx: Self::Ctx<'_>) -> Result<()>;
    async fn ctx<'p>(&'p self) -> Result<Self::Ctx<'p>>;
}

pub type SrcNode<'k> = Indexed<NodeI, &'k ObjectNode>;
pub type SrcDeps<'k> = Vec<Indexed<EdgeI, &'k Relation>>;
pub type NodeWDeps<'n, 'd> = (SrcNode<'n>, SrcDeps<'d>);
pub type IRelation<'k> = Indexed<EdgeI, &'k Relation>;

/// Modeled after systemd
pub trait MItem {
    type Param;
    type Serv: ServiceM;
}

/// Meaning as in systemd
pub trait ItemPersist: MItem {
    async fn enable(
        &self,
        serv: &Self::Serv,
        ctx: &<Self::Serv as ServiceM>::Ctx<'_>,
    ) -> Result<()>;
    async fn disable(
        &self,
        serv: &Self::Serv,
        ctx: &<Self::Serv as ServiceM>::Ctx<'_>,
    ) -> Result<()>;
}

/// Meaning as in systemd
pub trait ItemAction: MItem {
    async fn stop(&self, serv: &Self::Serv, ctx: &<Self::Serv as ServiceM>::Ctx<'_>) -> Result<()>;
    async fn start(&self, serv: &Self::Serv, ctx: &<Self::Serv as ServiceM>::Ctx<'_>)
        -> Result<()>;
}

pub trait ItemCreate: MItem {
    type Created;
    /// Should not start or enable anything (as in systemd)
    async fn write(&self, param: Self::Param, serv: &Self::Serv) -> Result<Self::Created>;
}

pub trait ItemRM: MItem {
    async fn remove(&self, serv: &Self::Serv) -> Result<()>;
}

#[public]
struct Indexed<I, N> {
    id: I,
    item: N,
}

// The path computer pattern. The struct should borrow the data and methods can be called to get relevant paths.
// It should not persist any state, but serve as a computer, a bundle of methods.
#[public]
struct Socks2TUN<'b> {
    /// File name is taken as the systemd unit name.
    confpath: &'b Path,
    /// It's possible to have multiple paths between one NS to another
    ix: EdgeIndex<Ix>,
}

#[public]
impl<'b> Socks2TUN<'b> {
    fn new(confpath: &'b PathBuf, ix: EdgeIndex<Ix>) -> Result<Self> {
        Ok(Self { confpath, ix })
    }
}

impl<'b> UnitName for Socks2TUN<'b> {
    fn stem(&self) -> Result<String> {
        Ok(self
            .confpath
            .file_stem()
            .unwrap_or_default()
            .to_str()
            .ok_or(NonUTF8Error)?
            .to_owned()
            + &self.ix.index().to_string())
    }
}

#[public]
impl Graphs {
    /// Writes to the OS
    async fn write_probes<'g: 'n + 'd, 'n, 'd, S: ServiceM>(&'g self, serv: &'g S) -> Result<()>
    where
        NodeWDeps<'n, 'd>: ItemCreate<Param = (), Serv = S>,
    {
        let data = &self.data;
        for (id, _on) in data.node_references() {
            // Each node is the an NS where probe enters
            let wdeps: NodeWDeps = self.nodewdeps(id);
            // Write the probe unit with Requires
            wdeps.write((), serv).await?;
            // Override all the configs each time we execute a graph
            // This only concerns the probe services. The dependencies, daemons, and other user specified units are added as dependency.
        }
        Ok(())
    }
    fn nodewdeps(&self, id: NodeI) -> NodeWDeps {
        let ed = self
            .data
            // A --push FD--> B
            .edges_directed(id, Direction::Outgoing)
            .collect::<Vec<_>>();
        let ew = ed
            .iter()
            .map(|e| Indexed {
                id: e.id(),
                item: e.weight().as_ref().unwrap(),
            })
            .collect::<Vec<_>>();
        let srcnode = Indexed {
            id,
            item: self.data[id].as_ref().unwrap(),
        };
        // Each node is the an NS where probe enters
        (srcnode, ew)
    }
}
