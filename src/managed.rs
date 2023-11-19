//! Executor of ObjectGraph
//! Allow for other means of process/task scheduling, managing.

use std::path::{Path, PathBuf};

use daggy::{
    petgraph::{
        visit::{IntoEdgesDirected, IntoNodeReferences},
        Direction,
    },
    NodeIndex,
};
use tun::Layer;

use super::*;
use crate::{
    data::{FDRecver, Graphs, NodeID, ObjectNode, Relation},
    paths::PathState,
};

// The whole thing should be modeled as as series of CRUD actions building up to the graph
// Therefore we can change the graph by initiating actions at runtime.
// Higer level actions: create nodes, relations
// Lower level actions: create, start, remove systemd services

pub trait ServiceManaged: Sized {
    fn probe(&self, place: &ObjectNode, relations: Vec<&Relation>) -> Result<()>;
    /// Any daemon must be enabled/placed before any probe associated with it.
    fn daemon(&self, place: &ObjectNode, recv: &FDRecver) -> Result<()>;
    fn socks2tun(&self, layer: Layer, id: Socks2TUN) -> Result<Relation>;
    fn rm_socks2tun(&self, id: Socks2TUN) -> Result<Relation>;
    fn new() -> Result<Self>;
}

#[public]
struct Socks2TUN {
    confpath: PathBuf,
    src: NodeIndex<NodeID>,
}

#[public]
impl Graphs {
    /// Execute a graph (plan), make them into probe/daemon calls
    /// Traverse the graph and visit each part
    fn handle(&self, exec: &impl ServiceManaged) -> Result<()> {
        let data = &self.data;
        // start/enable all the listeners first
        for ei in data.edge_indices() {
            let rel = &data[ei];
            let (x, y) = data.edge_endpoints(ei).unwrap();
            let recv = match rel {
                Relation::SendSocket(sock) => &sock.receiver,
                Relation::SendTUN(tun) => &tun.receiver,
            };
            exec.daemon(data[y].as_ref().unwrap(), recv)?;
        }
        for (ni, on) in data.node_references() {
            let ed = data
                // A --push FD--> B
                .edges_directed(ni, Direction::Outgoing)
                .collect::<Vec<_>>();
            if ed.len() > 0 {
                let ew = ed.iter().map(|e| e.weight()).collect::<Vec<_>>();
                exec.probe(on.as_ref().unwrap(), ew)?;
            }
        }
        Ok(())
    }
}
