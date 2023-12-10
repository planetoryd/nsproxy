//! Graph of all proxy nodes, decoupled from systemd or such.
//! We keep proxy graph information here, the topology.
//! Prevent proxy loops, and have a registry of NSes,
//! Processes are managed by systemd.

use std::{io::Read, path::PathBuf};

use super::*;
use crate::{
    data::{
        ExactNS, Graphs, Ix, NodeI, ObjectGraph, ObjectNS, ObjectNode, ProcNS, Relation, Route,
        RouteNode,
    },
    paths::{PathState, Paths},
};

use daggy::{
    self,
    petgraph::visit::{self, Reversed, Topo},
    stable_dag::StableDag,
    Dag,
};
use nsproxy_common::Validate;
use nsproxy_common::ValidationErr;
use petgraph::visit::IntoNodeReferences;
use serde_json::{from_str, to_string_pretty};

impl Graphs {
    pub fn prune(&mut self) -> Result<()> {
        let mut remove = Vec::new();
        for (ni, node) in self.data.node_references() {
            if let Some(k) = node {
                let rx = k.validate();
                if let Err(er) = rx {
                    let expected = er.downcast::<ValidationErr>()?;
                    log::info!("Removing NS node {}", k.main.key());
                    self.map.remove(&k.main.key());
                }
            } else {
                remove.push(ni);
            }
        }
        for ni in remove {
            self.data.remove_node(ni);
        }
        Ok(())
    }
    pub fn load(st: &str) -> Result<Self> {
        let g: Self = from_str(st)?;
        Ok(g)
    }
    pub fn load_file(path: &PathState) -> Result<Self> {
        let gp = Self::path(path);
        if gp.exists() {
            let mut file = std::fs::File::open(&gp)?;
            let mut st = Default::default();
            file.read_to_string(&mut st)?;
            Self::load(&st)
        } else {
            Ok(Graphs::default())
        }
    }
    pub fn dump_file(&self, path: &PathState) -> Result<()> {
        let pa = Self::path(path);
        log::info!("Dump graphs to {:?}", &pa);
        let file = std::fs::File::create(&pa)?;
        serde_json::to_writer_pretty(&file, self)?;
        Ok(())
    }
    pub fn path(path: &PathState) -> PathBuf {
        path.state.join("graphs.json")
    }
}

#[public]
impl ObjectNode {
    fn validate(&self) -> Result<()> {
        self.main.validate()?;
        // It should return Err in that case. A bool lacks info.
        Ok(())
    }
}
