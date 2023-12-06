//! Graph of all proxy nodes, decoupled from systemd or such.
//! We keep proxy graph information here, the topology.
//! Prevent proxy loops, and have a registry of NSes,
//! Processes are managed by systemd.

use std::io::Read;

use super::*;
use crate::{
    data::{
        ExactNS, Graphs, Ix, NodeI, ObjectGraph, ObjectNode, ProcNS, Relation, Route, RouteNode, ObjectNS,
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
use serde_json::{from_str, to_string_pretty};

impl Graphs {
    pub fn retain(&mut self) -> Result<()> {
        self.data.retain_nodes(|n, k| {
            if let Some(k) = &n[k] { 
                if k.validate().is_ok() {
                    true 
                } else {
                    self.map.remove(&k.main.key());
                    false
                }
            } else {
                false
            }
        });
        Ok(())
    }
    pub fn load(st: &str) -> Result<Self> {
        let g: Self = from_str(st)?;
        Ok(g)
    }
    pub fn load_file(path: &PathState) -> Result<Self> {
        let gp = path.state.join("graphs.json");
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
        log::info!("Write graphs");
        let file = std::fs::File::create(path.state.join("graphs.json"))?;
        serde_json::to_writer_pretty(&file, self)?;
        Ok(())
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
