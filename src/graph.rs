//! Graph of all proxy nodes, decoupled from systemd or such.
//! We keep proxy graph information here, the topology.
//! Prevent proxy loops, and have a registry of NSes,
//! Processes are managed by systemd.

use std::io::Read;

use super::*;
use crate::{
    data::{
        ExactNS, Graphs, Ix, NodeI, ObjectGraph, ObjectNode, ProcNS, Relation, Route, RouteNode,
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

/// This is an invariant of [ObjectGraph]
pub fn retain_object_graph(og: &mut ObjectGraph) -> Result<()> {
    og.retain_nodes(|n, k| {
        if let Some(k) = &n[k] {
            k.validate().is_ok()
        } else {
            false
        }
    });
    Ok(())
}

impl Graphs {
    pub fn load(st: &str) -> Result<Self> {
        let mut g: Self = from_str(st)?;
        retain_object_graph(&mut g.data)?;
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
        let file = std::fs::File::open(path.state.join("graphs.json"))?;
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
