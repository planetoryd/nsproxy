//! Graph of all proxy nodes, decoupled from systemd or such.
//! We keep proxy graph information here, the topology.
//! Prevent proxy loops, and have a registry of NSes,
//! Processes are managed by systemd.

use super::*;
use crate::data::{ExactNS, NodeID, PNode, ProcNS};
use daggy::{
    self,
    petgraph::visit::{Reversed, Topo},
    stable_dag::StableDag,
};
use nsproxy_common::Validate;
use serde_json::{from_str, to_string_pretty};

#[test]
fn test_ids() {
    let mut d = StableDag::<String, (), NodeID>::new();
    d.add_node(String::default()); // 0
    let i1 = d.add_node(String::default()); // 1
    let i2 = d.add_node(String::default()); // 2
    let i3 = d.add_node(String::default()); // 3
    d.add_node(String::default());
    d.add_node(String::default());
    d.remove_node(i1);
    d.remove_node(i2);
    d.remove_node(i3);
    dbg!(d.add_node(String::default()));
    dbg!(d.add_node(String::default()));
    dbg!(d.add_node(String::default()));
    dbg!(d.add_node(String::default()));
    // The graph seems to re-occupy vacant positions first.
    // Note, nodes are serialized to an array. The format must keep arrays ordered.
}

pub fn load_graph(text: String) -> Result<ProxyDAG> {
    let mut da: ProxyDAG = from_str(&text)?;
    // Prune dead processes. Remove invalid paths and node references.
    let mut topo = Topo::new(Reversed(&da));
    // Make sure every proxy node is valid itself, and every dependency of it is valid.
    while let Some(node) = topo.next(Reversed(&da)) {
        // For every super -> dep, dep comes before super.
        // Therefore for any super, all deps have been visited and checked
        let vres = da[node].validate();
        if vres.is_err() {
            // Simply remove this proxy node if it is invalid
            da.remove_node(node);
        }
    }

    Ok(da)
}

pub type ProxyDAG = StableDag<PNode, (), NodeID>;

#[public]
impl PNode {
    fn validate(&self) -> Result<()> {
        // It should return Err in that case. A bool lacks info.
        Ok(())
    }
}
