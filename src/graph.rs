//! Graph of all proxy nodes, decoupled from systemd or such.
//! We keep proxy graph information here, the topology.
//! Prevent proxy loops, and have a registry of NSes,
//! Processes are managed by systemd.

use std::{io::Read, path::PathBuf};

use super::*;
use crate::{
    data::{
        ExactNS, Graphs, Ix, NSGraph, NSGroup, NodeI, ObjectNode, Relation, Route, RouteNode,
        Validate,
    },
    managed::{ItemCreate, ItemRM, NodeWDeps},
    paths::{PathState, Paths},
};

use anyhow::anyhow;
use daggy::{
    self,
    petgraph::visit::{self, Reversed, Topo},
    stable_dag::StableDag,
    Dag,
};
use fs4::FileExt;
use netlink_ops::netlink::{NLDriver, NLHandle};
use nsproxy_common::{PidPath::Selfproc, VaCache, ValidationErr};
use petgraph::visit::IntoNodeReferences;
use serde_json::{from_str, to_string_pretty};
use tracing::info;

impl Graphs {
    pub async fn prune<S>(&mut self, va: &mut VaCache, serv: &S) -> Result<()>
    where
        for<'a, 'b> NodeWDeps<'a, 'b>: ItemRM<Serv = S>,
    {
        let ctx = NSGroup::proc_path(Selfproc, None)?;
        let mut remove = Vec::new();
        // let mut wh = NLDriver::new(NLHandle::new_self_proc_tokio()?);
        // wh.fill().await?;
        for (ni, node) in self.data.node_references() {
            if let Some(k) = node {
                let rx = k.main.net.validate(va, &ctx);
                if let Err(er) = rx {
                    let expected = er.downcast::<ValidationErr>()?;
                    if matches!(expected, ValidationErr::FileNonExistProc) {
                        // TODO: remove it when the NS really disappears
                        continue;
                    }
                    if !matches!(expected, ValidationErr::Permission) {
                        log::info!("Removing NS node {} for {}", k.main.key(), expected);
                        self.map.remove(&k.main.key());
                        remove.push(ni);
                    }
                } else {
                    log::info!("{:?} Net NS, {:?}", ni, rx.unwrap())
                }
            } else {
                remove.push(ni);
            }
        }
        for ni in remove {
            let nodew = self.nodewdeps(ni)?;
            nodew.remove(serv).await?;
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
        info!("Load graphs from {:?}", &gp);
        let mut thing: Option<Self> = None; 
        let file = if gp.exists() {
            let mut file = std::fs::File::open(&gp)?;
            file.try_lock_exclusive()
                .map_err(|_| anyhow!("State file locked"))?;
            let mut st = Default::default();
            file.read_to_string(&mut st)?;
            let k = Self::load(&st);
            if let Ok(stuff) = k {
                thing = Some(stuff)
            } else {
                log::warn!("Corrupted state file. Reset");
            }
            file
        } else {
            let f = std::fs::File::create(&gp)?;
            assert!(gp.exists());
            f.try_lock_exclusive()
                .map_err(|_| anyhow!("State file locked"))?;
            f
        };
        Ok(Graphs {
            file: Some(file),
            ..thing.unwrap_or_default()
        })
    }
    pub fn close(self) -> Result<()> {
        if let Some(ref f) = self.file {
            f.unlock()?;
        }
        Ok(())
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
