//! Graph of all NS nodes, decoupled from systemd or such.
//! We keep proxy graph information here, the topology.
//! Prevent proxy loops, and have a registry of NSes,
//! Processes are managed by systemd.

use std::{
    collections::{
        hash_map::Entry::{Occupied, Vacant},
        HashMap, HashSet,
    },
    ffi::OsStr,
    io::Read,
    os::unix::fs::chown,
    path::PathBuf,
};

use super::*;
use crate::{
    data::{
        ExactNS, Graphs, Ix, NSGraph, NSGroup, NSNet, NSSlot, NSTrait, NodeI, ObjectNode, Relation,
        Route, RouteNode, Validate,
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
use futures::Future;
use netlink_ops::netlink::{nl_ctx, LinkAB, LinkKey, NLDriver, NLHandle};
use nsproxy_common::{NSSource, PidPath::Selfproc, UniqueFile, VaCache, ValidationErr};
use petgraph::visit::IntoNodeReferences;
use serde_json::{from_str, to_string_pretty};
use tracing::{debug, info, warn};

pub fn find_all_netns() -> Result<HashMap<UniqueFile, PathBuf>> {
    let netk = OsStr::new("net");
    let mut uf_proc = HashMap::new();
    let procs = procfs::process::all_processes()?;
    for proc in procs {
        let proc = proc?;
        let mut ns = proc.namespaces()?;
        if let Some(net) = ns.0.remove(netk) {
            let uf = UniqueFile::new(net.identifier, net.device_id);
            match uf_proc.entry(uf) {
                Vacant(e) => {
                    e.insert(net.path);
                }
                Occupied(e) => continue,
            }
        }
    }
    Ok(uf_proc)
}

#[derive(PartialEq, Eq)]
pub enum FResult {
    /// remove the node, provide the reason
    Remove(String),
    Keep,
}
/// Removes useless nodes that may be removed for what net ns you are in, at best effort.
/// Fixes the graph when possible
/// Veths that are found, which should be removed when the node is removed, are added to .links
/// If veths should be present but are not, fn returns ::Remove
pub async fn check_veths(
    nl: &mut NLDriver,
    nodew: &NodeWDeps<'_, '_>,
    ctx: &NSGroup<ExactNS>,
    links: &mut HashSet<LinkKey>,
) -> Result<FResult> {
    let mut rx = FResult::Keep;
    for dep in &nodew.1 {
        match &dep.edge.item {
            Relation::Veth(ve) => {
                let lkb = ve.key.link(LinkAB::B);
                let lke = if nl.links.contains_key(&lkb) {
                    let lka = ve.key.link(LinkAB::A);
                    if nl.links.contains_key(&lka) {
                        Some(lka)
                    } else {
                        Some(lkb)
                    }
                } else {
                    None
                };
                let ctxino = ctx.net.must()?.unique;
                let match_ns = dep.dst.item.main.net.map(|dstino| {
                    nodew
                        .0
                        .item
                        .main
                        .net
                        .map(|srcino| dstino.unique == ctxino || srcino.unique == ctxino)
                });
                if let Some(lk) = lke {
                    // keep
                    if match_ns {
                        links.insert(lk);
                        // but links found are inserted, for use as you may want to remove this node later
                    }
                } else {
                    if match_ns {
                        // Veth not preset. Yet I am in one of the target and source NS.
                        rx = FResult::Remove("veth missing".to_string());
                    }
                }
            }
            _ => (),
        }
    }

    Ok(rx)
}

#[derive(Default)]
pub struct RM {
    /// Links found
    links: HashSet<LinkKey>,
    rm: bool,
}

pub trait RMable {
    fn add(self, rm: &mut RM);
}

impl RMable for LinkKey {
    fn add(self, rm: &mut RM) {
        rm.links.insert(self);
    }
}

impl RMable for () {
    fn add(self, rm: &mut RM) {}
}

fn insert_rm(map: &mut HashMap<NodeI, RM>, key: &NodeI, val: impl RMable) {
    val.add(insert_rm_ref(map, key))
}

fn insert_rm_ref<'b>(map: &'b mut HashMap<NodeI, RM>, key: &NodeI) -> &'b mut RM {
    if !map.contains_key(key) {
        map.insert(*key, RM::default());
    }
    map.get_mut(key).unwrap()
}

impl Graphs {
    /// remove: a hashset containing nodes scheduled for remove, by method prune.
    pub async fn clean_proc(&mut self, remove: &mut HashMap<NodeI, RM>) -> Result<()> {
        todo!();
        // try to fix /proc/ paths that are made unavailable by processes dying
        // by finding existing processes with same netns
        let mut uf_proc = find_all_netns()?;
        let mut indices = Vec::with_capacity(self.data.node_count());
        indices.extend(self.data.node_indices());
        for ni in indices {
            if let Some(node) = &mut self.data[ni] {
                match &mut node.main.net {
                    NSSlot::Provided(en, _ty) => match &mut en.source {
                        NSSource::Path(pt) => {
                            if pt.starts_with("/proc/") && !pt.exists() {
                                // Each node maps to one unique NS, so we can just take the owned
                                if let Some(uf) = uf_proc.remove(&en.unique) {
                                    *pt = uf;
                                } else {
                                    insert_rm(remove, &ni, ());
                                }
                            }
                        }
                        _ => (),
                    },
                    _ => (),
                }
            }
        }
        Ok(())
    }
    pub async fn node_rm<'f, S>(
        &mut self,
        ctx: &NSGroup<ExactNS>,
        nodes: &[NodeI],
        va: &mut VaCache,
        remove: &mut HashMap<NodeI, RM>,
        nl: &mut NLDriver,
    ) -> Result<()>
    where
        for<'a, 'b> NodeWDeps<'a, 'b>: ItemRM<Serv = S>,
    {
        for ni in nodes {
            if let Some(k) = self
                .data
                .node_weight(*ni)
                .ok_or(anyhow!("specified node to rm doesnt exist"))?
            {
                let nodew = self.nodewdeps(*ni)?;
                let rm = insert_rm_ref(remove, &ni);
                check_veths(nl, &nodew, &ctx, &mut rm.links).await?;
                rm.rm = true;
            } else {
                warn!("skipped {:?} for it's None", ni)
            }
        }
        Ok(())
    }
    pub async fn prune<'f, S>(
        &mut self,
        ctx: &NSGroup<ExactNS>,
        va: &mut VaCache,
        serv: &S,
        remove: &mut HashMap<NodeI, RM>,
        nl: &mut NLDriver,
    ) -> Result<()>
    where
        for<'a, 'b> NodeWDeps<'a, 'b>: ItemRM<Serv = S>,
    {
        for (ni, node) in self.data.node_references() {
            if let Some(k) = node {
                let rx = k.main.net.validate(va, &ctx);
                if let Err(er) = rx {
                    let verr = er.downcast::<ValidationErr>()?;
                    debug!("prune check, {:?} Net NS, {:?}", ni, verr);
                    let nodew = self.nodewdeps(ni)?;
                    let zerodep = nodew.1.len() == 0;
                    let rm = insert_rm_ref(remove, &ni);
                    if let FResult::Remove(_) = check_veths(nl, &nodew, &ctx, &mut rm.links).await?
                    {
                        info!("Removing NS node {} because veth is missing", k.main.key());
                        rm.rm = true;
                    }
                    if matches!(verr, ValidationErr::FileNonExistProc) {
                        if zerodep {
                            info!(
                                "Removing NS node {} for {} and having no dependencies",
                                k.main.key(),
                                verr
                            );
                            rm.rm = true;
                        }
                    }
                    if !matches!(verr, ValidationErr::Permission) {
                        info!("Removing NS node {} for {}", k.main.key(), verr);
                        rm.rm = true;
                    }
                } else {
                    debug!("prune check, {:?} Net NS, {:?}", ni, rx)
                }
            } else {
                insert_rm(remove, &ni, ());
            }
        }
        Ok(())
    }
    pub async fn do_prune<'f, S>(
        &mut self,
        ctx: &NSGroup<ExactNS>,
        serv: &S,
        remove: HashMap<NodeI, RM>,
        nl: &mut NLDriver,
    ) -> Result<()>
    where
        for<'a, 'b> NodeWDeps<'a, 'b>: ItemRM<Serv = S>,
    {
        for (ni, rm) in remove.iter() {
            let nodew = self.nodewdeps(*ni)?;
            if rm.rm {
                for link in &rm.links {
                    info!("Remove {:?}", &link);
                    nl.remove_link(&link).await?;
                }
                nodew.remove(serv).await?;
                self.map.remove(&nodew.0.item.main.key());
                self.data.remove_node(*ni);
            }
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
            } else if st.trim().is_empty() {
                // Ignore
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
        let mut k = thing.unwrap_or_default();
        k.file = Some(file);
        Ok(k)
    }
    pub fn dump_file(&self, path: &PathState, wuid: u32) -> Result<()> {
        let pa = Self::path(path);
        log::info!("Dump graphs to {:?}", &pa);
        let file = std::fs::File::create(&pa)?;
        chown(&pa, Some(wuid), None)?;
        serde_json::to_writer_pretty(&file, self)?;
        Ok(())
    }
    pub fn path(path: &PathState) -> PathBuf {
        path.state.join("graphs.json")
    }
}

impl Drop for Graphs {
    fn drop(&mut self) {
        if let Some(ref f) = self.file {
            f.unlock().unwrap();
        }
    }
}
