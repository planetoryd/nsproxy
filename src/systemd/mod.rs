//! https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html
//! https://www.freedesktop.org/software/systemd/man/systemctl.html

use std::path::Path;

use super::*;
use crate::{data::NodeID, managed::ServiceManaged};

pub mod service;

/// State data about the interfacing of service manager (process, task scheduler) and the proxy graph.
pub struct Managed {}

impl ServiceManaged for Managed {
    fn new() -> anyhow::Result<Self> {
        Ok(Self {})
    }
    /// Out node must exist beforehand. 
    /// Main node is created by unshare (if not supplied) and not systemd.
    fn create_proxy(
        &mut self,
        conf: &tun2proxy::PNodeConf,
        main_node: &mut Option<data::PNode>,
        out_node: &data::PNode,
    ) -> Result<()> {
        // It seems project systemd doesn't intend to handle namespaces well. 
        // Do syscalls directly then. 

        Ok(())
    }
}
