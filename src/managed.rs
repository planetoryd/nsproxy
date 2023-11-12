//! Allow for other means of process/task scheduling, managing.

use std::path::Path;

use super::*;
use crate::{
    data::{NodeID, PNode},
    graph::ProxyDAG,
    tun2proxy::PNodeConf,
};

pub trait ServiceManaged: Sized {
    fn create_proxy(
        &mut self,
        conf: &PNodeConf,
        main: &mut Option<PNode>,
        out: &PNode,
    ) -> Result<()>;
    fn new() -> Result<Self>;
}
