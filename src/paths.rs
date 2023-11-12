use std::{
    fs::create_dir_all,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::data::NodeID;

use super::*;
use xdg;

/// globally shared state to derive paths
#[public]
#[derive(Debug)]
struct PathState {
    config: PathBuf,
    binds: PathBuf,
    state: PathBuf,
}

const DIRPREFIX: &str = "nsproxy";

pub type Paths = Arc<PathState>;

// We want a feature to list all possible paths used by this program
// Otherwise it would suck, really hard.

impl PathState {
    pub fn default() -> Result<Self> {
        let dirs = xdg::BaseDirectories::with_prefix(DIRPREFIX)?;
        let k = Self {
            config: dirs.get_config_home(),
            // we persist NSes across reboots even tho re-creating them is cheap.
            binds: dirs.get_data_home(),
            state: dirs.get_state_home(),
        };
        k.create_dirs()?;
        Ok(k)
    }
    pub fn create_dirs(&self) -> Result<()> {
        create_dir_all(&self.config)?;
        create_dir_all(&self.binds)?;
        create_dir_all(&self.state)?;

        Ok(())
    }
    pub fn mount(&self, id: NodeID) -> Result<Binds> {
        Ok(Binds(checked_path(self.binds.join(id.to_string()))?))
    }
}

pub struct Binds(PathBuf);

// pass it through 
pub fn checked_path(p: PathBuf) -> Result<PathBuf> {
    create_dir_all(&p)?;
    Ok(p)
}

impl Binds {
    pub fn ns(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

#[test]
fn tryitout() -> Result<()> {
    let k = xdg::BaseDirectories::with_prefix("huh")?.get_state_home();
    dbg!(k);
    Ok(())
}
