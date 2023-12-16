use std::{
    fs::{create_dir_all, Permissions},
    path::{Path, PathBuf},
    sync::Arc, os::unix::fs::PermissionsExt,
};

use crate::{
    data::{Ix, NodeI},
    sys::UserNS,
};

use super::*;
use daggy::NodeIndex;
use xdg;

/// globally shared state to derive paths
#[public]
#[derive(Debug)]
struct PathState {
    config: PathBuf,
    binds: PathBuf,
    /// Privileged binds. This path shall not change across users
    /// because the user might use sudo to create them and use it as someone else
    priv_binds: PathBuf,
    state: PathBuf,
}

const DIRPREFIX: &str = "nsproxy";

pub type Paths = Arc<PathState>;

// We want a feature to list all possible paths used by this program
// Otherwise it would suck, really hard.

#[public]
impl PathState {
    fn default() -> Result<Self> {
        let dirs = xdg::BaseDirectories::with_prefix(DIRPREFIX)?;
        let k = Self {
            config: dirs.get_config_home(),
            // we persist NSes across reboots even tho re-creating them is cheap.
            binds: dirs.get_data_home(),
            state: dirs.get_state_home(),
            priv_binds: "/etc/nsproxy/".into(),
        };
        k.create_dirs()?;
        Ok(k)
    }
    fn create_dirs_priv(&self) -> Result<()> {
        create_dir_all(&self.priv_binds)?;
        let perms = PermissionsExt::from_mode(0o777); // a+rwx
        std::fs::set_permissions(&self.priv_binds, perms)?;
        Ok(())
    }
    fn create_dirs(&self) -> Result<()> {
        create_dir_all(&self.config)?;
        create_dir_all(&self.binds)?;
        create_dir_all(&self.state)?;
        Ok(())
    }
    fn mount(&self, id: NodeI) -> Result<Binds> {
        Ok(Binds(checked_path(
            self.binds.join(id.index().to_string()),
        )?))
    }
    fn private(&self) -> PathBuf {
        self.priv_binds.join("private")
    }
    fn user(&self) -> PathBuf {
        self.priv_binds.join("user")
    }
    fn user_nomnt(&self) -> PathBuf {
        self.state.join("user_nomnt.pid")
    }
    fn userns(&self) -> UserNS {
        UserNS(&self)
    }
    fn tun2proxy(&self) -> PathBuf {
        self.config.join("tun2proxy")
    }
}

pub struct Binds(pub PathBuf);

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
