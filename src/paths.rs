use std::{
    fs::{create_dir_all, Permissions},
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    data::{Ix, NodeI},
    sys::UserNS,
};

use super::*;
use anyhow::anyhow;
use daggy::NodeIndex;
use fs4::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use tracing::info;
use xdg;

/// globally shared state to derive paths
#[public]
#[derive(Debug, Serialize, Deserialize)]
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
    pub fn dump_file(&self, pa: &Path) -> Result<()> {
        // info!("Dump PathState to {:?}", &pa);
        let file = std::fs::File::create(&pa)?;
        serde_json::to_writer_pretty(&file, self)?;
        Ok(())
    }
    pub fn load_file(pa: &Path) -> Result<Self> {
        info!("Load PathState from {:?}", pa);
        if pa.exists() {
            let mut file = std::fs::File::open(pa)?;
            file.try_lock_exclusive()
                .map_err(|_| anyhow!("State file locked"))?;
            let mut st = Default::default();
            file.read_to_string(&mut st)?;
            let g: Self = from_str(&st)?;
            Ok(g)
        } else {
            let f = std::fs::File::create(&pa)?;
            assert!(pa.exists());
            f.try_lock_exclusive()
                .map_err(|_| anyhow!("State file locked"))?;
            PathState::default()
        }
    }
    fn load() -> Result<(PathBuf, Self)> {
        let pa = if let Ok(p) = std::env::var("PathState") {
            p.parse()?
        } else {
            let dpaths = PathState::default()?;
            dpaths.dump_paths()?;
            dpaths.pathspath()
        };
        let pb = PathState::load_file(&pa)?;
        Ok((pa, pb))
    }
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
    fn mount(&self, id: NodeI, root: bool) -> Result<Binds> {
        Ok(Binds(checked_path(
            if root { &self.priv_binds } else { &self.binds }.join(id.index().to_string()),
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
    fn flatpak(&self) -> PathBuf {
        self.config.join("flatpak.json")
    }
    fn pathspath(&self) -> PathBuf {
        self.config.join("paths")
    }
    fn dump_paths(&self) -> Result<()> {
        self.dump_file(&self.pathspath())
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
