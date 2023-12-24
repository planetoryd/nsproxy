use std::{
    fs::{create_dir_all, Permissions},
    io::Read,
    os::unix::fs::{chown, PermissionsExt},
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
use nix::unistd::geteuid;
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use tracing::info;
use xdg;

/// globally shared state to derive paths
#[public]
#[derive(Debug, Serialize, Deserialize)]
struct PathState {
    /// Should persist
    config: PathBuf,
    /// We need to make sure the paths of .binds are exclusively used by user NS (if its used)
    /// If regular mounts get here problems will happen
    /// Therefore, non-user-ns binds will never be mounted on .binds
    binds: Option<PathBuf>,
    /// Privileged binds. This path shall not change across users
    priv_binds: PathBuf,
    /// Transient state that should not persist
    state: PathBuf,
}

const DIRPREFIX: &str = "nsproxy";

pub type Paths = Arc<PathState>;

// We want a feature to list all possible paths used by this program
// Otherwise it would suck, really hard.


fn create_dirs_chown(path: &Path, uid: u32) -> Result<()> {
    create_dir_all(path)?;
    chown(path, Some(uid), None)?;
    // let perms = PermissionsExt::from_mode(0o777);
    // std::fs::set_permissions(&self.priv_binds, perms)?;
    Ok(())
}

#[public]
impl PathState {
    pub fn dump_file(&self, pa: &Path) -> Result<()> {
        // info!("Dump PathState to {:?}", &pa);
        let file = std::fs::File::create(&pa)?;
        serde_json::to_writer_pretty(&file, self)?;
        Ok(())
    }
    pub fn load_file(pa: &Path, uid: u32) -> Result<Self> {
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
            PathState::default(uid)
        }
    }
    fn load(whatuid: u32) -> Result<(PathBuf, Self)> {
        let pa = if let Ok(p) = std::env::var("PathState") {
            p.parse()?
        } else {
            let dpaths = PathState::default(whatuid)?;
            dpaths.dump_paths()?;
            dpaths.pathspath()
        };
        let pb = PathState::load_file(&pa, whatuid)?;
        Ok((pa, pb))
    }
    fn default(wuid: u32) -> Result<Self> {
        let dirs = xdg::BaseDirectories::with_prefix(DIRPREFIX)?;
        let k = if wuid != 0 {
            let user_run: PathBuf = format!("/run/user/{}/nsproxy/", wuid).parse()?;
            Self {
                config: dirs.get_config_home(),
                binds: Some(user_run.clone()),
                state: user_run,
                priv_binds: "/run/nsproxy/".into(),
            }
        } else {
            Self {
                config: dirs.get_config_home(),
                binds: None,
                // when we can not get a per-user graph
                state: "/run/nsproxy/root".into(),
                priv_binds: "/run/nsproxy/".into(),
            }
        };
        k.create_dirs(wuid)?;
        Ok(k)
    }
 
    fn binds(&self) -> Result<&PathBuf> {
        self.binds
            .as_ref()
            .ok_or(anyhow!("Binds directory (for non root) not available"))
    }
    fn create_dirs(&self, wuid: u32) -> Result<()> {
        create_dirs_chown(&self.config, wuid)?;
        if let Ok(user) = self.binds() {
            create_dirs_chown(user, wuid)?;
            create_dirs_chown(&self.private(false)?, wuid)?;
        }
        create_dirs_chown(&self.tun2proxy(), wuid)?;
        create_dirs_chown(&self.state, wuid)?;
        Ok(())
    }
    fn mount(&self, id: NodeI, root: bool) -> Result<Binds> {
        Ok(Binds(checked_path(
            self.private(root)?.join(id.index().to_string()),
        )?))
    }
    fn private(&self, root: bool) -> Result<PathBuf> {
        Ok(if root {
            &self.priv_binds
        } else {
            self.binds()?
        }
        .join("private"))
    }
    fn user(&self) -> Result<PathBuf> {
        Ok(self.binds()?.join("userns"))
    }
    fn user_nomnt(&self) -> PathBuf {
        self.state.join("user_nomnt.pid")
    }
    fn userns(&self) -> UserNS {
        UserNS(&self)
    }
    fn tun2proxy(&self) -> PathBuf {
        self.state.join("tun2proxy_sock")
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
