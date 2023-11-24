use super::*;
use anyhow::Ok;
use log::info;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, str::FromStr, fs::create_dir_all};

/// Adapt the flatpak settings of a given list
/// Dry: log and do nothing
pub fn adapt_flatpak(list: Vec<&FlatpakID>, dry: bool) -> Result<()> {
    let basedirs = xdg::BaseDirectories::with_prefix("flatpak")?;
    let poverride = basedirs.get_data_file("overrides");
    create_dir_all(&poverride)?;
    info!(
        "Trying to adapt flatpak app permissions.
     This turns 'Network' off which causes flatpak to use isolated network namespaces.
     This must be done early to prevent accidental unsandboxed use of network"
    );
    for appid in list {
        let fp = poverride.join(&appid.0);
        if dry {
            println!("{:?}", &fp);
        } else {
            let pstr = path_to_str(&fp)?;
            if fp.exists() {
                let mut conf = ini::Ini::load_from_file(fp.as_path())?;
                let val = conf.get_from(Some("Context"), "shared");
                if let Some(val) = val {
                    if val.contains("!network") {
                        info!("{} found. it has correct config", pstr);
                    } else {
                        let v = val.to_owned() + ";!network";
                        conf.set_to(Some("Context"), "shared".to_owned(), v);
                        conf.write_to_file(fp.as_path())?;
                        info!("{} written [Existing]", pstr);
                    }
                } else {
                    conf.set_to(Some("Context"), "shared".to_owned(), "!network".to_owned());
                    conf.write_to_file(fp.as_path())?;
                    info!("{} written [Existing]", pstr);
                }
            } else {
                // create a new file for it
                let mut conf = ini::Ini::new();
                conf.set_to(Some("Context"), "shared".to_owned(), "!network".to_owned());
                conf.write_to_file(fp.as_path())?;
                info!("{} written [New file]", pstr);
            }
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct FlatpakID(pub String);

impl FromStr for FlatpakID {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

#[test]
fn test_flatpakperm() -> Result<()> {
    adapt_flatpak(
        [
            &"org.mozilla.firefox".parse()?,
            &"im.fluffychat.Fluffychat".parse()?,
        ]
        .to_vec(),
        false,
    )?;
    Ok(())
}

// RUST_LOG=info cargo test logpath -- --nocapture
#[test]
fn logpath() -> Result<()> {
    adapt_flatpak(
        [
            &"org.mozilla.firefox".parse()?,
            &"im.fluffychat.Fluffychat".parse()?,
        ]
        .to_vec(),
        true,
    )?;

    Ok(())
}
