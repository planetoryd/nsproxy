use anyhow::Ok;
use log::info;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, str::FromStr};
use super::*;

/// Adapt the flatpak settings of a given list
pub fn adapt_flatpak(list: Vec<&FlatpakID>, logpath: bool) -> Result<()> {
    let basedirs = xdg::BaseDirectories::with_prefix("flatpak")?;
    info!(
        "Trying to adapt flatpak app permissions.
     This turns 'Network' off which causes flatpak to use isolated network namespaces.
     This must be done early to prevent accidental unsandboxed use of network"
    );
    for appid in list {
        let mut sub = PathBuf::from("overrides");
        sub.push(&appid.0);
        let p = basedirs.get_data_file(&sub);
        if logpath {
            println!("{:?}", &p);
        } else {
            if p.exists() {
                let mut conf = ini::Ini::load_from_file(p.as_path())?;
                let k = conf.get_from(Some("Context"), "shared");
                if k.is_some() {
                    if k.unwrap().contains("!network") {
                        info!("{} found. it has correct config", p.to_string_lossy());
                    } else {
                        let o = k.unwrap().to_owned();
                        let v = o + ";!network";
                        conf.set_to(Some("Context"), "shared".to_owned(), v);
                        conf.write_to_file(p.as_path())?;
                        info!("{} written", p.to_string_lossy());
                    }
                } else {
                    conf.set_to(Some("Context"), "shared".to_owned(), "!network".to_owned());
                    conf.write_to_file(p.as_path())?;
                    info!("{} written", p.to_string_lossy());
                }
            } else {
                // create a new file for it
                let mut conf = ini::Ini::new();
                conf.set_to(Some("Context"), "shared".to_owned(), "!network".to_owned());
                conf.write_to_file(p.as_path())?;
                info!("{} written. New file", p.to_string_lossy());
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
