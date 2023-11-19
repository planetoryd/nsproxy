//! https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html
//! https://www.freedesktop.org/software/systemd/man/systemctl.html

use std::{
    env::current_exe,
    fs::create_dir_all,
    path::{Path, PathBuf},
};

use anyhow::Result;
use daggy::NodeIndex;
use tun::Layer;

use super::*;
use crate::{
    data::{NodeID, PassFD, Relation},
    managed::{ServiceManaged, Socks2TUN},
};

pub mod service;

/// State data about the interfacing of service manager (process, task scheduler) and the proxy graph.
pub struct Systemd {
    tun2proxy_socks: PathBuf,
    self_path: PathBuf,
}

#[public]
impl Socks2TUN {
    fn stem(&self) ->  String{
        
    }
}

impl ServiceManaged for Systemd {
    fn new() -> Result<Self> {
        let path = "/run/nsproxy/tun2proxy/".parse()?;
        create_dir_all(&path)?;
        Ok(Self {
            tun2proxy_socks: path,
            self_path: current_exe()?,
        })
    }
    /// Creates a socket, and a tun2proxy service with the same name as the config file
    fn socks2tun(&self, layer: Layer, Socks2TUN { confpath, src }: Socks2TUN) -> Result<Relation> {
        let stem = confpath.file_stem().unwrap();
        let mut name = stem.to_owned();
        name.push(".sock");
        let name_str = name.to_string_lossy();
        let mut spath: PathBuf = self.tun2proxy_socks.clone();
        spath.push(name);

        // Add the tun2proxy unit
        let mut socket = ini::Ini::new();
        socket
            .with_section(Some("Unit"))
            .set("Description", format!("FD Receiver of {:?}", stem));
        socket
            .with_section(Some("Socket"))
            .set("ListenStream", spath.to_string_lossy());
        socket.write_to_file(spath)?;

        let mut service = ini::Ini::new();
        service
            .with_section(Some("Unit"))
            .set("Description", format!("TUN2Proxy of {stem:?}"))
            .set("Requires", name_str)
            .set("After", name_str);
        service.with_section(Some("Service")).set(
            "ExecStart",
            format!("{:?} tun2proxy {:?}", &self.self_path, &confpath),
        );
        let servname = stem.to_string_lossy().into_owned() + ".service";
        let servpath = ["/etc/systemd/system/", &servname]
            .iter()
            .collect::<PathBuf>();
        service.write_to_file(&servpath)?;

        Ok(Relation::SendTUN(PassFD {
            creation: data::TUNC { layer, name: None },
            receiver: data::FDRecver::TUN2Proxy(confpath),
            listener: spath,
        }))
    }
}
