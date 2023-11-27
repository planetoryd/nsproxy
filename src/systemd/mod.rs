//! https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html
//! https://www.freedesktop.org/software/systemd/man/systemctl.html

use std::{
    env::current_exe,
    fs::{create_dir_all, remove_file},
    path::{Path, PathBuf},
};

use anyhow::Result;
use daggy::NodeIndex;
use systemd_zbus::{ManagerProxy, Mode::Replace};
use tun::Layer;

use super::*;
use crate::{
    data::{EdgeI, FDRecver, Ix, NodeI, ObjectNode, PassFD, Relation},
    managed::{
        Indexed, ItemAction, ItemCreate, ItemRM, MItem, NodeWDeps, ServiceM, Socks2TUN, SrcNode,
    },
};

pub mod service;

/// State data about the interfacing of service manager (process, task scheduler) and the proxy graph.
pub struct Systemd {
    tun2proxy_socks: PathBuf,
    systemd_unit: PathBuf,
    self_path: PathBuf,
    conn: zbus::Connection,
}

impl<'b> MItem for Socks2TUN<'b> {
    type Param = Layer;
    type Serv = Systemd;
}

impl<'n, 'd> MItem for NodeWDeps<'n, 'd> {
    type Param = ();
    type Serv = Systemd;
}

/// Represents the probe
impl<'k> MItem for SrcNode<'k> {
    type Param = ();
    type Serv = Systemd;
}

// Therefore, the items are different perspectives upon the graph, by which we peform actions.

impl<'k> ItemRM for SrcNode<'k> {
    async fn remove(&self, serv: &Self::Serv) -> Result<()> {
        remove_file(serv.systemd_unit.join(self.service()?))?;
        Ok(())
    }
}

impl<'k> ItemAction for SrcNode<'k> {
    async fn start(
        &self,
        _serv: &Self::Serv,
        ctx: &<Self::Serv as ServiceM>::Ctx<'_>,
    ) -> Result<()> {
        ctx.start_unit(&self.service()?, Replace).await?;
        Ok(())
    }
    async fn stop(
        &self,
        _serv: &Self::Serv,
        ctx: &<Self::Serv as ServiceM>::Ctx<'_>,
    ) -> Result<()> {
        ctx.stop_unit(&self.service()?, Replace).await?;
        Ok(())
    }
}

pub trait UnitName {
    fn stem(&self) -> Result<String>;
    fn service(&self) -> Result<String> {
        Ok(self.stem()? + ".service")
    }
    fn socket(&self) -> Result<String> {
        Ok(self.stem()? + ".socket")
    }
    fn sockpath(&self, dir: &Path) -> Result<PathBuf> {
        Ok(dir.join(self.socket()?))
    }
}

impl<'k> UnitName for SrcNode<'k> {
    fn stem(&self) -> Result<String> {
        Ok(format!("probe{}", self.id.index()))
    }
}

impl<'n, 'd> ItemCreate for NodeWDeps<'n, 'd> {
    type Created = ();
    async fn write(&self, param: Self::Param, serv: &Self::Serv) -> Result<Self::Created> {
        let place = &self.0;
        let relations = &self.1;
        let servname = place.service()?;
        let mut deps = Vec::new();
        for Indexed { id, item: rel } in relations.iter() {
            let rec = match rel {
                Relation::SendTUN(pf) => &pf.receiver,
                Relation::SendSocket(pf) => &pf.receiver,
            };
            let unit: String = match rec {
                FDRecver::Systemd(unit_name) => unit_name.clone(),
                FDRecver::TUN2Proxy(confpath) => Socks2TUN { confpath, ix: *id }.service()?,
                FDRecver::DontCare => continue,
            };
            deps.push(unit);
        }
        let deplist = deps.join(" ");
        let mut service = ini::Ini::new();
        service
            .with_section(Some("Unit"))
            .set("Description", format!("Probe in {:?}", place.id))
            .set("Requires", &deplist)
            .set("After", &deplist);
        service.with_section(Some("Service")).set(
            "ExecStart",
            format!("{:?} probe {:?}", &serv.self_path, &place.id.index()),
        );
        let servpath = serv.systemd_unit.join(&servname);
        service.write_to_file(&servpath)?;
        Ok(())
    }
}

impl<'b> ItemCreate for Socks2TUN<'b> {
    type Created = Relation;
    async fn write(&self, param: Self::Param, serv: &Self::Serv) -> Result<Self::Created> {
        let spath = self.sockpath(&serv.tun2proxy_socks)?;
        let stem = self.stem()?;
        let selfsock = self.socket()?;
        // Add the tun2proxy unit
        let mut socket = ini::Ini::new();
        socket
            .with_section(Some("Unit"))
            .set("Description", format!("FD Receiver of {:?}", &stem));
        socket
            .with_section(Some("Socket"))
            .set("ListenStream", path_to_str(&spath)?);
        socket.write_to_file(&spath)?;

        let mut service = ini::Ini::new();
        service
            .with_section(Some("Unit"))
            .set("Description", format!("TUN2Proxy of {:?}", &stem))
            .set("Requires", &selfsock)
            .set("After", &selfsock);
        service.with_section(Some("Service")).set(
            "ExecStart",
            format!("{:?} tun2proxy {:?}", &serv.self_path, &self.confpath),
        );
        let servname = self.service()?;
        let servpath = serv.systemd_unit.join(&servname);
        service.write_to_file(&servpath)?;
        Ok(Relation::SendTUN(PassFD {
            creation: data::TUNC {
                layer: param,
                name: None,
            },
            receiver: data::FDRecver::TUN2Proxy(self.confpath.to_owned()),
            listener: spath,
        }))
    }
}

impl<'b> ItemRM for Socks2TUN<'b> {
    async fn remove(&self, serv: &Self::Serv) -> Result<()> {
        remove_file(serv.systemd_unit.join(self.service()?))?;
        remove_file(serv.systemd_unit.join(self.socket()?))?;
        Ok(())
    }
}

impl ServiceM for Systemd {
    type Ctx<'c> = ManagerProxy<'c>;
    async fn new() -> Result<Self> {
        let path = "/run/nsproxy/tun2proxy/".parse()?;
        create_dir_all(&path)?;
        let conn = zbus::Connection::system().await?;
        Ok(Self {
            systemd_unit: "/etc/systemd/system/".parse()?,
            tun2proxy_socks: path,
            self_path: current_exe()?,
            conn,
        })
    }
    async fn ctx<'k>(&'k self) -> Result<Self::Ctx<'k>> {
        Ok(ManagerProxy::new(&self.conn).await?)
    }
    async fn reload(&self, ctx: Self::Ctx<'_>) -> Result<()> {
        ctx.reload().await?;
        Ok(())
    }
}
