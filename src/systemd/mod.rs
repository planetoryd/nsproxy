//! https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html
//! https://www.freedesktop.org/software/systemd/man/systemctl.html

use std::{
    collections::HashSet,
    env::current_exe,
    fs::{create_dir_all, remove_file},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Result};
use daggy::NodeIndex;
use systemd_zbus::{ManagerProxy, Mode::Replace};
use tun::Layer;
use zbus::Address;

use super::*;
use crate::{
    data::{EdgeI, FDRecver, Ix, NodeI, ObjectNode, PassFD, Relation},
    managed::{
        Indexed, ItemAction, ItemCreate, ItemRM, MItem, NodeWDeps, ServiceM, Socks2TUN, SrcDeps,
        SrcNode,
    },
    paths::PathState,
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

impl<'k> MItem for SrcDeps<'k> {
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
    async fn restart(
        &self,
        _serv: &Self::Serv,
        ctx: &<Self::Serv as ServiceM>::Ctx<'_>,
    ) -> Result<()> {
        let n = self.service()?;
        log::info!("(Re)start unit {n}");
        ctx.restart_unit(&n, Replace).await?;
        Ok(())
    }
    async fn stop(
        &self,
        _serv: &Self::Serv,
        ctx: &<Self::Serv as ServiceM>::Ctx<'_>,
    ) -> Result<()> {
        let n = self.service()?;
        log::info!("Stop unit {n}");
        ctx.stop_unit(&n, Replace).await?;
        Ok(())
    }
}

pub fn units(ve: &SrcDeps<'_>) -> Result<HashSet<String>> {
    let mut units = HashSet::new();
    for Indexed { id, item } in ve {
        let re = match item {
            Relation::SendSocket(p) => &p.receiver,
            Relation::SendTUN(p) => &p.receiver,
        };
        match re {
            FDRecver::Systemd(se) => units.insert(se.to_owned()),
            FDRecver::TUN2Proxy(pa) => units.insert(Socks2TUN::new(&pa, *id)?.service()?),
            _ => false,
        };
    }
    Ok(units)
}

impl<'k> ItemAction for SrcDeps<'k> {
    async fn restart(
        &self,
        serv: &Self::Serv,
        ctx: &<Self::Serv as ServiceM>::Ctx<'_>,
    ) -> Result<()> {
        let units = units(self)?;
        for s in units {
            ctx.restart_unit(&s, Replace).await?;
        }
        Ok(())
    }
    async fn stop(&self, serv: &Self::Serv, ctx: &<Self::Serv as ServiceM>::Ctx<'_>) -> Result<()> {
        let units = units(self)?;
        for s in units {
            ctx.stop_unit(&s, Replace).await?;
        }
        Ok(())
    }
}

pub trait UnitName {
    fn stem(&self) -> Result<String>;
    fn service(&self) -> Result<String> {
        Ok(self.stem()? + ".service")
    }
    fn sockunit(&self) -> Result<String> {
        Ok(self.stem()? + ".socket")
    }
    fn sockf(&self) -> Result<String> {
        Ok(self.stem()? + ".sock")
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
        service
            .with_section(Some("Service"))
            .set(
                "ExecStart",
                format!("{:?} probe {:?}", &serv.self_path, &place.id.index()),
            )
            .set("Type", "oneshot")
            .set("RemainAfterExit", "yes")
            .set("StandardOutput", "journal")
            .set("StandardError", "journal")
            .set("Environment", "RUST_BACKTRACE=1");
        let servpath = serv.systemd_unit.join(&servname);
        service.write_to_file(&servpath)?;
        // Note: do not run jounralctl in the userns shell, or it won't show any logs
        Ok(())
    }
}

impl<'b> ItemCreate for Socks2TUN<'b> {
    type Created = Relation;
    async fn write(&self, param: Self::Param, serv: &Self::Serv) -> Result<Self::Created> {
        let sunit = serv.systemd_unit.join(self.sockunit()?);
        let sfile = serv.tun2proxy_socks.join(self.sockf()?);
        let stem = self.stem()?;
        let selfsock = self.sockunit()?;
        // Add the tun2proxy unit
        let mut socket = ini::Ini::new();
        socket
            .with_section(Some("Unit"))
            .set("Description", format!("FD Receiver of {:?}", &stem));
        socket
            .with_section(Some("Socket"))
            .set("ListenStream", path_to_str(&sfile)?);
        socket.write_to_file(&sunit)?;

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
            listener: sfile,
        }))
    }
}

impl<'b> ItemAction for Socks2TUN<'b> {
    async fn restart(
        &self,
        serv: &Self::Serv,
        ctx: &<Self::Serv as ServiceM>::Ctx<'_>,
    ) -> Result<()> {
        let servname = self.service()?;
        ctx.restart_unit(&servname, Replace).await?;
        Ok(())
    }
    async fn stop(&self, serv: &Self::Serv, ctx: &<Self::Serv as ServiceM>::Ctx<'_>) -> Result<()> {
        let servname = self.service()?;
        ctx.stop_unit(&servname, Replace).await?;
        Ok(())
    }
}

impl<'b> ItemRM for Socks2TUN<'b> {
    async fn remove(&self, serv: &Self::Serv) -> Result<()> {
        remove_file(serv.systemd_unit.join(self.service()?))?;
        remove_file(serv.systemd_unit.join(self.sockunit()?))?;
        Ok(())
    }
}

#[public]
impl Systemd {
    async fn new(paths: &PathState, conn: impl Into<zbus::Connection>) -> Result<Self> {
        let path = paths.tun2proxy();
        create_dir_all(&path)?;
        let base = directories::BaseDirs::new().unwrap();
        let systemd_unit = base.config_local_dir().join("systemd/user");
        // create_dir_all(&systemd_unit);
        Ok(Self {
            systemd_unit,
            tun2proxy_socks: path,
            self_path: current_exe()?,
            conn: conn.into(),
        })
    }
}

impl ServiceM for Systemd {
    type Ctx<'c> = ManagerProxy<'c>;
    async fn ctx<'k>(&'k self) -> Result<Self::Ctx<'k>> {
        Ok(ManagerProxy::new(&self.conn).await?)
    }
    async fn reload(&self, ctx: &Self::Ctx<'_>) -> Result<()> {
        ctx.reload().await?;
        log::info!("Reloaded");
        Ok(())
    }
}
