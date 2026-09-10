#![feature(exact_size_is_empty)]
#![feature(decl_macro)]
#![allow(async_fn_in_trait)]
#![feature(ip_as_octets)]
#![feature(setgroups)]

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs::{File, create_dir_all};
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use futures::StreamExt;
use futures::TryStreamExt;
use ipnetwork::Ipv4Network;
use ipnetwork::Ipv6Network;
use libc::pid_t;
use nsproxy_common::ExactNS;
use nsproxy_common::NSFrom;
pub use nsproxy_common::{NsAlive, PERSIST_ROOT, state_paths};
use rtnetlink::Handle;
use rtnetlink::LinkUnspec;
use rtnetlink::LinkVeth;
use rtnetlink::RouteAddRequest;
use rtnetlink::RouteMessageBuilder;
use rtnetlink::packet_route::address::AddressAttribute;
use rtnetlink::packet_route::address::AddressMessage;
use rtnetlink::packet_route::link::InfoKind;
use rtnetlink::packet_route::link::LinkAttribute;
use rtnetlink::packet_route::link::LinkFlags;
use rtnetlink::packet_route::link::LinkInfo;
use rtnetlink::packet_route::link::LinkMessage;
use rtnetlink::packet_route::route::RouteAddress;
use rtnetlink::packet_route::route::RouteAttribute;
use rtnetlink::packet_route::route::RouteMessage;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_untagged::UntaggedEnumVisitor;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;
use tracing::level_filters::LevelFilter;
use tracing::{info, warn};
pub use tun2socks5;
pub mod cmd_common;
pub mod cmd_uplink;
pub mod env;
pub mod hot_reload;
pub mod internal_dns;
pub mod personal;
pub mod prelude;
pub mod sandbox;
pub mod shell;
pub mod state_blueprint;
pub mod sys;
pub mod utils;

pub fn build_tree_hash() -> &'static str {
    option_env!("NSP_BUILD_TREE_HASH").unwrap_or("unknown")
}

pub const NSPROXY_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn build_epoch_secs() -> u64 {
    option_env!("NSP_BUILD_EPOCH_SECS")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
}

pub fn build_identity() -> String {
    build_tree_hash().to_owned()
}

pub struct TunMaker {
    pub name: String,
    pub ipv4: Ipv4Network,
    pub ipv6: Ipv6Network,
    pub mtu: u16,
}

#[derive(Default)]
pub struct TunState {
    pub fd: Option<TUNDev>,
    default_route: bool,
    tun_is_up: bool,
    name: String,
    pub dev_index: u32,
    sync: SyncStatus,
}

#[derive(Default)]
/// Does the data struct correctly represent Kernel state?
pub struct SyncStatus {
    basic_synced: bool,
    route_checked: bool,
}

/// Minimal utils atop netlink
pub trait NetlinkParseUpdate {
    type Repr;
    /// Continually updates a parser state. Allowing gradual buildup.
    fn parse_update(&self, parsed: &mut Self::Repr) -> Result<()>;
}

pub trait NetlinkParse {
    type Repr;
    fn parse(&self) -> Result<Self::Repr>;
}

use ipnetwork::IpNetwork;

pub const CAPTURED_RESOLV_CONF_DNS: &str = "100.68.0.2";
pub const INTERNAL_RESOLV_CONF_DNS: &str = "127.0.0.1";

fn default_resolv_conf_dns() -> String {
    CAPTURED_RESOLV_CONF_DNS.to_string()
}

#[derive(Default)]
pub struct AddressResponse {
    pub addrs: Vec<IpNetwork>,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct RouteEntry {
    pub source_addrs: Vec<IpNetwork>,
    pub dst_addrs: Vec<IpNetwork>,
    pub table: Option<u32>,
    pub oif: Option<u32>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct RoutingTable {
    pub tables: HashMap<u32, Vec<RouteEntry>>,
}

impl NetlinkParseUpdate for AddressMessage {
    type Repr = AddressResponse;
    fn parse_update(&self, parsed: &mut Self::Repr) -> Result<()> {
        for msg in &self.attributes {
            match msg {
                AddressAttribute::Address(ip) => {
                    parsed
                        .addrs
                        .push(IpNetwork::new(ip.to_owned(), self.header.prefix_len)?);
                }
                _ => (),
            }
        }
        Ok(())
    }
}

pub fn octets_to_addr(a: &[u8], prefix: u8) -> Result<Option<IpNetwork>> {
    let ip = if a.len() == 4 {
        let con: [u8; 4] = a.to_owned().try_into().unwrap();
        let ip4: Ipv4Addr = con.into();
        Some(IpNetwork::new(ip4.into(), prefix)?)
    } else if a.len() == 16 {
        let con: [u8; 16] = a.to_owned().try_into().unwrap();
        let ip6: Ipv6Addr = con.into();
        Some(IpNetwork::new(ip6.into(), prefix)?)
    } else {
        None
    };
    Ok(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnetwork::{IpNetwork, Ipv4Network};
    use std::os::unix::fs::MetadataExt;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    /// Verify that the no_dns_capture sentinel ("0.0.0.0/32") matches no real IP.
    #[test]
    fn test_no_dns_capture_sentinel_matches_nothing() {
        let mut hot = HotConfig::default();
        hot.dns_capture = ["0.0.0.0/32".parse().unwrap()].into();

        // Common routable addresses that should NOT be captured.
        let candidates: &[&str] = &[
            "1.1.1.1",
            "8.8.8.8",
            "100.68.0.1",
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "::1",
            "fe80::1",
            "127.0.0.1",
        ];
        for addr in candidates {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(!hot.captures_dns(ip), "sentinel should not capture {addr}");
        }
    }

    #[test]
    fn test_find_vacant_ipv4() {
        let net: Ipv4Network = "100.64.0.0/10".parse().unwrap();
        let used: Vec<Ipv4Addr> = vec!["100.64.0.5".parse::<_>().unwrap()];

        let vacant = find_vacant_ipv4_subnet(used, net, 2).expect("should find a vacant addr");
        dbg!(vacant);
        dbg!(veth_addr_for(vacant, 2, true));
        dbg!(veth_addr_for(vacant, 2, false));
    }

    #[test]
    fn test_hotconfig_expand_placeholders_at_and_tilde() {
        let instance_root = PathBuf::from("/nsp3/test-profile");
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .expect("HOME must be set for expansion tests");

        let mut hot = HotConfig::default();
        hot.mnt
            .insert(PathBuf::from("@/src"), PathBuf::from("~/dst"));
        hot.mnt
            .insert(PathBuf::from("~"), PathBuf::from("@/target"));

        hot.expand_placeholders(&instance_root);

        assert!(hot.mnt.contains_key(&instance_root.join("src")));
        assert_eq!(
            hot.mnt.get(&instance_root.join("src")).cloned(),
            Some(home.join("dst"))
        );

        assert!(hot.mnt.contains_key(&home));
        assert_eq!(
            hot.mnt.get(&home).cloned(),
            Some(instance_root.join("target"))
        );
    }

    #[test]
    fn test_profileconfig_expand_placeholders_including_hot_init() {
        let instance_root = PathBuf::from("/nsp3/profileA");
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .expect("HOME must be set for expansion tests");

        let mut profile = TemplateConfig {
            schema: TemplateConfigV2::VERSION,
            sandbox_mode: SandboxMode::Overlay,
            mounts: vec![ProfileMount {
                source: PathBuf::from("@/mnt-src"),
                target: PathBuf::from("@/mnt-dst"),
                read_only: false,
                recursive: true,
                skip_missing: false,
            }],
            chmod: vec![ProfileChmod {
                path: PathBuf::from("@/chmod-target"),
                mode: Some(0o755),
                uid: None,
                gid: None,
                mkdir: false,
            }],
            env: HashMap::new(),
            inherit_env: true,
            hot: PathBuf::from("@/hot.json"),
            hot_init: Some(HotConfig {
                dns: HashMap::new(),
                x11: false,
                wayland: false,
                tun: HashMap::new(),
                devs: HashMap::new(),
                mnt: {
                    let mut m = HashMap::new();
                    m.insert(PathBuf::from("@/hot-src"), PathBuf::from("~/hot-dst"));
                    m.insert(PathBuf::from("~"), PathBuf::from("@/hot-target"));
                    m
                },
                locals: HashMap::new(),
                dns_capture: Default::default(),
                resolv_conf_dns: default_resolv_conf_dns(),
                route: HotRoute::None,
                mounts: Vec::new(),
                daemons: Vec::new(),
                applications: Vec::new(),
                veth: Vec::new(),
            }),
            sargs: shell::ShellArgs {
                uid: None,
                gid: None,
                gids: Vec::new(),
                shell: None,
                cwd: Some(PathBuf::from("@/cwd")),
                args: Vec::new(),
            },
            browser_profile: None,
            dbus: DbusMode::Container,
            rootfs: Rootfs::Default,
        };

        profile.expand_placeholders(&instance_root);

        assert_eq!(profile.hot, instance_root.join("hot.json"));
        assert_eq!(profile.mounts[0].source, instance_root.join("mnt-src"));
        assert_eq!(profile.mounts[0].target, instance_root.join("mnt-dst"));
        assert_eq!(profile.chmod[0].path, instance_root.join("chmod-target"));
        assert_eq!(profile.sargs.cwd, Some(instance_root.join("cwd")));

        let hot_init = profile.hot_init.as_ref().expect("hot_init should exist");
        assert_eq!(
            hot_init.mnt.get(&instance_root.join("hot-src")).cloned(),
            Some(home.join("hot-dst"))
        );
        assert_eq!(
            hot_init.mnt.get(&home).cloned(),
            Some(instance_root.join("hot-target"))
        );
    }

    fn test_mount(source: &str, target: &str) -> ProfileMount {
        ProfileMount {
            source: PathBuf::from(source),
            target: PathBuf::from(target),
            read_only: false,
            recursive: true,
            skip_missing: false,
        }
    }

    #[test]
    fn test_hotconfig_merged_mounts_preserves_explicit_order() {
        let mut hot = HotConfig::default();
        hot.mounts = vec![
            test_mount("/source-a", "/target-a"),
            test_mount("/source-b", "/target-b"),
        ];

        let mounts = hot.merged_mounts().unwrap();
        assert_eq!(mounts, hot.mounts);
    }

    #[test]
    fn test_hotconfig_process_x11_appends_once() {
        let mut hot = HotConfig::default();
        hot.x11 = true;
        hot.mounts = vec![test_mount("/source", "/target")];

        hot.process_x11_with_authority(PathBuf::from("~/.Xauthority"));
        let first = hot.mounts.clone();
        hot.process_x11_with_authority(PathBuf::from("~/.Xauthority"));

        assert_eq!(hot.mounts, first);
        assert_eq!(hot.mounts[0].target, PathBuf::from("/target"));
        assert_eq!(hot.mounts[1].target, PathBuf::from("/tmp/.X11-unix"));
        assert_eq!(hot.mounts[2].target, PathBuf::from("~/.Xauthority"));
    }

    #[test]
    fn test_hotconfig_process_x11_preserves_explicit_targets() {
        let mut hot = HotConfig::default();
        hot.x11 = true;
        hot.mounts = vec![
            test_mount("/custom-x11", "/tmp/.X11-unix"),
            test_mount("/custom-authority", "~/.Xauthority"),
        ];

        hot.process_x11_with_authority(PathBuf::from("~/.Xauthority"));

        assert_eq!(hot.mounts.len(), 2);
        assert_eq!(hot.mounts[0].source, PathBuf::from("/custom-x11"));
        assert_eq!(hot.mounts[1].source, PathBuf::from("/custom-authority"));
    }

    #[test]
    fn test_hotconfig_process_wayland_appends_socket_once() {
        let mut hot = HotConfig::default();
        hot.wayland = true;
        hot.process_wayland();
        let first = hot.mounts.clone();
        hot.process_wayland();

        assert_eq!(hot.mounts, first);
        assert_eq!(hot.mounts.len(), 1);
        assert!(hot.mounts[0].source.to_string_lossy().ends_with("wayland-0"));
        assert_eq!(hot.mounts[0].source, hot.mounts[0].target);
    }

    #[test]
    fn test_hotconfig_process_veth_dns_adds_aliases_once_and_preserves_explicit() {
        let mut hot = HotConfig::default();
        hot.dns.insert("peer.ns".to_owned(), "192.0.2.1".to_owned());
        hot.veth = vec![
            HotVeth {
                dst: "peer".to_owned(),
                dst_ip4: Some("192.0.2.2".parse().unwrap()),
                ..Default::default()
            },
            HotVeth {
                dst: "other".to_owned(),
                dst_ip4: Some("192.0.2.3".parse().unwrap()),
                ..Default::default()
            },
        ];

        hot.process_veth_dns();
        let first = hot.dns.clone();
        hot.process_veth_dns();

        assert_eq!(hot.dns, first);
        assert_eq!(hot.dns.get("peer.ns"), Some(&"192.0.2.1".to_owned()));
        assert_eq!(hot.dns.get("other.ns"), Some(&"192.0.2.3".to_owned()));
    }

    #[test]
    fn test_hotconfig_process_and_save_skips_unchanged_write() {
        let path = std::env::temp_dir().join(format!(
            "nsp3-hotconfig-test-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        let mut hot = HotConfig::default();
        hot.process_and_save(&path).unwrap();
        let inode = std::fs::metadata(&path).unwrap().ino();

        hot.process_and_save(&path).unwrap();

        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_hotconfig_merged_mounts_rejects_duplicate_targets() {
        let mut structured = HotConfig::default();
        structured.mounts = vec![
            test_mount("/source-a", "/same-target"),
            test_mount("/source-b", "/same-target"),
        ];
        assert!(structured.merged_mounts().is_err());

        let mut shorthand = HotConfig::default();
        shorthand
            .mounts
            .push(test_mount("/source-a", "/same-target"));
        shorthand
            .mnt
            .insert(PathBuf::from("/source-b"), PathBuf::from("/same-target"));
        assert!(shorthand.merged_mounts().is_err());

        let mut x11 = HotConfig::default();
        x11.x11 = true;
        x11.mnt.insert(
            PathBuf::from("/custom-x11"),
            PathBuf::from("/tmp/.X11-unix"),
        );
        x11.process_x11_with_authority(PathBuf::from("~/.Xauthority"));
        assert!(x11.merged_mounts().is_err());
    }
}

pub fn find_vacant_ipv4_subnet(
    mut used: Vec<Ipv4Addr>,
    net: Ipv4Network,
    host_bits: u8,
) -> Option<Ipv4Addr> {
    let first = net.nth(0).unwrap();
    let last = Ipv4Addr::from_bits(net.network().to_bits() | (!0 >> net.prefix()));
    used.push(first);
    used.push(last);
    used.sort();
    let bits: Vec<_> = used.iter().map(|x| x.to_bits() >> host_bits).collect();

    let mut ix = None;
    for x in 0..bits.len() - 1 {
        let diff = bits[x + 1] - bits[x];
        // need 2 consecutive vacant ips
        if diff > 1 {
            ix = Some(x);
            break;
        }
    }
    if let Some(ix) = ix {
        let start = bits[ix];
        let ip = start + 1;
        let ip = Ipv4Addr::from_bits(ip << host_bits);
        Some(ip)
    } else {
        None
    }
}

pub fn veth_addr_for(subnet: Ipv4Addr, host_bits: u8, host: bool) -> Ipv4Addr {
    Ipv4Addr::from_bits(subnet.to_bits() & !0 << host_bits | if host { 1 } else { 2 })
}

pub trait IpExt {
    fn next(&self) -> Self;
}

impl IpExt for Ipv4Addr {
    fn next(&self) -> Self {
        Ipv4Addr::from_bits(self.to_bits() + 1)
    }
}

impl NetlinkParseUpdate for RouteMessage {
    type Repr = RouteEntry;
    fn parse_update(&self, parsed: &mut Self::Repr) -> Result<()> {
        let make = |ip: RouteAddress| -> Result<Option<IpNetwork>> {
            let ip: Option<IpAddr> = match ip {
                RouteAddress::Inet(ip) => Some(ip.into()),
                RouteAddress::Inet6(ip) => Some(ip.into()),
                _ => None,
            };
            let ip = if let Some(ip) = ip {
                IpNetwork::new(ip, self.header.source_prefix_length)?.into()
            } else {
                None
            };

            Ok(ip)
        };

        for msg in &self.attributes {
            match msg {
                RouteAttribute::PrefSource(ip) => {
                    if let Some(ip) = make(ip.to_owned())? {
                        parsed.source_addrs.push(ip);
                    }
                }
                RouteAttribute::Destination(ip) => {
                    if let Some(ip) = make(ip.to_owned())? {
                        parsed.source_addrs.push(ip);
                    }
                }
                RouteAttribute::Table(t) => parsed.table = Some(*t),
                RouteAttribute::Oif(t) => parsed.oif = Some(*t),
                _ => (),
            }
        }

        Ok(())
    }
}

pub struct LinkDev {
    pub up: bool,
    pub index: u32,
    pub max_mtu: Option<u32>,
    pub kind: Option<InfoKind>,
    pub name: Option<String>,
}

impl NetlinkParse for LinkMessage {
    type Repr = LinkDev;
    fn parse(&self) -> Result<Self::Repr> {
        let up = self.header.flags & LinkFlags::Up != LinkFlags::empty();
        let index = self.header.index;
        let mut max_mtu = None;
        let mut kind = None;
        let mut name = None;
        for a in &self.attributes {
            match a {
                LinkAttribute::IfName(n) => name = Some(n.to_owned()),
                LinkAttribute::OperState(s) => match s {
                    _ => (),
                },
                LinkAttribute::LinkInfo(k) => {
                    for i in k {
                        match i {
                            LinkInfo::Kind(x) => {
                                kind = Some(x.to_owned());
                            }
                            _ => (),
                        }
                    }
                }
                LinkAttribute::MaxMtu(max) => {
                    max_mtu = Some(*max);
                }
                _ => {}
            }
        }

        Ok(LinkDev {
            up,
            index,
            max_mtu,
            kind,
            name,
        })
    }
}

pub fn tokio_netlink_conn() -> Result<Handle> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    Ok(handle)
}

pub fn smol_netlink_conn() -> Result<Handle> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    Ok(handle)
}

/// this trait might be useful 'cause we might have wrappers over Handle, and Handles typed over net ns
pub trait NetlinkOps {
    async fn fetch_routing_table(&self) -> Result<RoutingTable>;
    async fn fetch_link_by_name(&self, name: String) -> Result<LinkMessage>;
    async fn fetch_link_addrs(&self, index: u32) -> Result<AddressResponse>;
    async fn fetch_all_ip_addrs(&self) -> Result<Vec<IpNetwork>>;
    async fn add_veth(&self, name_a: &str, name_b: &str) -> Result<()>;
    async fn remove_link_if_exists(&self, name: &str) -> Result<()>;
    async fn add_route(&self, index: u32, pref_src: IpAddr, dst: IpAddr, prefix: u8) -> Result<()>;
    async fn ip_add_default_route(&self, index: u32) -> Result<()>;
    async fn test_route(&self, ip: IpAddr) -> Result<Option<RouteMessage>>;
    async fn up_lo(&self) -> Result<()>;
}

use tun2socks5::IArgs;
use tun2socks5::ipstack::TUNDev;
use tun2socks5::tun_rs::AsyncDevice;
use tun2socks5::tun_rs::DeviceBuilder;
use utils::MapExt;

use crate::shell::ShellArgs;
use crate::utils::dump_as_json;
use crate::utils::dump_as_toml;
use nsproxy_common::routing::{ProxyID, ProxyNym};

impl NetlinkOps for Handle {
    async fn fetch_routing_table(&self) -> Result<RoutingTable> {
        let m = RouteMessageBuilder::<IpAddr>::new().build();

        let mut k = self.route().get(m).execute();
        let mut table = RoutingTable::default();

        while let Some(msg) = k.try_next().await? {
            let mut entry = Default::default();
            msg.parse_update(&mut entry)?;
            if let Some(t) = &entry.table {
                table.tables.update(*t).push(entry);
            }
        }

        Ok(table)
    }
    async fn fetch_link_by_name(&self, name: String) -> Result<LinkMessage> {
        let mut links = self.link().get().match_name(name.into()).execute();
        if let Some(link) = links.try_next().await? {
            Ok(link)
        } else {
            bail!("can not find link")
        }
    }
    async fn fetch_link_addrs(&self, index: u32) -> Result<AddressResponse> {
        let mut addrs = self.address().get().set_link_index_filter(index).execute();
        let mut resp = AddressResponse::default();

        while let Some(msg) = addrs.try_next().await? {
            msg.parse_update(&mut resp)?;
        }

        Ok(resp)
    }
    async fn fetch_all_ip_addrs(&self) -> Result<Vec<IpNetwork>> {
        let mut addrs = self.address().get().execute();
        let mut res: Vec<IpNetwork> = Vec::new();

        while let Some(msg) = addrs.try_next().await? {
            let mut resp = AddressResponse::default();
            msg.parse_update(&mut resp)?;
            for ip in resp.addrs {
                res.push(ip);
            }
        }

        Ok(res)
    }
    async fn add_veth(&self, name: &str, peer: &str) -> Result<()> {
        // remove existing links with these names if they exist
        let _ = self.remove_link_if_exists(name).await;
        let _ = self.remove_link_if_exists(peer).await;

        self.link()
            .add(LinkVeth::new(name, peer).build())
            .execute()
            .await?;

        Ok(())
    }
    async fn remove_link_if_exists(&self, name: &str) -> Result<()> {
        warn!("removed obsolete device {}", name);
        let mut links = self.link().get().match_name(name.to_owned()).execute();
        if let Some(Some(link)) = links.try_next().await.ok() {
            self.link().del(link.header.index).execute().await?;
        }
        Ok(())
    }
    async fn add_route(&self, index: u32, pref_src: IpAddr, dst: IpAddr, prefix: u8) -> Result<()> {
        let route = RouteMessageBuilder::<IpAddr>::new()
            .destination(dst, prefix)?
            .output_interface(index)
            .pref_source(pref_src)?
            .build();
        self.route().add(route).execute().await?;
        Ok(())
    }
    async fn ip_add_default_route(&self, index: u32) -> Result<()> {
        let route = RouteMessageBuilder::<Ipv4Addr>::new()
            .output_interface(index)
            .build();
        self.route().add(route).execute().await?;
        let route = RouteMessageBuilder::<Ipv6Addr>::new()
            .output_interface(index)
            .build();
        self.route().add(route).execute().await?;
        Ok(())
    }
    async fn test_route(&self, ip: IpAddr) -> Result<Option<RouteMessage>> {
        let m = RouteMessageBuilder::<IpAddr>::new()
            .destination(ip, (ip.as_octets().len() * 8) as u8)?
            .build();
        let routes = self.route().get(m).execute();
        let vec: Vec<_> = routes.try_collect().await?;
        assert!(vec.len() <= 1);
        Ok(vec.get(0).cloned())
    }
    async fn up_lo(&self) -> Result<()> {
        let mut s = self.link().get().match_name("lo".to_owned()).execute();
        if let Some(lo) = s.next().await {
            let lo = lo?;
            self.link()
                .set(LinkUnspec::new_with_index(lo.header.index).up().build())
                .execute()
                .await?;
        }
        aok!()
    }
}

pub enum PidOrFd {
    Pid(u32),
    Fd(Box<dyn AsFd + Send + Sync>),
}
impl TunMaker {
    pub fn make(&self) -> Result<TunState> {
        let dev = DeviceBuilder::new()
            .name(self.name.to_owned())
            .ipv4(self.ipv4.ip(), self.ipv4.prefix(), None)
            .ipv6(self.ipv6.ip(), self.ipv6.prefix())
            .packet_information(false)
            .mtu(self.mtu)
            .build_async()?;

        Ok(TunState {
            name: self.name.to_owned(),
            fd: Some(dev.into()),
            ..Default::default()
        })
    }
    /// There isnt a need to call this method after make()
    /// Not sure which part changed the routing. Kernel default, or some lib.
    pub async fn add_route(&self, nl: &Handle, dev: &TUNDev) -> Result<()> {
        nl.add_route(
            dev.if_index()?,
            self.ipv4.ip().into(),
            self.ipv4.ip().into(),
            self.ipv4.prefix(),
        )
        .await?;

        Ok(())
    }
    pub async fn test_route(&self, nl: &Handle, state: &TunState) -> Result<bool> {
        let test_ip = self.ipv4.nth(2).unwrap();
        let re = nl.test_route(test_ip.into()).await?;
        let mut entry = RouteEntry::default();
        re.map(|m| m.parse_update(&mut entry));
        if !state.sync.basic_synced {
            bail!("TUN unsynced");
        }
        let test = entry.oif.map(|c| c == state.dev_index).unwrap_or_default();

        Ok(test)
    }
}

impl TunState {
    pub fn sync_basic(&mut self) -> Result<()> {
        if let Some(dev) = &self.fd {
            self.dev_index = dev.if_index()?;
            self.tun_is_up = dev.is_running()?;
            self.sync.basic_synced = true;
        }

        Ok(())
    }
}

impl Default for TunMaker {
    fn default() -> Self {
        Self {
            name: "tun1".to_owned(),
            ipv4: tun2socks5::dns::VIRT_TUN_IP4.try_into().unwrap(),
            ipv6: "fe80::bc2e:4aff:fe02:c223/64".try_into().unwrap(),
            mtu: 1500,
        }
    }
}

#[derive(Clone)]
pub struct PathState {
    root_config: PathBuf,
}

pub type Paths = Arc<PathState>;

pub trait PathsBinds {
    fn root(&self) -> PathBuf;
    fn mount(&self, ns: ExactNS) -> PathBuf;
    fn mount_user_space(&self, user_ns: ExactNS, ns: ExactNS) -> PathBuf;
    fn readable_config(&self) -> PathBuf;
    fn mount_private(&self) -> PathBuf;
    fn make_mount_point(&self, path: PathBuf) -> Result<()> {
        std::fs::File::create(&path)?;
        Ok(())
    }
    fn socket_server(&self) -> PathBuf {
        self.root().join("nsproxy.sock")
    }
}

use fs4::tokio::AsyncFileExt;

/// The entirety of persisted runtime state.
pub struct TotalConfig {
    fd: tokio::fs::File,
    path: Paths,
    data: Result<NsproxyConfig>,
}

#[derive(Deserialize, Clone, Serialize, Debug)]
pub struct NsproxyConfig {
    pub container: HashMap<String, Namespace>,
    pub veth: HashMap<String, VethConf>,
    pub link: Vec<LinkConf>,
}

#[derive(Deserialize, Clone, Serialize, Debug)]
pub struct LinkConf {
    pub global_route: bool,
    pub proxy: String,
    pub proxied: NSID,
    pub source: NSID,
}

#[derive(Deserialize, Clone, Debug, Serialize)]
pub struct Namespace {
    pub user: Option<NSID>,
    pub mnt: Option<NSID>,
    pub net: NSID,
}

#[derive(Deserialize, Clone, Debug, Serialize)]
pub struct VethConf {
    pub src_ip4: Ipv4Addr,
    pub dst_ip4: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NSID {
    PID(i32),
    Path(PathBuf),
}

impl<'d> Deserialize<'d> for NSID {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'d>,
    {
        use std::result::Result::Ok;
        UntaggedEnumVisitor::new()
            .string(|v| Ok(NSID::Path(PathBuf::from(v))))
            .i32(|v| Ok(NSID::PID(v)))
            .deserialize(deserializer)
    }
}

impl Serialize for NSID {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::PID(p) => serializer.serialize_i32(*p),
            Self::Path(p) => serializer.serialize_str(
                p.to_str()
                    .ok_or(serde::ser::Error::custom("path invalid"))?,
            ),
        }
    }
}

#[test]
fn test_untag() {
    #[derive(Deserialize, Debug, Serialize)]
    struct Example {
        k: NSID,
    }

    let sx: Example = toml_edit::de::from_str("k = \"sss/ssss\"").unwrap();
    dbg!(&sx);
    let sx: Example = toml_edit::de::from_str("k = 2").unwrap();
    dbg!(&sx);

    let sx: Namespace = toml_edit::de::from_str(
        r#"
            user = 3
            net = "/path/"
     "#,
    )
    .unwrap();
    dbg!(&sx);

    let sx = toml_edit::ser::to_string_pretty(&Example {
        k: NSID::Path(PathBuf::from("/test")),
    });
    dbg!(&sx);

    let sx: NsproxyConfig = toml_edit::de::from_str(
        r#"
            [container.geph]
            net = "/run/1.ns"
            [veth.geph]
            src_ip4 = "1.1.1.1"
            [[link]]
            global_route = false
            proxy = "socks5"
            proxied = 2
            source = 3
     "#,
    )
    .unwrap();
    dbg!(&sx);

    let sx = toml_edit::ser::to_string_pretty(&sx);
    println!("{}", sx.unwrap());
}

impl TotalConfig {
    pub async fn new(path: Paths) -> Result<TotalConfig> {
        let mut c = TotalConfig {
            fd: fs::File::open(path.readable_config()).await?,
            path,
            data: Err(anyhow!("not loaded")),
        };
        let re = c.fd.try_lock_exclusive()?;
        if re {
            Ok(c)
        } else {
            tracing::error!("config file locked.. waiting");
            let f = c.fd.unlock_async();
            let k: std::result::Result<
                std::result::Result<(), std::io::Error>,
                tokio::time::error::Elapsed,
            > = timeout(Duration::from_secs(20), f).await;
            match k {
                Result::Ok(_) => {}
                Err(_) => {
                    bail!("timeout reached");
                }
            }
            let mut buf = Vec::with_capacity(4096);
            c.fd.read_to_end(&mut buf).await?;
            c.data = Ok(toml_edit::de::from_slice(&buf)?);
            Ok(c)
        }
    }
    pub async fn save(&mut self) {}
}

impl PathsBinds for Paths {
    fn root(&self) -> PathBuf {
        self.root_config.clone()
    }
    fn mount(&self, ns: ExactNS) -> PathBuf {
        self.root_config.join(ns.unique.to_string() + ".ns")
    }
    fn mount_private(&self) -> PathBuf {
        self.root_config.join("priv_mnt")
    }
    fn mount_user_space(&self, user_ns: ExactNS, ns: ExactNS) -> PathBuf {
        self.mount_private()
            .join(user_ns.unique.to_string() + ".user")
            .join(ns.unique.to_string() + ".ns")
    }
    fn readable_config(&self) -> PathBuf {
        self.root_config.join("nsproxyd.toml")
    }
}

pub macro aok {
    () => {
        ::core::result::Result::Ok::<(), anyhow::Error>(())
    },
    (#ty:ty) => {
        Ok::<#ty, anyhow::Error>(())
    }
}

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Eq, Debug)]
pub enum HotRoute {
    /// No explicit runtime route is configured.
    #[default]
    None,
    /// Route all normal proxyable traffic through one specific uplink proxy.
    SimpleProxy { proxy_id: ProxyID },
}

impl HotRoute {}

/// An application that can be launched on demand from a profile's Actions UI.
/// Unlike `daemons`, applications are never started implicitly on reload.
#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq, Eq)]
pub struct LaunchableApp {
    /// Stable, profile-local identifier shown in the Actions UI.
    pub name: String,
    /// Optional user-facing summary of the application.
    #[serde(default)]
    pub description: String,
    /// Process command and identity used for the managed launch.
    #[serde(default)]
    pub command: ShellArgs,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq, Eq)]
pub struct HotConfig {
    /// Commands Virtual DNS to directly A to B
    pub dns: HashMap<String, String>,
    /// Bind the host X11 socket and Xauthority file into the sandbox.
    #[serde(default)]
    pub x11: bool,
    /// Bind the host Wayland display socket into the sandbox.
    #[serde(default)]
    pub wayland: bool,
    /// NAT by TUN
    pub tun: HashMap<String, Value>,
    /// Map devs from a mac address (or interface name) to an IP address
    /// This commands nsproxy to move the devices into the new namespace
    /// And assign them with the provided IP addresses
    pub devs: HashMap<String, String>,
    /// Bind mounts
    pub mnt: HashMap<PathBuf, PathBuf>,
    /// Mapping of localhost:port in container to localhost:port outside container
    pub locals: HashMap<u32, u32>,
    /// Networks whose DNS traffic should be intercepted.
    /// When absent or empty, all IPs are captured.
    #[serde(default)]
    pub dns_capture: HashSet<IpNetwork>,
    /// Nameserver written into `/etc/resolv.conf` inside the running namespace.
    #[serde(default = "default_resolv_conf_dns")]
    pub resolv_conf_dns: String,
    /// Persisted live routing selection for the running serve process.
    #[serde(default)]
    pub route: HotRoute,
    /// Mnt but with full parameters
    #[serde(default)]
    pub mounts: Vec<ProfileMount>,
    /// Daemon processes to run inside the container on startup or reload.
    #[serde(default)]
    pub daemons: Vec<ShellArgs>,
    /// Applications that may be launched manually from the Actions tab.
    #[serde(default)]
    pub applications: Vec<LaunchableApp>,
    /// Veth pairs to create whenever this profile's container starts.
    #[serde(default)]
    pub veth: Vec<HotVeth>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq, Eq)]
pub struct HotVeth {
    #[serde(default = "default_veth_source")]
    pub src: String,
    #[serde(alias = "peer")]
    pub dst: String,
    #[serde(default, alias = "name")]
    pub veth_name: Option<String>,
    #[serde(default)]
    pub src_ip4: Option<Ipv4Addr>,
    #[serde(default)]
    pub dst_ip4: Option<Ipv4Addr>,
    #[serde(default = "default_veth_prefix_len")]
    pub prefix_len: u8,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct VethStatus {
    pub spec: HotVeth,
    pub success: bool,
    pub detail: String,
    pub updated_at_secs: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct VethStatusSnapshot {
    pub entries: Vec<VethStatus>,
}

fn default_veth_source() -> String {
    "basis".to_owned()
}

fn default_veth_prefix_len() -> u8 {
    30
}

pub fn default_hotconfig() -> HotConfig {
    HotConfig {
        resolv_conf_dns: INTERNAL_RESOLV_CONF_DNS.to_owned(),
        ..Default::default()
    }
}

#[derive(Clone, Debug, Default)]
pub struct PathExpansionState {
    instance_root: Option<PathBuf>,
    home: Option<PathBuf>,
    pub src_chroot: Option<PathBuf>,
    pub dst_chroot: Option<PathBuf>,
}

impl PathExpansionState {
    pub fn for_instance(instance_root: &Path) -> Self {
        Self {
            instance_root: Some(instance_root.to_path_buf()),
            home: std::env::var_os("HOME").map(PathBuf::from),
            ..Default::default()
        }
    }

    pub fn without_instance() -> Self {
        Self {
            instance_root: None,
            home: std::env::var_os("HOME").map(PathBuf::from),
            ..Default::default()
        }
    }

    pub fn with_src_chroot(mut self, src: &Path) -> Self {
        self.src_chroot = Some(src.to_path_buf());
        self
    }

    pub fn with_dst_chroot(mut self, dst: &Path) -> Self {
        self.dst_chroot = Some(dst.to_path_buf());
        self
    }

    /// Expand variables in `path` and, if `src_chroot` is set, relocate the
    /// resulting absolute path underneath it.
    pub fn expand_source(&self, path: &Path) -> PathBuf {
        let expanded = self.expand(path);
        if let Some(ref chroot) = self.src_chroot {
            if expanded.is_absolute() {
                let rel = expanded.strip_prefix("/").unwrap_or(&expanded);
                return chroot.join(rel);
            }
        }
        expanded
    }

    /// Expand variables in `path` and, if `dst_chroot` is set, resolve the
    /// result relative to that chroot root.
    pub fn expand_target(&self, path: &Path) -> PathBuf {
        let expanded = self.expand(path);
        if let Some(ref chroot) = self.dst_chroot {
            let rel = expanded.strip_prefix("/").unwrap_or(&expanded);
            return chroot.join(rel);
        }
        expanded
    }

    pub fn is_instance_variable(path: &Path) -> bool {
        let Some(path_str) = path.to_str() else {
            return false;
        };
        path_str == "@" || path_str.starts_with("@/") || path_str.starts_with('@')
    }

    pub fn is_home_variable(path: &Path) -> bool {
        let Some(path_str) = path.to_str() else {
            return false;
        };
        path_str == "~" || path_str.starts_with("~/")
    }

    pub fn expand(&self, path: &Path) -> PathBuf {
        let Some(path_str) = path.to_str() else {
            return path.to_path_buf();
        };

        if path_str == "~" {
            if let Some(home) = &self.home {
                return home.clone();
            }
            return path.to_path_buf();
        }

        if let Some(rest) = path_str.strip_prefix("~/") {
            if let Some(home) = &self.home {
                return home.join(rest);
            }
            return path.to_path_buf();
        }

        if let Some(root) = &self.instance_root {
            if path_str == "@" {
                return root.clone();
            }

            if let Some(rest) = path_str.strip_prefix("@/") {
                return root.join(rest);
            }

            if path_str.starts_with('@') {
                let root_str = root.to_string_lossy();
                return PathBuf::from(path_str.replace('@', &root_str));
            }
        }

        path.to_path_buf()
    }
}

fn is_absolute_or_variable(path: &Path, allow_home: bool, allow_instance: bool) -> bool {
    path.is_absolute()
        || (allow_home && PathExpansionState::is_home_variable(path))
        || (allow_instance && PathExpansionState::is_instance_variable(path))
}

impl HotConfig {
    /// Normalize convenience fields into the explicit runtime configuration.
    /// This is idempotent; explicit entries take precedence over generated ones.
    pub fn process(&mut self) {
        self.process_x11();
        self.process_wayland();
        self.process_veth_dns();
    }

    /// Normalize and persist this configuration as one atomic file replacement.
    pub fn process_and_save(&mut self, path: &Path) -> Result<()> {
        self.process();
        let json = serde_json::to_vec_pretty(self)?;
        write_file_atomic(path, &json)
    }

    pub fn expand_placeholders(&mut self, instance_root: &Path) {
        let vars = PathExpansionState::for_instance(instance_root);
        self.expand_with(&vars);
    }

    pub fn expand_with(&mut self, vars: &PathExpansionState) {
        let mut expanded_mnt = HashMap::new();
        for (source, target) in &self.mnt {
            expanded_mnt.insert(vars.expand(source), vars.expand(target));
        }
        self.mnt = expanded_mnt;

        for mount in &mut self.mounts {
            mount.source = vars.expand(&mount.source);
            mount.target = vars.expand(&mount.target);
        }

        for daemon in &mut self.daemons {
            if let Some(cwd) = daemon.cwd.clone() {
                daemon.cwd = Some(vars.expand(&cwd));
            }
            if let Some(shell) = daemon.shell.clone() {
                let shell_path = PathBuf::from(&shell);
                if PathExpansionState::is_home_variable(&shell_path)
                    || PathExpansionState::is_instance_variable(&shell_path)
                {
                    daemon.shell = Some(vars.expand(&shell_path).to_string_lossy().to_string());
                }
            }
        }
    }

    /// Compile the X11 convenience flag into explicit mount entries.
    /// This is idempotent; explicit mounts take precedence over generated ones.
    pub fn process_x11(&mut self) {
        if !self.x11 {
            return;
        }

        let xauthority = match std::env::var_os("XAUTHORITY") {
            Some(path) if !path.is_empty() => {
                let path = PathBuf::from(path);
                if !path.is_file() {
                    warn!(
                        path = %path.display(),
                        "X11 is enabled but XAUTHORITY does not point to a readable file"
                    );
                }
                path
            }
            Some(_) => {
                warn!("X11 is enabled but XAUTHORITY is empty; falling back to ~/.Xauthority");
                PathBuf::from("~/.Xauthority")
            }
            None => {
                warn!("X11 is enabled but XAUTHORITY is unset; falling back to ~/.Xauthority");
                PathBuf::from("~/.Xauthority")
            }
        };
        self.process_x11_with_authority(xauthority);
    }

    /// Compile the Wayland convenience flag into an explicit socket mount.
    /// This is idempotent; explicit mounts take precedence over the generated one.
    pub fn process_wayland(&mut self) {
        if !self.wayland {
            return;
        }

        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", unsafe {
                libc::getuid()
            })));
        let display = std::env::var_os("WAYLAND_DISPLAY")
            .filter(|name| !name.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("wayland-0"));
        let socket = if display.is_absolute() {
            display
        } else {
            runtime_dir.join(display)
        };

        let mount = ProfileMount {
            source: socket.clone(),
            target: socket,
            read_only: false,
            recursive: false,
            skip_missing: true,
        };
        if !self
            .mounts
            .iter()
            .any(|existing| existing.target == mount.target)
        {
            self.mounts.push(mount);
        }
    }

    /// Add DNS aliases for configured VETH endpoints in target namespaces.
    /// Explicit DNS entries take precedence over generated aliases.
    pub fn process_veth_dns(&mut self) {
        for veth in &self.veth {
            let (Some(ip), false) = (veth.dst_ip4, veth.dst.is_empty()) else {
                continue;
            };
            self.dns
                .entry(format!("{}.ns", veth.dst))
                .or_insert_with(|| ip.to_string());
        }
    }

    fn process_x11_with_authority(&mut self, xauthority: PathBuf) {
        let x11_mounts = [
            ProfileMount {
                source: PathBuf::from("/tmp/.X11-unix"),
                target: PathBuf::from("/tmp/.X11-unix"),
                read_only: false,
                recursive: true,
                skip_missing: true,
            },
            ProfileMount {
                source: xauthority.clone(),
                target: xauthority,
                read_only: false,
                recursive: false,
                skip_missing: true,
            },
        ];

        for mount in x11_mounts {
            if !self
                .mounts
                .iter()
                .any(|existing| existing.target == mount.target)
            {
                self.mounts.push(mount);
            }
        }
    }

    /// Merge explicit mounts with shorthand `mnt` entries.
    /// Errors on duplicate target paths.
    pub fn merged_mounts(&self) -> Result<Vec<ProfileMount>> {
        let mut merged = Vec::with_capacity(self.mounts.len() + self.mnt.len());
        let mut seen_targets: HashSet<PathBuf> = HashSet::new();

        for mount in &self.mounts {
            ensure!(
                seen_targets.insert(mount.target.clone()),
                "duplicate mount target: {:?}",
                mount.target
            );
            merged.push(mount.clone());
        }

        for (source, target) in &self.mnt {
            ensure!(
                seen_targets.insert(target.clone()),
                "duplicate mount target: {:?}",
                target
            );
            merged.push(ProfileMount {
                source: source.clone(),
                target: target.clone(),
                read_only: false,
                recursive: true,
                skip_missing: false,
            });
        }

        Ok(merged)
    }

    /// Returns true if the given IP's DNS traffic should be intercepted.
    /// An empty `dns_capture` set means "capture all".
    pub fn captures_dns(&self, ip: IpAddr) -> bool {
        self.dns_capture.is_empty() || self.dns_capture.iter().any(|net| net.contains(ip))
    }

    pub fn dns_capture_enabled(&self) -> bool {
        self.dns_capture
            .iter()
            .all(|net| net != &"0.0.0.0/32".parse().unwrap())
    }

    pub fn set_dns_capture_enabled(&mut self, enabled: bool) {
        if enabled {
            self.dns_capture.clear();
        } else {
            self.disable_dns_capture();
        }
    }

    /// Override `dns_capture` with a sentinel that matches no real IP,
    /// effectively disabling DNS interception entirely.
    pub fn disable_dns_capture(&mut self) {
        self.dns_capture = ["0.0.0.0/32".parse().unwrap()].into();
    }

    /// Serialize and persist this config to `path`.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_vec_pretty(self)?;
        write_file_atomic(path, &json)
    }
}

/// Replace a file atomically using a temporary file in the same directory.
pub fn write_file_atomic(path: &Path, content: &[u8]) -> Result<()> {
    match std::fs::read(path) {
        Ok(existing) if existing == content => return Ok(()),
        Ok(_) | Err(_) => {}
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("path has no parent: {}", path.display()))?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let existing_mode = std::fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions().mode());
    let temporary = parent.join(format!(
        ".{}.tmp.{}.{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id(),
        stamp
    ));

    let result = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        if let Some(mode) = existing_mode {
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        file.write_all(content)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

// [schema-bump] To add schema VN:
//   1. Rename this type alias to point at `TemplateConfigVN` — the compiler
//      will flag every struct literal that has stale/missing fields.
//   2. Freeze the current `TemplateConfigV2` (remove `pub` fields you want
//      hidden, keep it `Deserialize`-only).
//   3. Add `TemplateConfigVN` with the new shape + `VERSION` const.
//   4. Add `From<TemplateConfigV(N-1)> for TemplateConfigVN`.
//   5. Add the new arm in `TemplateConfig::load()`.
//   6. In nsproxy-ui/src/main.rs search `[schema-bump:wizard]` for the
//      wizard factory sites.
pub type TemplateConfig = TemplateConfigV2;

/// Explicit, stable profile config for filesystem isolation and app launch
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct TemplateConfigV2 {
    /// Schema version for compatibility checks
    pub schema: u32,
    /// Filesystem isolation mode
    pub sandbox_mode: SandboxMode,
    /// Explicit bind mounts, in order
    pub mounts: Vec<ProfileMount>,
    /// Optional chmod operations to apply after mounts
    #[serde(default)]
    pub chmod: Vec<ProfileChmod>,
    /// Environment variables (overrides if inherit_env=true, replaces if false)
    pub env: HashMap<String, String>,
    /// Inherit parent environment and apply env as overrides (default: true)
    #[serde(default = "default_inherit_env")]
    pub inherit_env: bool,
    /// Hot config JSON path (frequently changed)
    pub hot: PathBuf,
    /// Initialize hot config with these values if missing
    #[serde(default)]
    pub hot_init: Option<HotConfig>,
    /// Explicit shell argument overrides
    #[serde(default)]
    pub sargs: ShellArgs,
    /// Browser profile name for env isolation (set NSPROXY_PROFILE_BROWSER)
    #[serde(default)]
    pub browser_profile: Option<String>,
    /// D-Bus exposure mode. Schema 2+; Container is the absent-field default.
    #[serde(default)]
    pub dbus: DbusMode,
    #[serde(default)]
    pub rootfs: Rootfs,
}

impl TemplateConfigV2 {
    pub const VERSION: u32 = 2;
}

/// Schema-1 profile config. The `dbus` field was a plain `bool`:
/// `true` = run a private container D-Bus daemon, `false`/absent = host bus inherited.
/// Used only for deserializing legacy configs inside `TemplateConfig::load()`.
#[derive(Deserialize)]
struct TemplateConfigV1 {
    #[serde(default = "schema_one")]
    schema: u32,
    sandbox_mode: SandboxMode,
    #[serde(default)]
    mounts: Vec<ProfileMount>,
    #[serde(default)]
    chmod: Vec<ProfileChmod>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default = "default_inherit_env")]
    inherit_env: bool,
    hot: PathBuf,
    #[serde(default)]
    hot_init: Option<HotConfig>,
    #[serde(default)]
    sargs: ShellArgs,
    #[serde(default)]
    browser_profile: Option<String>,
    /// false/absent = Pass (host env inherited), true = Container (private daemon)
    #[serde(default)]
    dbus: bool,
    #[serde(default)]
    rootfs: Rootfs,
}

impl TemplateConfigV1 {
    const VERSION: u32 = 1;
}

fn schema_one() -> u32 {
    TemplateConfigV1::VERSION
}

impl From<TemplateConfigV1> for TemplateConfigV2 {
    fn from(v1: TemplateConfigV1) -> Self {
        TemplateConfigV2 {
            schema: TemplateConfigV2::VERSION,
            sandbox_mode: v1.sandbox_mode,
            mounts: v1.mounts,
            chmod: v1.chmod,
            env: v1.env,
            inherit_env: v1.inherit_env,
            hot: v1.hot,
            hot_init: v1.hot_init,
            sargs: v1.sargs,
            browser_profile: v1.browser_profile,
            // false/absent → Pass (legacy: host bus was inherited through adjust())
            // true          → Container (private daemon is spawned)
            dbus: if v1.dbus {
                DbusMode::Container
            } else {
                DbusMode::Pass
            },
            rootfs: v1.rootfs,
        }
    }
}

/// Controls how the session D-Bus is exposed inside the container.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DbusMode {
    /// Block D-Bus: strip DBUS_SESSION_BUS_ADDRESS from the spawn environment.
    Block,
    /// Pass the host session bus through directly (risky — host services reachable).
    Pass,
    /// Legacy private-proxy mode. It is retained for configuration compatibility
    /// but intentionally starts no service and exposes no session bus.
    Proxy,
    /// Run one private `dbus-daemon` session bus inside the container.
    #[default]
    Container,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub enum Rootfs {
    #[default]
    /// Mount it at default nsp3 state path
    Default,
    /// Mount rootfs in tmpfs, ie. in memory
    Tempfs,
    Path(PathBuf),
}

impl Default for TemplateConfigV2 {
    fn default() -> Self {
        Self {
            schema: TemplateConfigV2::VERSION,
            sandbox_mode: SandboxMode::Overlay,
            mounts: Vec::new(),
            chmod: Vec::new(),
            env: HashMap::new(),
            inherit_env: true,
            hot: PathBuf::from("@/hot.json"),
            hot_init: Some(default_hotconfig()),
            sargs: ShellArgs::default(),
            browser_profile: None,
            dbus: DbusMode::Container,
            rootfs: Rootfs::Default,
        }
    }
}

fn default_inherit_env() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum SandboxMode {
    /// Keep current root, layer bind-mounts onto it.
    Overlay,
    /// Replace root via pivot_root(2) with a fresh tmpfs, old root at /pivot.
    Pivot,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ProfileMount {
    /// Host path
    pub source: PathBuf,
    /// Target path inside the container root
    pub target: PathBuf,
    /// Mount read-only (default: false)
    #[serde(default)]
    pub read_only: bool,
    /// Mount recursively (default: true)
    #[serde(default = "default_recursive")]
    pub recursive: bool,
    /// Allow the mount to be skipped if src is missing
    #[serde(default)]
    pub skip_missing: bool,
}

/// Permission/ownership operation to apply inside the container root
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ProfileChmod {
    /// Target path inside the container root
    pub path: PathBuf,
    /// Mode bits (e.g. 0o755)
    pub mode: Option<u32>,
    /// Owner uid
    pub uid: Option<u32>,
    /// Owner gid
    pub gid: Option<u32>,
    /// Create it as directory if non existent
    #[serde(default)]
    pub mkdir: bool,
}

fn default_recursive() -> bool {
    true
}

impl TemplateConfig {
    pub fn load(path: &Path) -> Result<TemplateConfig> {
        create_dir_all(state_paths::persist_root())?;
        let content = std::fs::read_to_string(path)?;
        // Peek at schema to select the right versioned struct for deserialization.
        // Missing schema field defaults to 1 (legacy).
        let schema: u32 = serde_json::from_str::<serde_json::Value>(&content)?
            .get("schema")
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u32;
        // [schema-bump] add new arms here (oldest first); exhaustive match
        // ensures every version is explicitly handled.
        let conf = match schema {
            s if s < TemplateConfigV2::VERSION => {
                // V1: dbus was a plain bool. Migrate via TemplateConfigV1 → TemplateConfigV2.
                TemplateConfigV2::from(serde_json::from_str::<TemplateConfigV1>(&content)?)
            }
            _ => serde_json::from_str::<TemplateConfigV2>(&content)?,
        };
        conf.validate()?;
        Ok(conf)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema > 0, "schema must be > 0");
        if let Some(ref cwd) = self.sargs.cwd {
            ensure!(cwd.is_absolute(), "sargs.cwd must be absolute");
        }
        ensure!(
            is_absolute_or_variable(&self.hot, true, true),
            "hot must be absolute or use ~/@ placeholder"
        );
        for m in &self.mounts {
            ensure!(
                is_absolute_or_variable(&m.source, true, true),
                "mount source must be absolute or use ~/@ placeholder"
            );
            ensure!(
                is_absolute_or_variable(&m.target, true, true),
                "mount target must be absolute or use ~/@ placeholder"
            );
        }
        for c in &self.chmod {
            ensure!(
                is_absolute_or_variable(&c.path, true, true),
                "chmod path must be absolute or use ~/@ placeholder"
            );
        }
        Ok(())
    }

    /// Expand path variables to concrete paths.
    ///
    /// Supported variables:
    /// - `@` for instance config root (/nsp3/config/{name})
    /// - `~` for HOME
    pub fn expand_placeholders(&mut self, instance_root: &Path) {
        let vars = PathExpansionState::for_instance(instance_root);

        self.hot = vars.expand(&self.hot);

        for m in &mut self.mounts {
            m.source = vars.expand(&m.source);
            m.target = vars.expand(&m.target);
        }

        if let Some(cwd) = &self.sargs.cwd {
            self.sargs.cwd = Some(vars.expand(cwd));
        }

        for c in &mut self.chmod {
            c.path = vars.expand(&c.path);
        }

        if let Some(ref mut hot_init) = self.hot_init {
            hot_init.expand_with(&vars);
        }
    }

    pub fn template(name: &str, hot_path: &Path) -> Result<TemplateConfig> {
        use nix::unistd::getresuid;
        use nsproxy_common::UID_HINT_VAR;
        use std::result::Result::Ok;
        use uzers::os::unix::UserExt;

        // Detect UID the same way ShellArgs does
        let uid = if let Ok(id) = std::env::var(UID_HINT_VAR) {
            id.parse()?
        } else if let Ok(id) = std::env::var("SUDO_UID") {
            id.parse()?
        } else {
            let res = getresuid()?;
            if !res.real.is_root() {
                res.real.as_raw()
            } else if let Ok(kde) = std::env::var("KDE_SESSION_UID") {
                kde.parse()?
            } else {
                1000 // fallback
            }
        };

        let user = uzers::get_user_by_uid(uid)
            .ok_or_else(|| anyhow!("cannot find user for uid {}", uid))?;

        let shell = user.shell().to_owned();
        let shell_path = PathBuf::from(shell);
        let shell_str = shell_path
            .to_str()
            .ok_or_else(|| anyhow!("invalid shell path"))?
            .to_string();

        let gid = user.primary_group_id();
        let gids: Vec<u32> = user
            .groups()
            .unwrap_or_default()
            .iter()
            .map(|g| g.gid())
            .collect();

        Ok(TemplateConfig {
            schema: TemplateConfigV2::VERSION,
            sandbox_mode: SandboxMode::Overlay,
            mounts: vec![],
            env: HashMap::new(),
            inherit_env: true,
            hot: hot_path.to_path_buf(),
            hot_init: Some(default_hotconfig()),
            sargs: ShellArgs {
                uid: Some(uid),
                gid: Some(gid),
                gids: gids,
                shell: Some(shell_str),
                cwd: Some(user.home_dir().to_path_buf()),
                args: Vec::new(),
            },
            chmod: Vec::new(),
            browser_profile: None,
            dbus: DbusMode::Container,
            rootfs: Rootfs::Default,
        })
    }
}

/// Configuration for binaries that must be wrapped for security
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub struct WrappedBinariesConfig {
    /// List of absolute paths to binaries that must be wrapped
    pub binaries: Vec<PathBuf>,
    /// Cached BLAKE3 hash of nswrap binary
    pub nswrap_hash: Option<String>,
}

impl WrappedBinariesConfig {
    pub fn path() -> PathBuf {
        <Self as state_blueprint::PersistentState>::path()
    }

    pub fn load() -> Result<Self> {
        <Self as state_blueprint::PersistentState>::load_or_default()
    }

    pub fn save(&self) -> Result<()> {
        <Self as state_blueprint::PersistentState>::save_atomic(self)
    }

    /// Add a binary by name (resolves via which) and save
    pub fn add_binary(&mut self, name: &str) -> Result<PathBuf> {
        let resolved_path = which::which(name)?;

        if self.binaries.contains(&resolved_path) {
            info!("Binary {:?} already in config", resolved_path);
            return Ok(resolved_path);
        }

        self.binaries.push(resolved_path.clone());
        self.save()?;
        info!("Added {:?} to wrapped binaries config", resolved_path);
        Ok(resolved_path)
    }

    /// Compute BLAKE3 hash of a file
    fn compute_file_hash(path: &Path) -> Result<String> {
        let mut file = std::fs::File::open(path)?;
        let mut hasher = blake3::Hasher::new();
        std::io::copy(&mut file, &mut hasher)?;
        Ok(hasher.finalize().to_hex().to_string())
    }

    /// Get the expected nswrap hash (from cache or by computing)
    /// This will compute and cache the hash if not present
    pub fn get_or_compute_nswrap_hash(&mut self) -> Result<String> {
        if let Some(ref hash) = self.nswrap_hash {
            return Ok(hash.clone());
        }

        let nswrap_path = std::env::current_exe()?
            .parent()
            .ok_or_else(|| anyhow!("Cannot get parent directory of current exe"))?
            .join("nswrap");

        if !nswrap_path.exists() {
            bail!("nswrap binary not found at {:?}", nswrap_path);
        }

        let hash = Self::compute_file_hash(&nswrap_path)?;
        self.nswrap_hash = Some(hash.clone());
        self.save()?;
        Ok(hash)
    }

    pub fn update_nswrap_hash(&mut self) -> Result<String> {
        let nswrap_path = std::env::current_exe()?
            .parent()
            .ok_or_else(|| anyhow!("Cannot get parent directory of current exe"))?
            .join("nswrap");

        if !nswrap_path.exists() {
            bail!("nswrap binary not found at {:?}", nswrap_path);
        }

        let hash = Self::compute_file_hash(&nswrap_path)?;
        self.nswrap_hash = Some(hash.clone());
        self.save()?;
        Ok(hash)
    }

    /// Check if all configured binaries are properly wrapped
    /// Requires cached hash - will not compute it
    pub fn check_all_wrapped(&self) -> Result<()> {
        if self.binaries.is_empty() {
            return Ok(());
        }

        let expected_hash = self.nswrap_hash.as_ref().ok_or_else(|| {
            anyhow!("No cached nswrap hash found. Run 'sp wrap' first to initialize.")
        })?;

        let mut errors = Vec::new();

        for binary_path in &self.binaries {
            if let Err(e) = self.check_single_wrapped(binary_path, expected_hash) {
                errors.push(format!("{:?}: {}", binary_path, e));
            }
        }

        if !errors.is_empty() {
            bail!("Wrapped binaries check failed:\n{}", errors.join("\n"));
        }

        Ok(())
    }

    /// Check if a single binary is properly wrapped
    pub fn check_single_wrapped(&self, binary_path: &Path, expected_hash: &str) -> Result<()> {
        let wrapped_path = binary_path.with_extension("wrapped");

        if !wrapped_path.exists() {
            bail!("missing .wrapped file");
        }

        if !binary_path.exists() {
            bail!("binary does not exist");
        }

        // Verify the binary at binary_path has the expected nswrap hash
        let actual_hash = Self::compute_file_hash(binary_path)?;
        if actual_hash != expected_hash {
            bail!(
                "hash mismatch: expected {} but got {}",
                expected_hash,
                actual_hash
            );
        }

        Ok(())
    }

    /// Wrap all configured binaries
    pub fn wrap_all(&mut self) -> Result<()> {
        if self.binaries.is_empty() {
            warn!("No binaries configured for wrapping");
            return Ok(());
        }

        let nswrap_path = std::env::current_exe()?
            .parent()
            .ok_or_else(|| anyhow!("Cannot get parent directory of current exe"))?
            .join("nswrap");

        if !nswrap_path.exists() {
            bail!("nswrap binary not found at {:?}", nswrap_path);
        }

        // Compute and cache the hash
        let _ = self.get_or_compute_nswrap_hash()?;

        info!("Wrapping {} binaries...", self.binaries.len());

        // Clone the list to avoid borrow checker issues
        let binaries = self.binaries.clone();
        for binary_path in &binaries {
            self.wrap_single(binary_path, &nswrap_path)?;
        }

        info!("All binaries wrapped successfully");
        Ok(())
    }

    /// Wrap a single binary
    fn wrap_single(&mut self, binary_path: &Path, nswrap_path: &Path) -> Result<()> {
        if !binary_path.exists() {
            bail!("Binary {:?} does not exist", binary_path);
        }

        let wrapped_path = binary_path.with_extension("wrapped");

        if wrapped_path.exists() {
            // Already wrapped, verify it's correct
            let expected_hash = self.get_or_compute_nswrap_hash()?;
            let check_result = self.check_single_wrapped(binary_path, &expected_hash);
            match check_result {
                Ok(_) => {
                    info!("Binary {:?} already properly wrapped", binary_path);
                    return Ok(());
                }
                Err(_) => {
                    warn!(
                        "Binary {:?} is wrapped but check failed. Re-wrapping...",
                        binary_path
                    );
                    // Remove the bad wrapped file and re-wrap
                    std::fs::remove_file(binary_path)?;
                    std::fs::rename(&wrapped_path, binary_path)?;
                }
            }
        }

        info!("Wrapping binary: {:?}", binary_path);
        std::fs::rename(binary_path, &wrapped_path)?;
        std::fs::copy(nswrap_path, binary_path)?;

        Ok(())
    }

    /// Unwrap all configured binaries
    pub fn unwrap_all(&mut self) -> Result<()> {
        if self.binaries.is_empty() {
            warn!("No binaries configured for unwrapping");
            return Ok(());
        }

        info!("Unwrapping {} binaries...", self.binaries.len());

        // Clone the list to avoid borrow checker issues
        let binaries = self.binaries.clone();
        for binary_path in &binaries {
            self.unwrap_single(binary_path)?;
        }

        // Clear cached hash after unwrapping
        self.nswrap_hash = None;
        self.save()?;

        info!("All binaries unwrapped successfully");
        Ok(())
    }

    /// Unwrap a single binary
    fn unwrap_single(&self, binary_path: &Path) -> Result<()> {
        let wrapped_path = binary_path.with_extension("wrapped");

        if !wrapped_path.exists() {
            info!("Binary {:?} not wrapped", binary_path);
            return Ok(());
        }

        info!("Unwrapping binary: {:?}", binary_path);

        if binary_path.exists() {
            std::fs::remove_file(binary_path)?;
        }

        std::fs::rename(&wrapped_path, binary_path)?;

        Ok(())
    }
}

impl state_blueprint::PersistentState for WrappedBinariesConfig {
    const STATE_NAME: &'static str = "wrapped_binaries";

    fn path() -> PathBuf {
        state_paths::wrapped_binaries_config()
    }
}

use clap::{
    Parser, Subcommand, ValueEnum,
    builder::{TypedValueParser, ValueParser, ValueParserFactory},
};

/// NSProxy V3
/// Manage netns redirection with SOCKS5 proxy configuration
#[derive(Parser, Debug, Serialize, Deserialize)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long)]
    pub conf: Option<PathBuf>,
    /// State root, defaults to /nsp3
    #[arg(short, long)]
    pub root: Option<PathBuf>,
    #[arg(short, long)]
    pub no_wrap_check: bool,
    /// UI control socket path.  When set the process connects to this socket on
    /// startup and sends a `ControlSocketGreeting` frame so the UI can receive
    /// events without waiting to poll its own outgoing connection.
    #[arg(long, hide = true)]
    pub control_socket: Option<PathBuf>,
    #[command(subcommand)]
    pub cmd: MainCommand,
}

/// Spawn arguments representation suitable for CLI (mirrors `diag::SpawnArgs`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliSpawnArgs {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub exec: Option<String>,
    pub cwd: Option<PathBuf>,
    pub gids: Vec<u32>,
    pub args: Vec<String>,
    #[serde(default)]
    pub ns: diag::NamespaceSpawn,
}

impl Default for CliSpawnArgs {
    fn default() -> Self {
        CliSpawnArgs {
            uid: None,
            gid: None,
            exec: None,
            cwd: None,
            gids: Vec::new(),
            args: Vec::new(),
            ns: diag::NamespaceSpawn::Outside,
        }
    }
}

/// Lightweight CLI form of `DaemonRequest` used for `--cmd` parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CliDaemonRequest {
    Spawn {
        args: CliSpawnArgs,
    },
    /// Provide a JSON `Cli` payload as text; it will be bincode-serialized
    /// and sent as the raw payload (converts to `DaemonRequest::SpawnCli`).
    SpawnCli {
        cli_json: String,
        #[serde(default)]
        ns: diag::NamespaceSpawn,
    },
    /// Liveness ping
    Ping,
    EnsureDbus,
    GetProcessList,
    Kill {
        task_pgid: u32,
    },
    Stop,
}

impl std::str::FromStr for CliDaemonRequest {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        match t.to_ascii_lowercase().as_str() {
            "stop" => Ok(CliDaemonRequest::Stop),
            "ping" => Ok(CliDaemonRequest::Ping),
            "ensuredbus" | "ensure_dbus" | "dbus" => Ok(CliDaemonRequest::EnsureDbus),
            "get" | "getprocesslist" | "get_process_list" | "processlist" => {
                Ok(CliDaemonRequest::GetProcessList)
            }
            other => {
                // Try JSON fallback for more complex forms
                if other.starts_with('{') || other.starts_with('[') {
                    serde_json::from_str::<CliDaemonRequest>(s).map_err(|e| e.to_string())
                } else {
                    Err(format!("unknown daemon cmd: {}", s))
                }
            }
        }
    }
}

/// Lightweight CLI form of global privileged daemon requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonCliRequest {
    Ping,
    Stop,
    CreateDirAll {
        path: PathBuf,
    },
    ReadFile {
        path: PathBuf,
    },
    WriteFile {
        path: PathBuf,
        content: Vec<u8>,
        #[serde(default)]
        create_parent: bool,
    },
    CreateProfile {
        name: String,
        profile_content: String,
        hot_content: Option<String>,
    },
}

impl std::str::FromStr for DaemonCliRequest {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        match t.to_ascii_lowercase().as_str() {
            "ping" => Ok(DaemonCliRequest::Ping),
            "stop" => Ok(DaemonCliRequest::Stop),
            other => {
                if other.starts_with('{') || other.starts_with('[') {
                    serde_json::from_str::<DaemonCliRequest>(s).map_err(|e| e.to_string())
                } else {
                    Err(format!("unknown privileged daemon cmd: {}", s))
                }
            }
        }
    }
}

/// Representation of a namespace input (PID or Path)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum NsInput {
    Pid(i32),
    Path(PathBuf),
    /// this process
    This,
    New,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum NsArg {
    Basis,
    Container(String),
    This,
}

impl std::str::FromStr for NsArg {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err("namespace argument must not be empty".to_string());
        }
        if trimmed.eq_ignore_ascii_case("basis") {
            Ok(NsArg::Basis)
        } else if trimmed.eq_ignore_ascii_case("this") {
            Ok(NsArg::This)
        } else {
            Ok(NsArg::Container(trimmed.to_string()))
        }
    }
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum MainCommand {
    #[command(alias = "e")]
    /// Find by process and enter an existing nsproxy namespace
    /// Enter the best-match based on searching arguments provided
    Enter {
        /// Instance name or path (if starts with /, ./, or ~/)
        target: String,
        #[command(flatten)]
        sargs: ShellArgs,
    },

    /// Install nsproxy to a folder
    Install {
        #[arg(default_value = "./install")]
        dir: PathBuf,
    },
    /// Generate shell completions
    Completions {
        /// Install fish completions to ~/.config/fish/completions
        #[arg(long)]
        fish: bool,
    },
    /// Remove a bind-mount file
    Rm { file: PathBuf },
    #[command(alias = "c")]
    Clean {
        /// Does a simple removal of default veth
        #[arg(short, long)]
        veth: bool,
    },
    #[command(alias = "n")]
    /// Netlink testing: print all IPv4 addresses
    Netlink,
    /// Generates an empty config file
    Gen { save_to: PathBuf },
    /// Record the current process namespaces as the basis namespace set.
    Init {
        /// Replace the recorded basis and recreate its namespace mounts.
        #[arg(long)]
        force: bool,
    },
    /// Identify current net-ns
    #[command(alias = "i")]
    Id {
        /// Optionally supply an PID
        pid: Option<u32>,
    },
    /// Serve a socks5 proxy server that could be used to escape a container
    Socks5 { port: u32 },
    /// Fire a single HTTP request to a URL
    Curl {
        /// URL to request
        url: String,
        /// Use socks5 proxy (address:port)
        #[arg(short, long)]
        proxy: Option<String>,
    },
    /// TCP forward
    Forward { src: u32, dst: u32 },
    /// Create a new container instance from a config template
    Template {
        /// Path to a profile template
        path: PathBuf,
        /// Name of profile to create (defaults to config filename stem)
        name: Option<String>,
        /// Reset profile by removing existing directory and recreating from scratch
        #[arg(short, long)]
        reset: bool,
        /// Update existing profile config without recreating directories
        #[arg(short, long)]
        update: bool,
    },
    /// Clone an existing profile into a new profile directory
    Clone {
        /// Name of the new profile to create
        name: String,
        /// Existing profile name to clone from
        from: String,
    },
    /// Create and persist a set of namespaces for a profile.
    /// A minimal long-lived process keeps the namespaces alive.
    /// Use `tun` and `veth` subcommands afterwards to attach networking.
    Up {
        /// Profile name (config resolves under /nsp3/config/{name})
        profile: String,
        /// Optional daemon request to send to the `up` daemon. Provide JSON matching `CliDaemonRequest`.
        #[arg(long)]
        cmd: Option<CliDaemonRequest>,
        /// Mock mode: reject protocol upgrades as if daemon runs an older version.
        #[arg(long)]
        simulate_protocol_no_upgrade: bool,
        /// Mock mode: accept and immediately close incoming up-daemon connections.
        #[arg(long)]
        simulate_conn_close: bool,
        /// Mock mode: delay daemon shutdown acknowledgement/exit to simulate slow replacement.
        #[arg(long)]
        simulate_slow_shutdown: bool,
    },
    /// Tear down a profile: kill the keeper process and remove the namespace bind mount.
    Down {
        /// Profile name
        profile: String,
        /// Remove both the profile config and runtime mount directories after teardown.
        #[arg(long)]
        rm: bool,
    },
    /// Attach a TUN device + tun2socks5 proxy to an already-up profile namespace.
    /// Only one TUN process may exist per profile at a time.
    Serve {
        /// Profile name (must have been brought up with `up` first)
        #[arg(long)]
        profile: String,
        /// TUN interface name (defaults to tun2)
        #[arg(long)]
        tun_name: Option<String>,
        /// Route all traffic through one proxy instance nym
        #[arg(long)]
        simple: Option<ProxyNym>,
        /// Do not set TUN as default route
        #[arg(short, long)]
        no_default: bool,
        #[arg(short, long)]
        #[serde(with = "level_filter_serde")]
        log: Option<LevelFilter>,
        /// Use Clash uplink profile for all TUN connections
        #[arg(long)]
        clash: Option<String>,
        // Optional override for HotConfig. When omitted, honor hot.json.
        #[arg(long, num_args = 0..=1, default_missing_value = "true")]
        no_dns_capture: Option<bool>,
        /// Use internal DNS server by default
        /// This server strips off IPv6 records. For compatilibty with certain proxies.
        /// This was intended for Geph, because at the point of writing Geph doesn't work with IPv6 properly
        #[arg(long, num_args = 0..=1, default_missing_value = "true")]
        internal_dns_server: Option<bool>,
    },
    /// Run the private `dbus-daemon` session bus for an already-up container.
    Dbus {
        /// Profile name (must have been brought up with `up` first)
        #[arg(long)]
        profile: String,
    },
    /// Create a veth pair between host and an already-up profile namespace.
    Veth {
        /// Source namespace endpoint (`this`, `default`, or a profile name)
        #[arg(long)]
        src: NsArg,
        /// Destination namespace endpoint (`this`, `default`, or a profile name)
        #[arg(long)]
        dst: NsArg,
        /// Veth pair base name (produces {name}_src and {name}_dst)
        #[arg(long)]
        veth_name: Option<String>,
        /// Fixed source IPv4 address; omit together with dst_ip4 for auto allocation.
        #[arg(long)]
        src_ip4: Option<Ipv4Addr>,
        /// Fixed destination IPv4 address; omit together with src_ip4 for auto allocation.
        #[arg(long)]
        dst_ip4: Option<Ipv4Addr>,
        /// Prefix length used for fixed or automatically allocated addresses.
        #[arg(long, default_value_t = 30)]
        prefix_len: u8,
        #[arg(short, long)]
        #[serde(with = "level_filter_serde")]
        log: Option<LevelFilter>,
    },
    /// Operations about basis network namespace, ie. the namespace where your system boots with
    Basis {
        #[command(subcommand)]
        cmd: BasisCommand,
    },
    /// Uplink by which you connect to freedom
    Uplink {
        #[command(subcommand)]
        kind: UplinkCommand,
    },
    /// Print a typed blueprint tree for global state paths
    StateTree,
    /// Print build identity (BLAKE3 source tree hash + build epoch timestamp)
    #[command(alias = "v")]
    Version,
    /// Pivot-root sandbox: enters an existing namespace, builds a tmpfs pivot
    /// root from a profile's TemplateConfig
    /// This command is run whenever any change is supposed to be made to the sandbox
    // Pass by FD if this is supposed to be a subprocess, instead of string args
    #[command(alias = "sb")]
    Sandbox {
        /// Profile name (must have been created with `profile` and brought up with `up`)
        profile: String,
    },
    /// Global privileged maintenance daemon used for state-tree writes.
    Daemon {
        /// Optional one-shot request to send to the global daemon socket.
        #[arg(long)]
        cmd: Option<DaemonCliRequest>,
    },
    /// Accept args as a serialized file
    File { path: PathBuf },
    /// Nsproxy can be used as sudo.
    /// The difference is nsproxy does not change anything about Wayland other display protocol, introducing minimal context change
    Sudo {
        #[command(flatten)]
        sargs: ShellArgs,
    },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum UplinkCommand {
    Clash {
        #[command(subcommand)]
        cmd: ClashOps,
    },
    Geph,
    Instance {
        name: ProxyNym,
        #[command(subcommand)]
        cmd: UplinkInstanceCommand,
    },
    Remote {
        #[command(subcommand)]
        cmd: RemoteOps,
    },
    Stats,
    /// Export a portable snapshot of all uplink hub state to a JSON file
    Export {
        /// Path to write the snapshot JSON to
        path: PathBuf,
    },
    /// Import uplink hub state from a previously exported snapshot JSON file
    Import {
        /// Path to the snapshot JSON file
        path: PathBuf,
    },
    /// Export only DNS backup cache to a JSON file
    DnsBackup {
        /// Path to write DNS backup JSON to
        path: PathBuf,
    },
    /// Import only DNS backup cache from JSON file
    DnsImport {
        /// Path to read DNS backup JSON from
        path: PathBuf,
    },
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum RemoteOps {
    /// Add a remote proxy by URL, e.g. socks5://127.0.0.1:1080
    Add { url: String },
    /// Remove a remote proxy by proxy nym
    Remove { nym: ProxyNym },
    /// List saved remote proxies
    List,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum UplinkInstanceCommand {
    Test,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum ClashOps {
    /// Import Clash config data into global clash state for a group
    ConfigAdd {
        /// Target group id for nameservers + domains
        group_id: String,
        /// Path to Clash YAML config file
        path: PathBuf,
    },
    /// Show status of imported Clash groups and cached proxies
    List,
    /// Analyze a Clash profile and explain the two-tier DNS bootstrap process
    ConfigExplain {
        /// Path to Clash YAML config file
        path: PathBuf,
    },
    /// Resolve proxies that do not have a known IP
    /// Regular upkeeping
    Resolve {
        #[arg(long)]
        direct: bool,
        #[arg(long)]
        refresh: bool,
        /// Optional DNS backup JSON file to pre-load cache before resolve
        #[arg(long)]
        backup: Option<PathBuf>,
    },
    /// Test the DNS resolution for one host
    TestResolve {
        #[arg(long)]
        direct: bool,
        query: String,
    },
}

pub mod uplink;

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum BasisCommand {
    /// Mount the basis network namespace
    Mount {},
    /// Enter the basis network namespace
    Enter {
        #[command(flatten)]
        sargs: ShellArgs,
    },
}

impl std::str::FromStr for NsInput {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use std::result::Result::Ok;

        if let Ok(pid) = s.parse::<i32>() {
            Ok(NsInput::Pid(pid))
        } else if s == "new" {
            Ok(NsInput::New)
        } else if s == "this" {
            Ok(NsInput::This)
        } else {
            Ok(NsInput::Path(PathBuf::from(s)))
        }
    }
}

pub fn to_cstr(f: &str) -> CString {
    CString::from_str(f).unwrap()
}

/// Serde helpers for `Option<LevelFilter>` (stored/transmitted as an optional string).
mod level_filter_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use tracing::level_filters::LevelFilter;

    pub fn serialize<S: Serializer>(v: &Option<LevelFilter>, s: S) -> Result<S::Ok, S::Error> {
        v.as_ref().map(|lf| lf.to_string()).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<LevelFilter>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(s) => s
                .parse::<LevelFilter>()
                .map(Some)
                .map_err(serde::de::Error::custom),
        }
    }
}

/// Encode a [`Cli`] value to a file-descriptor as a length-prefixed bincode frame.
/// The caller retains ownership of `fd`; this function does **not** close it.
pub fn encode_cli_to_fd(cli: &Cli, fd: std::os::fd::RawFd) -> anyhow::Result<()> {
    use std::mem::ManuallyDrop;
    use std::os::unix::io::FromRawFd;
    // SAFETY: fd is valid and caller retains ownership; ManuallyDrop prevents drop/close.
    let mut file = ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
    bincode::serialize_into(&mut *file, cli)?;
    Ok(())
}

/// Decode a [`Cli`] value from a file-descriptor (reads from current position).
/// The caller retains ownership of `fd`; this function does **not** close it.
pub fn decode_cli_from_fd(fd: std::os::fd::RawFd) -> anyhow::Result<Cli> {
    use std::mem::ManuallyDrop;
    use std::os::unix::io::FromRawFd;
    let mut file = ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
    Ok(bincode::deserialize_from(&mut *file)?)
}

/// Serialize a [`Cli`] into a fresh `memfd`, seeked back to offset 0.
/// Returns the `OwnedFd`; pass its raw fd number to a child process as `sp <fd>`.
pub fn cli_to_memfd(cli: &Cli) -> anyhow::Result<std::os::fd::OwnedFd> {
    use std::io::{Seek, SeekFrom};
    use std::os::unix::io::{FromRawFd, OwnedFd};
    let raw = unsafe { libc::memfd_create(c"nsp-cli-args".as_ptr(), libc::MFD_CLOEXEC) };
    if raw < 0 {
        return Err(anyhow::anyhow!(
            "memfd_create failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fresh fd from memfd_create
    let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
    bincode::serialize_into(&mut file, cli)?;
    file.seek(SeekFrom::Start(0))?;
    // Convert back to OwnedFd without closing
    let owned = unsafe { OwnedFd::from_raw_fd(std::os::unix::io::IntoRawFd::into_raw_fd(file)) };
    Ok(owned)
}

/// Serialize a [`Cli`] into a non-`CLOEXEC` memfd so it is inherited across `exec`.
/// Returns the **raw fd number**; the caller is responsible for `close()`ing it after
/// the child has been spawned.  Use this when passing the fd to a subprocess via
/// `Command::arg(fd.to_string())`.
pub fn cli_to_inheritable_fd(cli: &Cli) -> anyhow::Result<std::os::fd::RawFd> {
    use std::io::{Seek, SeekFrom};
    use std::os::unix::io::FromRawFd;
    // MFD_CLOEXEC intentionally omitted — the child process must inherit the fd.
    let raw = unsafe { libc::memfd_create(c"nsp-cli-inh".as_ptr(), 0) };
    if raw < 0 {
        return Err(anyhow::anyhow!(
            "memfd_create failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
    bincode::serialize_into(&mut file, cli)?;
    file.seek(SeekFrom::Start(0))?;
    // Leak the File — caller owns the fd lifetime.
    std::mem::forget(file);
    Ok(raw)
}

#[cfg(test)]
mod cli_fd_tests {
    use std::os::fd::IntoRawFd;

    use tracing::level_filters::LevelFilter;

    use super::*;

    fn roundtrip(cli: Cli) {
        let owned_fd = cli_to_memfd(&cli).expect("cli_to_memfd failed");
        let raw = owned_fd.into_raw_fd();
        let decoded = decode_cli_from_fd(raw).expect("decode_cli_from_fd failed");
        // Close the fd now (we own it after the ManuallyDrop dance is done).
        unsafe { libc::close(raw) };

        // Compare by re-serialising both sides to JSON — Cli doesn't impl PartialEq
        // because clap derives only Debug, but all inner types do serialise deterministically.
        let orig = serde_json::to_string(&cli).unwrap();
        let got = serde_json::to_string(&decoded).unwrap();
        assert_eq!(orig, got, "roundtrip mismatch");
    }

    #[test]
    fn roundtrip_serve() {
        roundtrip(Cli {
            conf: None,
            root: None,
            no_wrap_check: false,
            control_socket: None,
            cmd: MainCommand::Serve {
                profile: "myvpn".into(),
                tun_name: Some("tun42".into()),
                simple: Some(nsproxy_common::routing::ProxyNym("geph".into())),
                no_default: false,
                log: Some(LevelFilter::DEBUG),
                clash: None,
                no_dns_capture: Some(true),
                internal_dns_server: Some(false),
            },
        });
    }

    #[test]
    fn roundtrip_up() {
        roundtrip(Cli {
            conf: None,
            root: Some("/nsp3".into()),
            no_wrap_check: true,
            control_socket: None,
            cmd: MainCommand::Up {
                profile: "myprofile".into(),
                cmd: None,
                simulate_protocol_no_upgrade: false,
                simulate_conn_close: false,
                simulate_slow_shutdown: false,
            },
        });
    }

    #[test]
    fn roundtrip_veth_with_log_none() {
        roundtrip(Cli {
            conf: None,
            root: None,
            no_wrap_check: false,
            control_socket: None,
            cmd: MainCommand::Veth {
                src: NsArg::This,
                dst: NsArg::Container("p1".into()),
                veth_name: None,
                src_ip4: None,
                dst_ip4: None,
                prefix_len: 30,
                log: None,
            },
        });
    }

    #[test]
    fn roundtrip_veth_with_log_some() {
        roundtrip(Cli {
            conf: None,
            root: None,
            no_wrap_check: false,
            control_socket: None,
            cmd: MainCommand::Veth {
                src: NsArg::Container("p2".into()),
                dst: NsArg::Container("p3".into()),
                veth_name: Some("v_custom".into()),
                src_ip4: None,
                dst_ip4: None,
                prefix_len: 30,
                log: Some(LevelFilter::WARN),
            },
        });
    }

    #[test]
    fn parse_ns_arg_this_and_container() {
        assert_eq!("this".parse::<NsArg>().unwrap(), NsArg::This);
        assert_eq!("basis".parse::<NsArg>().unwrap(), NsArg::Basis);
        assert_eq!(
            "demo".parse::<NsArg>().unwrap(),
            NsArg::Container("demo".to_string())
        );
    }

    #[test]
    fn roundtrip_down_with_rm() {
        roundtrip(Cli {
            conf: None,
            root: None,
            no_wrap_check: false,
            control_socket: None,
            cmd: MainCommand::Down {
                profile: "p3".into(),
                rm: true,
            },
        });
    }

    #[test]
    fn roundtrip_clone_profile() {
        roundtrip(Cli {
            conf: None,
            root: None,
            no_wrap_check: false,
            control_socket: None,
            cmd: MainCommand::Clone {
                name: "p4-copy".into(),
                from: "p4".into(),
            },
        });
    }
}
