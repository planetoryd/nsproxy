use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    future::ready,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Result, anyhow};
use futures::{StreamExt, channel::mpsc, stream::TryStreamExt};
use hardware_address::MacAddr;
use ipnetwork::IpNetwork;
use notify::{Event, EventKind, RecommendedWatcher, Watcher, event::ModifyKind};
use rtnetlink::packet_route::link::LinkAttribute;
use rtnetlink::{Handle, LinkMessageBuilder, LinkUnspec};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select, sync,
};
use tracing::{error, info, warn};
use tun2socks5::{dns::VirtDNSHandle, flume, ipstack::stream::IpStackTcpStream};
use warp::server::accept::Accept;

use crate::{HotConfig, HotRoute, ProfileMount, shell::ShellArgs, tokio_netlink_conn};
use diag::{DiagEvent, DiagServer, Timestamp};
use nsproxy_common::routing::{DropReason, RoutingDecision};

#[derive(Clone)]
pub enum HotReloadTrigger {
    ApplyConfig {
        persist_backup: bool,
        source: &'static str,
        config: Arc<HotConfig>,
    },
}

fn async_watcher() -> notify::Result<(RecommendedWatcher, sync::mpsc::Receiver<()>)> {
    let (mut tx, rx) = tokio::sync::mpsc::channel(1);
    let tx1 = tx.clone();
    tokio::spawn(async move { tx1.send(()).await });

    let watcher = RecommendedWatcher::new(
        move |res: std::result::Result<Event, notify::Error>| match res {
            Ok(res) => {
                if matches!(res.kind, EventKind::Modify(ModifyKind::Data(_))) {
                    let _ = tx.try_send(());
                }
            }
            _ => {}
        },
        notify::Config::default(),
    )?;

    Ok((watcher, rx))
}

struct WarpServer {
    task: JoinHandle<()>,
}

struct LocalForward {
    dst_port: u32,
    task: JoinHandle<()>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum VdnsDesired {
    Dns(Ipv4Addr),
    NatByTun(SocketAddr),
    File(PathBuf),
}

#[derive(Clone, PartialEq, Eq)]
struct DesiredHotState {
    vdns: BTreeMap<String, VdnsDesired>,
    warps: BTreeSet<PathBuf>,
    devs: HashMap<String, String>,
    mnt: HashMap<PathBuf, PathBuf>,
    locals: BTreeMap<u32, u32>,
    dns_capture: HashSet<IpNetwork>,
    resolv_conf_dns: String,
    route: HotRoute,
    mounts: Vec<ProfileMount>,
    daemons: Vec<ShellArgs>,
}

#[derive(Clone, PartialEq, Eq)]
struct AppliedHotState {
    vdns: BTreeMap<String, VdnsDesired>,
    warps: BTreeSet<PathBuf>,
    devs: HashMap<String, String>,
    mnt: HashMap<PathBuf, PathBuf>,
    locals: BTreeMap<u32, u32>,
    dns_capture: HashSet<IpNetwork>,
    resolv_conf_dns: String,
    route: HotRoute,
    mounts: Vec<ProfileMount>,
    daemons: Vec<ShellArgs>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConfigOpKind {
    Add,
    Remove,
    Sync,
}

#[derive(Clone)]
enum ConfigChange {
    ResolvConf(String),
    DnsCapture(HashSet<IpNetwork>),
    Route(HotRoute),
    Devs(HashMap<String, String>),
    Mnt(HashMap<PathBuf, PathBuf>),
    Mounts(Vec<ProfileMount>),
    Daemons(Vec<ShellArgs>),
    Vdns {
        domain: String,
        desired: VdnsDesired,
    },
    WarpPath(PathBuf),
    LocalForward {
        in_port: u32,
        dst_port: u32,
    },
}

#[derive(Clone)]
struct ConfigDelta {
    op: ConfigOpKind,
    change: ConfigChange,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChildHotReloadRequest {
    pub config: HotConfig,
    #[serde(default)]
    pub requested_local_ports: Vec<u32>,
}

struct WarpAcceptor {
    path: PathBuf,
    rx: flume::Receiver<(PathBuf, IpStackTcpStream)>,
}

impl Accept for WarpAcceptor {
    type IO = hyper_util::rt::TokioIo<IpStackTcpStream>;
    type AcceptError = flume::RecvError;
    type Accepting = std::future::Ready<Result<Self::IO, Self::AcceptError>>;

    async fn accept(&mut self) -> std::result::Result<Self::Accepting, std::io::Error> {
        loop {
            let rx: std::result::Result<(PathBuf, IpStackTcpStream), flume::RecvError> =
                self.rx.recv_async().await;
            match rx {
                Ok((p, s)) => {
                    if p == self.path {
                        info!("accepted stream");
                        return Ok(ready(Ok(hyper_util::rt::TokioIo::new(s))));
                    }
                }
                Err(e) => {
                    return Ok(ready(Err(e)));
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
pub struct VethIps {
    pub vout: Ipv4Addr,
    pub vin: Ipv4Addr,
}

/// TCP forwarder across namespaces, listen within container, forward to TCP outside.
async fn handle_tcp_forward_local(fd: OwnedFd, port: u32, dst_port: u32) {
    let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd.into_raw_fd()) };
    std_listener.set_nonblocking(true).unwrap();
    match tokio::net::TcpListener::from_std(std_listener) {
        Ok(listener) => loop {
            match listener.accept().await {
                Ok((mut client, _)) => {
                    let dst_addr = format!("127.0.0.1:{}", dst_port);
                    tokio::spawn(async move {
                        match tokio::net::TcpStream::connect(&dst_addr).await {
                            Ok(mut server) => {
                                info!("forwarded connection from port {} to {}", port, dst_addr);
                                if let Err(e) =
                                    tokio::io::copy_bidirectional(&mut client, &mut server).await
                                {
                                    warn!("forward error: {}", e);
                                }
                            }
                            Err(e) => {
                                warn!("failed to connect to {}: {}", dst_addr, e);
                            }
                        }
                    });
                }
                Err(e) => {
                    warn!("accept error on port {}: {}", port, e);
                    break;
                }
            }
        },
        Err(e) => {
            warn!("failed to create async listener for port {}: {}", port, e);
        }
    }
}

fn spawn_warp_server(
    path: PathBuf,
    acceptor: flume::Receiver<(PathBuf, IpStackTcpStream)>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let filter = warp::fs::dir(path.clone());
        let wa = WarpAcceptor { path, rx: acceptor };
        warp::serve(filter).incoming(wa).run().await;
    })
}

fn derive_desired_state(conf: &HotConfig) -> DesiredHotState {
    let mut vdns = BTreeMap::new();
    let mut warps = BTreeSet::new();

    for (domain, ip) in &conf.dns {
        if let Ok(addr) = ip.parse::<Ipv4Addr>() {
            vdns.insert(domain.clone(), VdnsDesired::Dns(addr));
        }
    }

    for (domain, spec) in &conf.tun {
        match spec {
            serde_json::Value::String(mapstr) => {
                if let Ok(addr) = mapstr.parse::<SocketAddr>() {
                    vdns.insert(domain.clone(), VdnsDesired::NatByTun(addr));
                } else if let Ok(path) = mapstr.parse::<PathBuf>() {
                    warps.insert(path.clone());
                    vdns.insert(domain.clone(), VdnsDesired::File(path));
                }
            }
            serde_json::Value::Number(port) => {
                if let Some(port) = port.as_u64().and_then(|p| u16::try_from(p).ok()) {
                    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into();
                    vdns.insert(domain.clone(), VdnsDesired::NatByTun(addr));
                }
            }
            _ => {}
        }
    }

    DesiredHotState {
        vdns,
        warps,
        devs: conf.devs.clone(),
        mnt: conf.mnt.clone(),
        locals: conf.locals.iter().map(|(src, dst)| (*src, *dst)).collect(),
        dns_capture: conf.dns_capture.clone(),
        resolv_conf_dns: conf.resolv_conf_dns.clone(),
        route: conf.route.clone(),
        mounts: conf.mounts.clone(),
        daemons: conf.daemons.clone(),
    }
}

fn into_applied_state(desired: &DesiredHotState) -> AppliedHotState {
    AppliedHotState {
        vdns: desired.vdns.clone(),
        warps: desired.warps.clone(),
        devs: desired.devs.clone(),
        mnt: desired.mnt.clone(),
        locals: desired.locals.clone(),
        dns_capture: desired.dns_capture.clone(),
        resolv_conf_dns: desired.resolv_conf_dns.clone(),
        route: desired.route.clone(),
        mounts: desired.mounts.clone(),
        daemons: desired.daemons.clone(),
    }
}

fn calculate_hot_diff(
    current: Option<&AppliedHotState>,
    desired: &DesiredHotState,
) -> Vec<ConfigDelta> {
    let mut ops = Vec::new();

    if let Some(current) = current {
        if current.resolv_conf_dns != desired.resolv_conf_dns {
            ops.push(ConfigDelta {
                op: ConfigOpKind::Sync,
                change: ConfigChange::ResolvConf(desired.resolv_conf_dns.clone()),
            });
        }

        for (in_port, dst_port) in &current.locals {
            if desired.locals.get(in_port) != Some(dst_port) {
                ops.push(ConfigDelta {
                    op: ConfigOpKind::Remove,
                    change: ConfigChange::LocalForward {
                        in_port: *in_port,
                        dst_port: *dst_port,
                    },
                });
            }
        }

        for path in &current.warps {
            if !desired.warps.contains(path) {
                ops.push(ConfigDelta {
                    op: ConfigOpKind::Remove,
                    change: ConfigChange::WarpPath(path.clone()),
                });
            }
        }

        for (domain, entry) in &current.vdns {
            if desired.vdns.get(domain) != Some(entry) {
                ops.push(ConfigDelta {
                    op: ConfigOpKind::Remove,
                    change: ConfigChange::Vdns {
                        domain: domain.clone(),
                        desired: entry.clone(),
                    },
                });
            }
        }
    }

    if current.is_none_or(|state| state.dns_capture != desired.dns_capture) {
        ops.push(ConfigDelta {
            op: ConfigOpKind::Sync,
            change: ConfigChange::DnsCapture(desired.dns_capture.clone()),
        });
    }

    if current.is_none_or(|state| state.route != desired.route) {
        ops.push(ConfigDelta {
            op: ConfigOpKind::Sync,
            change: ConfigChange::Route(desired.route.clone()),
        });
    }

    if current.is_none_or(|state| state.devs != desired.devs) {
        ops.push(ConfigDelta {
            op: ConfigOpKind::Sync,
            change: ConfigChange::Devs(desired.devs.clone()),
        });
    }

    if current.is_none_or(|state| state.mnt != desired.mnt) {
        ops.push(ConfigDelta {
            op: ConfigOpKind::Sync,
            change: ConfigChange::Mnt(desired.mnt.clone()),
        });
    }

    if current.is_none_or(|state| state.mounts != desired.mounts) {
        ops.push(ConfigDelta {
            op: ConfigOpKind::Sync,
            change: ConfigChange::Mounts(desired.mounts.clone()),
        });
    }

    if current.is_none_or(|state| state.daemons != desired.daemons) {
        ops.push(ConfigDelta {
            op: ConfigOpKind::Sync,
            change: ConfigChange::Daemons(desired.daemons.clone()),
        });
    }

    for (domain, entry) in &desired.vdns {
        if current.and_then(|state| state.vdns.get(domain)) != Some(entry) {
            ops.push(ConfigDelta {
                op: ConfigOpKind::Add,
                change: ConfigChange::Vdns {
                    domain: domain.clone(),
                    desired: entry.clone(),
                },
            });
        }
    }

    for path in &desired.warps {
        if current.is_none_or(|state| !state.warps.contains(path)) {
            ops.push(ConfigDelta {
                op: ConfigOpKind::Add,
                change: ConfigChange::WarpPath(path.clone()),
            });
        }
    }

    for (in_port, dst_port) in &desired.locals {
        if current.and_then(|state| state.locals.get(in_port)) != Some(dst_port) {
            ops.push(ConfigDelta {
                op: ConfigOpKind::Add,
                change: ConfigChange::LocalForward {
                    in_port: *in_port,
                    dst_port: *dst_port,
                },
            });
        }
    }

    ops
}

fn describe_delta(delta: &ConfigDelta) -> String {
    let op = match delta.op {
        ConfigOpKind::Add => "add",
        ConfigOpKind::Remove => "remove",
        ConfigOpKind::Sync => "sync",
    };

    let target = match &delta.change {
        ConfigChange::ResolvConf(nameserver) => {
            format!("resolv.conf nameserver {}", nameserver)
        }
        ConfigChange::DnsCapture(nets) => {
            format!("dns capture set ({} entries)", nets.len())
        }
        ConfigChange::Route(route) => {
            format!("route {:?}", route)
        }
        ConfigChange::Devs(devs) => {
            format!("device runtime state ({} entries)", devs.len())
        }
        ConfigChange::Mnt(mnt) => {
            format!("shorthand bind mounts ({} entries)", mnt.len())
        }
        ConfigChange::Mounts(mounts) => {
            format!("explicit mounts ({} entries)", mounts.len())
        }
        ConfigChange::Daemons(daemons) => {
            format!("daemon config ({} entries)", daemons.len())
        }
        ConfigChange::Vdns { domain, desired } => match desired {
            VdnsDesired::Dns(addr) => format!("dns {} -> {}", domain, addr),
            VdnsDesired::NatByTun(addr) => format!("nat {} -> {}", domain, addr),
            VdnsDesired::File(path) => format!("files {} -> {}", domain, path.display()),
        },
        ConfigChange::WarpPath(path) => {
            format!("warp path {}", path.display())
        }
        ConfigChange::LocalForward { in_port, dst_port } => {
            format!("localhost forward {} -> {}", in_port, dst_port)
        }
    };

    format!("hot config op: {} {}", op, target)
}

fn should_log_delta(delta: &ConfigDelta) -> bool {
    !matches!(
        (&delta.op, &delta.change),
        (
            ConfigOpKind::Add,
            ConfigChange::Vdns {
                desired: VdnsDesired::Dns(_),
                ..
            }
        )
    )
}

fn routing_decision_from_desired(desired: &VdnsDesired) -> (Option<Ipv4Addr>, RoutingDecision) {
    match desired {
        VdnsDesired::Dns(addr) => (
            Some(*addr),
            RoutingDecision::Drop(DropReason::Preprocess(Cow::Borrowed("dns config"))),
        ),
        VdnsDesired::NatByTun(addr) => (None, RoutingDecision::NATByTUN(*addr)),
        VdnsDesired::File(path) => (None, RoutingDecision::File(path.clone())),
    }
}

async fn request_local_forwarders(
    tx: &mut tokio::net::UnixStream,
    conf: &HotConfig,
    requested_local_ports: &[u32],
) -> Result<Vec<(u32, OwnedFd, u32)>> {
    let request = ChildHotReloadRequest {
        config: conf.clone(),
        requested_local_ports: requested_local_ports.to_vec(),
    };
    let payload = serde_json::to_vec(&request)?;
    tx.write_all(&[1u8]).await?;
    tx.write_all(&(payload.len() as u32).to_le_bytes()).await?;
    tx.write_all(&payload).await?;

    use tokio_send_fd::SendFd;
    let mut locals = Vec::new();
    let mut port_bytes = [0u8; 4];
    let mut first = false;
    while tx.read_exact(&mut port_bytes).await.is_ok() {
        let in_port = u32::from_le_bytes(port_bytes);
        if in_port == 0 {
            if !first {
                first = true;
                continue;
            }
            break;
        }

        let fd = tx.recv_fd().await?;
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        if let Some(dst_port) = conf.locals.get(&in_port).copied() {
            locals.push((in_port, fd, dst_port));
        }
    }

    if let Some(missing_port) = requested_local_ports
        .iter()
        .find(|port| !locals.iter().any(|(in_port, _, _)| in_port == *port))
    {
        return Err(anyhow!(
            "child namespace did not return a listener fd for requested local port {}",
            missing_port
        ));
    }

    Ok(locals)
}

fn delta_requires_child_apply(delta: &ConfigDelta) -> bool {
    match (&delta.op, &delta.change) {
        (ConfigOpKind::Sync, ConfigChange::ResolvConf(_)) => true,
        (ConfigOpKind::Sync, ConfigChange::Devs(_)) => true,
        (ConfigOpKind::Sync, ConfigChange::Mnt(_)) => true,
        (ConfigOpKind::Sync, ConfigChange::Mounts(_)) => true,
        (ConfigOpKind::Add, ConfigChange::LocalForward { .. }) => true,
        _ => false,
    }
}

async fn apply_hot_config(
    current: Option<&AppliedHotState>,
    desired: &DesiredHotState,
    desired_config: &HotConfig,
    vdns: Option<VirtDNSHandle>,
    child_pid: u32,
    tx: &mut tokio::net::UnixStream,
    acceptor: &flume::Receiver<(PathBuf, IpStackTcpStream)>,
    warps: &mut HashMap<PathBuf, WarpServer>,
    locals: &mut HashMap<u32, LocalForward>,
) -> Result<()> {
    let ops = calculate_hot_diff(current, desired);
    let requested_local_ports: Vec<u32> = ops
        .iter()
        .filter_map(|delta| match (&delta.op, &delta.change) {
            (ConfigOpKind::Add, ConfigChange::LocalForward { in_port, .. }) => Some(*in_port),
            _ => None,
        })
        .collect();

    let mut child_apply_done = false;
    let mut refreshed_locals: Option<Vec<(u32, OwnedFd, u32)>> = None;

    for delta in ops {
        if !child_apply_done && delta_requires_child_apply(&delta) {
            refreshed_locals =
                Some(request_local_forwarders(tx, desired_config, &requested_local_ports).await?);
            child_apply_done = true;
        }

        if should_log_delta(&delta) {
            info!("{}", describe_delta(&delta));
        }
        match delta {
            ConfigDelta {
                op: ConfigOpKind::Remove,
                change: ConfigChange::Vdns { domain, .. },
            } => {
                if let Some(vdns) = &vdns {
                    vdns.unpin(domain);
                }
            }
            ConfigDelta {
                op: ConfigOpKind::Add,
                change: ConfigChange::Vdns { domain, desired },
            } => {
                if let Some(vdns) = &vdns {
                    let (ip, target) = routing_decision_from_desired(&desired);
                    vdns.pin(ip, domain, target)?;
                }
            }
            ConfigDelta {
                op: ConfigOpKind::Remove,
                change: ConfigChange::WarpPath(path),
            } => {
                if let Some(server) = warps.remove(&path) {
                    server.task.abort();
                }
            }
            ConfigDelta {
                op: ConfigOpKind::Add,
                change: ConfigChange::WarpPath(path),
            } => {
                warps.entry(path.clone()).or_insert_with(|| WarpServer {
                    task: spawn_warp_server(path, acceptor.clone()),
                });
            }
            ConfigDelta {
                op: ConfigOpKind::Remove,
                change: ConfigChange::LocalForward { in_port, dst_port },
            } => {
                if let Some(forward) = locals.remove(&in_port) {
                    forward.task.abort();
                }
            }
            ConfigDelta {
                op: ConfigOpKind::Sync,
                change: ConfigChange::ResolvConf(_),
            } => {}
            ConfigDelta {
                op: ConfigOpKind::Sync,
                change: ConfigChange::DnsCapture(_),
            } => {}
            ConfigDelta {
                op: ConfigOpKind::Sync,
                change: ConfigChange::Route(_),
            } => {}
            ConfigDelta {
                op: ConfigOpKind::Sync,
                change: ConfigChange::Devs(devs),
            } => {
                sync_links(Some(child_pid), &devs).await?;
            }
            ConfigDelta {
                op: ConfigOpKind::Sync,
                change: ConfigChange::Mnt(_),
            } => {}
            ConfigDelta {
                op: ConfigOpKind::Sync,
                change: ConfigChange::Mounts(_),
            } => {}
            ConfigDelta {
                op: ConfigOpKind::Sync,
                change: ConfigChange::Daemons(_),
            } => {}
            ConfigDelta {
                op: ConfigOpKind::Add,
                change: ConfigChange::LocalForward { in_port, dst_port },
            } => {
                if let Some(new_locals) = &mut refreshed_locals
                    && let Some(index) = new_locals
                        .iter()
                        .position(|(port, _, target)| *port == in_port && *target == dst_port)
                {
                    let (_, fd, dst_port) = new_locals.swap_remove(index);
                    let task = tokio::spawn(handle_tcp_forward_local(fd, in_port, dst_port));
                    locals.insert(in_port, LocalForward { dst_port, task });
                }
            }
            _ => {}
        }
    }

    Ok(())
}

pub async fn watch_hot(
    mut vdns_rx: mpsc::Receiver<Option<VirtDNSHandle>>,
    conf: Option<PathBuf>,
    acceptor: flume::Receiver<(PathBuf, IpStackTcpStream)>,
    child_pid: u32,
    mut tx: tokio::net::UnixStream,
    veths: Option<VethIps>,
    diag: DiagServer,
    mut reload_rx: sync::mpsc::Receiver<HotReloadTrigger>,
    live_hot: Arc<sync::RwLock<HotConfig>>,
    hot_tx: sync::watch::Sender<HotConfig>,
) -> Result<()> {
    let mut warps: HashMap<PathBuf, WarpServer> = HashMap::new();
    let mut locals: HashMap<u32, LocalForward> = HashMap::new();
    let vdns: Option<Option<VirtDNSHandle>> = vdns_rx.next().await;
    let vdns = vdns.unwrap();
    let mut applied_state: Option<AppliedHotState> = None;
    let mut ignored_backup: Option<HotConfig> = None;

    if let Some(vdns) = &vdns
        && let Some(veth) = veths
    {
        vdns.pin(
            Some(veth.vout),
            "veth.host.".to_owned(),
            RoutingDecision::Drop(DropReason::Preprocess(Cow::Borrowed("veth host"))),
        );
        vdns.pin(
            Some(veth.vin),
            "veth.peer.".to_owned(),
            RoutingDecision::Drop(DropReason::Preprocess(Cow::Borrowed("veth peer"))),
        );
    }

    if let Some(conf) = conf {
        let (mut wx, mut rx) = async_watcher()?;
        wx.watch(&conf, notify::RecursiveMode::NonRecursive)?;

        loop {
            let conf = conf.clone();
            let diag = diag.clone();
            let mut source = None;
            let mut persist_backup = false;
            let desired = select! {
                k = rx.recv() => {
                    if k.is_none() {
                        break;
                    }

                    match tokio::fs::read_to_string(&conf).await {
                        Ok(fc) => match serde_json::from_str::<HotConfig>(&fc) {
                            Ok(mut cfg) => {
                                cfg.process_and_save(&conf)?;
                                if ignored_backup.as_ref() == Some(&cfg) {
                                    ignored_backup = None;
                                    continue;
                                }
                                source = Some("file");
                                cfg
                            }
                            Err(err) => {
                                warn!("config changed, but is invalid: {err}");
                                diag.emit(DiagEvent::HotConfigReloaded {
                                    ts: Timestamp::now(),
                                    ok: false,
                                    changed: false,
                                    source: "file".to_string(),
                                    error: Some(err.to_string()),
                                });
                                continue;
                            }
                        },
                        Err(err) => {
                            diag.emit(DiagEvent::HotConfigReloaded {
                                ts: Timestamp::now(),
                                ok: false,
                                changed: false,
                                source: "file".to_string(),
                                error: Some(err.to_string()),
                            });
                            continue;
                        }
                    }
                }
                Some(trigger) = reload_rx.recv() => {
                    match trigger {
                        HotReloadTrigger::ApplyConfig { source: trigger_source, config, persist_backup: trigger_persist } => {
                            source = Some(trigger_source);
                            persist_backup = trigger_persist;
                            (*config).clone()
                        }
                    }
                }
            };

            let source = source.unwrap_or("direct");
            let mut desired = desired;
            desired.process();
            let desired_state = derive_desired_state(&desired);
            let diff = calculate_hot_diff(applied_state.as_ref(), &desired_state);
            if diff.is_empty() {
                diag.emit(DiagEvent::HotConfigReloaded {
                    ts: Timestamp::now(),
                    ok: true,
                    changed: false,
                    source: source.to_string(),
                    error: None,
                });
                if persist_backup {
                    desired.process_and_save(&conf)?;
                    ignored_backup = Some(desired);
                }
                continue;
            }

            match apply_hot_config(
                applied_state.as_ref(),
                &desired_state,
                &desired,
                vdns.clone(),
                child_pid,
                &mut tx,
                &acceptor,
                &mut warps,
                &mut locals,
            )
            .await
            {
                Ok(()) => {
                    if persist_backup {
                        desired.process_and_save(&conf)?;
                        ignored_backup = Some(desired.clone());
                    }

                    applied_state = Some(into_applied_state(&desired_state));
                    {
                        let mut live = live_hot.write().await;
                        *live = desired.clone();
                    }
                    let _ = hot_tx.send(desired.clone());
                    diag.emit(DiagEvent::HotConfigReloaded {
                        ts: Timestamp::now(),
                        ok: true,
                        changed: true,
                        source: source.to_string(),
                        error: None,
                    });
                }
                Err(err) => {
                    diag.emit(DiagEvent::HotConfigReloaded {
                        ts: Timestamp::now(),
                        ok: false,
                        changed: false,
                        source: source.to_string(),
                        error: Some(err.to_string()),
                    });
                }
            }
        }

        warn!("config watching ended");
    } else {
        error!("no config specified. config watcher stopped");
    }
    Ok(())
}

pub async fn sync_links(child_pid: Option<u32>, devs: &HashMap<String, String>) -> Result<()> {
    let handle: Handle = tokio_netlink_conn()?;

    let mut links = handle.link().get().execute();
    'outer: loop {
        match links.try_next().await {
            Ok(Some(msg)) => {
                for nla in msg.attributes.into_iter() {
                    match nla {
                        LinkAttribute::IfName(name) => {
                            if let Some(ipstr) = devs.get(&name) {
                                if let Some(pid) = child_pid {
                                    let msg: LinkMessageBuilder<LinkUnspec> =
                                        LinkMessageBuilder::default()
                                            .index(msg.header.index)
                                            .setns_by_pid(pid);
                                    handle.link().set(msg.build()).execute().await?;
                                }
                                if let Ok(ip) = ipstr.parse::<IpNetwork>() {
                                    let _ = handle
                                        .address()
                                        .add(msg.header.index, ip.ip(), ip.prefix())
                                        .execute()
                                        .await;

                                    let _ = handle
                                        .link()
                                        .set(
                                            LinkUnspec::new_with_index(msg.header.index)
                                                .up()
                                                .build(),
                                        )
                                        .execute()
                                        .await;
                                }
                            }
                            continue 'outer;
                        }
                        LinkAttribute::Address(mac) => {
                            if mac.len() == 6 {
                                let mac: [u8; 6] = mac[..6].try_into().unwrap();
                                let macstr = MacAddr::from_raw(mac).to_colon_separated();
                                if let Some(pid) = child_pid {
                                    let msg: LinkMessageBuilder<LinkUnspec> =
                                        LinkMessageBuilder::default()
                                            .index(msg.header.index)
                                            .setns_by_pid(pid);
                                    handle.link().set(msg.build()).execute().await?;
                                }
                                if let Some(ipstr) = devs.get(&macstr) {
                                    if let Ok(ip) = ipstr.parse::<IpNetwork>() {
                                        let _ = handle
                                            .address()
                                            .add(msg.header.index, ip.ip(), ip.prefix())
                                            .execute()
                                            .await;
                                    }
                                }
                            }
                        }
                        LinkAttribute::PermAddress(_addr) => {}
                        _ => {}
                    }
                }
            }
            Err(er) => {
                warn!("link enumeration failed with {:?}", er);
                break 'outer;
            }
            Ok(None) => break 'outer,
        }
    }

    Ok(())
}
