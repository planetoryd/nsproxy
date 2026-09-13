use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Instant, SystemTime};
use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use anyhow::{Context, Result};
use diag::summary::DiagAccumulator;
use diag::{ControlCommand, DiagEvent, DiagEventStream, LogEntry};
use eframe::egui;
use libc;
use nix::sys::signal::{kill, Signal};
use nix::unistd::{execve, fork, ForkResult, Pid};
use notify::{event::ModifyKind, Event, EventKind, RecommendedWatcher, Watcher};
use nsproxy_common::routing::ProxyID;
use nsproxy_common::state_paths;
use nsproxy_common::stats::ProxyStats;
use nsproxy_common::NsAlive;
use nsproxy_common::{ExactNS, Inode, NSFrom, PidPath};
use nsproxy_core::cmd_common::read_ns_alive;
use nsproxy_core::sandbox::{read_sandbox_status, SandboxStatus};
use nsproxy_core::shell::ShellArgs;
use nsproxy_core::{
    cli_to_inheritable_fd, to_cstr, Cli, HotConfig, HotRoute, HotVeth, MainCommand, TemplateConfig,
};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

pub type ContainerName = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagSummary {
    pub total_conns: usize,
    pub active_conns: usize,
}

/// Snapshot of connection-level traffic data from the DiagAccumulator,
/// suitable for rendering the traffic table in the UI.
#[derive(Clone, Default)]
pub struct TrafficSnapshot {
    pub conn_order: VecDeque<diag::ConnId>,
    pub conns: HashMap<diag::ConnId, diag::summary::ConnStats>,
    pub loop_avg_us: f64,
    pub loop_max_us: u64,
    pub loop_min_us: u64,
    pub loop_samples: usize,
}

/// A log entry combined with its source (up-daemon or serve process).
#[derive(Clone, Debug)]
pub struct LogEntryOf {
    pub hash: u64,
    pub log: LogEntry,
    pub src: LogSource,
}

#[derive(Clone, Debug)]
pub struct RenderedLogEntry {
    pub entry: LogEntryOf,
    pub ansi_parts: Arc<Vec<egui::RichText>>,
}

/// Source of a [`LogEntryOf`] entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum LogSource {
    Up,
    Serve,
    RootDaemon,
    Pid(u32),
}

const LOG_VIEW_SLOTS: usize = 5;
const MAX_LOG_ENTRIES: usize = 2048 * LOG_VIEW_SLOTS;

fn fast_hash_log_entry(entry: &LogEntry) -> u64 {
    let mut hasher = twox_hash::XxHash3_64::default();
    entry.hash(&mut hasher);
    hasher.finish()
}

#[derive(Debug, Default)]
pub struct LevelLogView {
    entries: VecDeque<Arc<RenderedLogEntry>>,
    visible_by_min_level: [VecDeque<Arc<RenderedLogEntry>>; LOG_VIEW_SLOTS],
}

impl LevelLogView {
    pub fn clear(&mut self) {
        self.entries.clear();
        let mut slot = 0;
        while slot < LOG_VIEW_SLOTS {
            self.visible_by_min_level[slot].clear();
            slot += 1;
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn total_entries(&self) -> usize {
        self.entries.len()
    }

    pub fn entries_for_min_level(&self, min_level_rank: u8) -> &VecDeque<Arc<RenderedLogEntry>> {
        let slot = usize::min(min_level_rank as usize, LOG_VIEW_SLOTS.saturating_sub(1));
        &self.visible_by_min_level[slot]
    }

    fn push_entry(&mut self, src: LogSource, entry: LogEntry) {
        let shared = Arc::new(Self::render_entry(src, entry));
        self.entries.push_back(shared.clone());

        let rank = log_level_rank(&shared.entry.log.level) as usize;
        let mut slot = 0;
        while slot <= rank {
            self.visible_by_min_level[slot].push_back(shared.clone());
            slot += 1;
        }

        self.trim_to_cap();
    }

    fn replace_source<I>(&mut self, src: LogSource, entries: I)
    where
        I: IntoIterator<Item = LogEntry>,
    {
        self.entries.retain(|entry| entry.entry.src != src);
        for entry in entries {
            self.entries
                .push_back(Arc::new(Self::render_entry(src.clone(), entry)));
        }
        self.trim_to_cap();
        self.rebuild_views();
    }

    fn trim_to_cap(&mut self) {
        while self.entries.len() > MAX_LOG_ENTRIES {
            let Some(evicted) = self.entries.pop_front() else {
                break;
            };
            let rank = log_level_rank(&evicted.entry.log.level) as usize;
            let mut slot = 0;
            while slot <= rank {
                let _ = self.visible_by_min_level[slot].pop_front();
                slot += 1;
            }
        }
    }

    fn rebuild_views(&mut self) {
        let mut slot = 0;
        while slot < LOG_VIEW_SLOTS {
            self.visible_by_min_level[slot].clear();
            slot += 1;
        }

        for entry in &self.entries {
            let rank = log_level_rank(&entry.entry.log.level) as usize;
            let mut view_slot = 0;
            while view_slot <= rank {
                self.visible_by_min_level[view_slot].push_back(entry.clone());
                view_slot += 1;
            }
        }
    }

    fn render_entry(src: LogSource, entry: LogEntry) -> RenderedLogEntry {
        RenderedLogEntry {
            ansi_parts: Arc::new(egui_sgr::ansi_to_rich_text(&entry.message)),
            entry: LogEntryOf {
                hash: fast_hash_log_entry(&entry),
                log: entry,
                src,
            },
        }
    }
}

pub type SharedLevelLogRings = Arc<RwLock<LevelLogView>>;

pub struct ProcessRawLogUpdate {
    pub profile: ContainerName,
    pub task_pgid: u32,
    pub reset: bool,
    pub start_seq: u64,
    pub next_seq: u64,
    pub logs: Vec<diag::RawLog>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NamespaceIndicator {
    pub mnt: Option<String>,
    pub net: Option<String>,
    pub pid: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ContainerState {
    pub process_list_snapshot: Option<diag::ProcessListSnapshot>,
    pub container_lifecycle: ContainerLifecycleState,
    pub child_pid: Option<i32>,
    pub child_alive: bool,
    pub up_connected: bool,
    pub up_connection: ConnectionState,
    pub up_error: Option<String>,
    pub serve_pid: Option<i32>,
    pub serve_alive: bool,
    pub diag_connection: ConnectionState,
    pub diag_error: Option<String>,
    pub hotconfig: HotConfig,
    pub template: TemplateConfig,
    pub sandbox_status: Option<SandboxStatus>,
    /// None = valid, Some(msg) = missing or parse error
    pub template_error: Option<String>,
    pub routing_state: Option<diag::RoutingState>,
    pub dns_state: Option<diag::DnsState>,
    pub diag_connected: bool,
    pub diag_summary: Option<DiagSummary>,
    #[serde(skip)]
    pub traffic: TrafficSnapshot,
    pub proxy_stats: HashMap<ProxyID, ProxyStats>,
    #[serde(skip)]
    pub hotconfig_value: serde_json::Value,
    #[serde(skip)]
    pub template_value: serde_json::Value,
    pub ns_alive: Option<NsAlive>,
    pub up_ns: Option<NamespaceIndicator>,
    pub keeper_ns: Option<NamespaceIndicator>,
    /// Client-side log storage with prebuilt views per minimum log level.
    #[serde(skip)]
    pub logs_by_level: SharedLevelLogRings,
    /// Local rolling copy of raw `DiagEvent`s received from tun_diag.sock.
    /// Used by the Traffic tab Logs sub-view.
    #[serde(skip)]
    pub diag_event_log: Vec<DiagEvent>,
    /// Client-side reconstruction of the server's live connection-tracking state.
    /// Used by the Traffic tab Connections sub-view.
    #[serde(skip)]
    pub conns_state: diag::ConnsState,
    /// Raw PTY bytes received since the previous snapshot, keyed by slot PID.
    #[serde(skip)]
    pub pty_streams: HashMap<u32, Vec<u8>>,
    pub veth_status: Vec<VethStatus>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VethStatus {
    pub success: bool,
    pub detail: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SupervisorSnapshot {
    pub profiles: BTreeMap<ContainerName, ContainerState>,
    pub ui_ns: NamespaceIndicator,
    pub namespace_warning: Option<String>,
    pub root_daemon_connection: ConnectionState,
    pub root_daemon_error: Option<String>,
    pub hotconfig_editor_status: Option<EditorStatus>,
    pub profile_editor_status: Option<EditorStatus>,
    pub constants_editor_status: Option<EditorStatus>,
    pub constants_editor_content: Option<String>,
    pub personal_runtime_state: diag::personal::PersonalRuntimeState,
    #[serde(skip)]
    pub root_daemon_logs: SharedLevelLogRings,
    pub auto_open_logs_target: Option<AutoOpenLogsTarget>,
    pub generated_at: SystemTime,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AutoOpenLogsTarget {
    pub profile: ContainerName,
    pub pid: u32,
    pub token: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EditorStatus {
    pub token: u64,
    pub ok: bool,
    pub profile: Option<ContainerName>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    /// Terminal error state: do not attempt further reconnects unless user intervenes.
    NoRetry,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerLifecycleState {
    #[default]
    Stopped,
    Starting,
    Running,
    Stopping {
        attempt: u8,
    },
    Killing {
        attempt: u8,
    },
}

impl ContainerLifecycleState {
    pub fn stop_attempt(self) -> u8 {
        match self {
            Self::Stopping { attempt } | Self::Killing { attempt } => attempt,
            Self::Stopped | Self::Starting | Self::Running => 0,
        }
    }

    pub fn is_active(self) -> bool {
        !matches!(self, Self::Stopped)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TabKind {
    Proxies,
    Processes,
    Traffic,
    Dns,
    Hotconfig,
    ProfileEditor,
}

#[derive(Debug)]
pub enum SupervisorCommand {
    StartUp {
        profile: ContainerName,
    },
    StartServe {
        profile: ContainerName,
    },
    StopServe {
        profile: ContainerName,
    },
    StartDaemon {
        profile: ContainerName,
        args: diag::SpawnArgs,
    },
    CreateVeth {
        profile: ContainerName,
        peer: ContainerName,
        veth_name: Option<String>,
        src_ip4: Option<std::net::Ipv4Addr>,
        dst_ip4: Option<std::net::Ipv4Addr>,
        prefix_len: u8,
    },
    SaveHotconfigPrivileged {
        profile: ContainerName,
        content: String,
    },
    SaveProfilePrivileged {
        profile: ContainerName,
        content: String,
    },
    SaveConstantsPrivileged {
        content: String,
    },
    LoadConstantsPrivileged,
    SetPersonalRuntimeState {
        profile: ContainerName,
        state: diag::personal::PersonalRuntimeState,
    },
    CreateProfilePrivileged {
        name: ContainerName,
        profile_content: String,
        hot_content: Option<String>,
    },
    RunSandbox {
        profile: ContainerName,
        reason: String,
    },
    SpawnPty {
        profile: ContainerName,
        args: diag::SpawnArgs,
    },
    DeleteContainer {
        profile: ContainerName,
    },
    StopContainer {
        profile: ContainerName,
    },
    KillContainer {
        profile: ContainerName,
    },
    KillManagedProcess {
        profile: ContainerName,
        task_pgid: u32,
    },
    /// Request raw stdout/stderr lines appended after `after_seq`.
    QueryRawLogs {
        profile: ContainerName,
        pid: u32,
        limit: usize,
        after_seq: Option<u64>,
    },
    StopQueryRawLogs {
        profile: ContainerName,
        pid: u32,
    },
    AttachPty {
        profile: ContainerName,
        pid: u32,
    },
    DetachPty {
        profile: ContainerName,
        pid: u32,
    },
    PtyInput {
        profile: ContainerName,
        pid: u32,
        data: Vec<u8>,
    },
    PtyResize {
        profile: ContainerName,
        pid: u32,
        cols: u16,
        rows: u16,
    },
    StartHotconfigDaemons {
        profile: ContainerName,
    },

    Ctrl {
        profile: ContainerName,
        cmd: ControlCommand,
    },

    ReloadHotconfig(ContainerName),
    ReloadProfile(ContainerName),
    LoadProfile(ContainerName),
    LoadProfiles(Vec<ContainerName>),
    RefreshNamespaces,

    Init,
    OnTabOpen {
        profile: ContainerName,
        tab: TabKind,
    },
    SetTrafficSubscription {
        profile: Option<ContainerName>,
    },
}

/// Shared PTY byte buffer.  The supervisor task appends; the UI thread drains.
type SharedPtyBuf = Arc<Mutex<HashMap<ContainerName, HashMap<u32, Vec<u8>>>>>;

type SharedPtyWakeState = Arc<PtyWakeState>;

struct PtyWakeState {
    generations: Mutex<HashMap<ContainerName, HashMap<u32, u64>>>,
    condvar: Condvar,
}

impl PtyWakeState {
    fn new() -> Self {
        Self {
            generations: Mutex::new(HashMap::new()),
            condvar: Condvar::new(),
        }
    }

    fn wait_for_change(&self, profile: &ContainerName, pid: u32, observed_generation: u64) -> u64 {
        let mut guard = self
            .generations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        loop {
            let current_generation = guard
                .get(profile)
                .and_then(|per_profile| per_profile.get(&pid))
                .copied()
                .unwrap_or_default();

            if current_generation > observed_generation {
                return current_generation;
            }

            guard = self
                .condvar
                .wait(guard)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    fn notify_pty_data(&self, profile: &ContainerName, pid: u32) {
        let mut guard = self
            .generations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let generation = guard
            .entry(profile.clone())
            .or_default()
            .entry(pid)
            .or_default();
        *generation = generation.saturating_add(1);
        self.condvar.notify_all();
    }

    fn wake_all(&self) {
        self.condvar.notify_all();
    }
}

/// When an external PTY viewport is active, holds its ViewportId so the
/// supervisor can repaint only that viewport (not the main window).
type SharedPtyViewportId = Arc<Mutex<Option<egui::ViewportId>>>;

#[derive(Clone)]
pub struct SupervisorHandle {
    cmd_tx: mpsc::UnboundedSender<SupervisorCommand>,
    snapshot_rx: std::sync::Arc<std::sync::Mutex<tokio::sync::watch::Receiver<SupervisorSnapshot>>>,
    process_raw_log_rx: Arc<Mutex<std_mpsc::Receiver<ProcessRawLogUpdate>>>,
    pty_buf: SharedPtyBuf,
    pty_wake_state: SharedPtyWakeState,
    pty_viewport_id: SharedPtyViewportId,
}

impl SupervisorHandle {
    pub fn new(ectx: egui::Context) -> (Self, SupervisorTask) {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (snapshot_tx, snapshot_rx) = tokio::sync::watch::channel(SupervisorSnapshot {
            profiles: BTreeMap::new(),
            ui_ns: NamespaceIndicator::default(),
            namespace_warning: None,
            root_daemon_connection: ConnectionState::Disconnected,
            root_daemon_error: None,
            hotconfig_editor_status: None,
            profile_editor_status: None,
            constants_editor_status: None,
            constants_editor_content: None,
            personal_runtime_state: diag::personal::PersonalRuntimeState::default(),
            root_daemon_logs: Arc::new(RwLock::new(LevelLogView::default())),
            auto_open_logs_target: None,
            generated_at: SystemTime::now(),
        });
        let (process_raw_log_tx, process_raw_log_rx) = std_mpsc::channel();

        let pty_buf: SharedPtyBuf = Arc::new(Mutex::new(HashMap::new()));
        let pty_wake_state: SharedPtyWakeState = Arc::new(PtyWakeState::new());
        let pty_viewport_id: SharedPtyViewportId = Arc::new(Mutex::new(None));
        let cmd_tx_for_self = cmd_tx.clone();
        (
            Self {
                cmd_tx: cmd_tx_for_self,
                snapshot_rx: std::sync::Arc::new(std::sync::Mutex::new(snapshot_rx)),
                process_raw_log_rx: Arc::new(Mutex::new(process_raw_log_rx)),
                pty_buf: pty_buf.clone(),
                pty_wake_state: pty_wake_state.clone(),
                pty_viewport_id: pty_viewport_id.clone(),
            },
            SupervisorTask {
                cmd_tx,
                cmd_rx,
                snapshot_tx,
                process_raw_log_tx,
                ectx,
                pty_buf,
                pty_wake_state,
                pty_viewport_id,
            },
        )
    }

    pub fn send(&self, cmd: SupervisorCommand) {
        info!(
            command = command_name(&cmd),
            profile = command_profile(&cmd).unwrap_or("<global>"),
            "queueing supervisor command"
        );
        if self.cmd_tx.send(cmd).is_err() {
            warn!("supervisor command channel dropped");
        }
    }

    pub fn try_recv_snapshot(&self) -> Option<SupervisorSnapshot> {
        let mut rx = self.snapshot_rx.lock().ok()?;
        if rx.has_changed().ok()? {
            Some(rx.borrow_and_update().clone())
        } else {
            None
        }
    }

    pub fn try_recv_process_raw_log(&self) -> Option<ProcessRawLogUpdate> {
        self.process_raw_log_rx.lock().ok()?.try_recv().ok()
    }

    pub fn current_snapshot(&self) -> Option<SupervisorSnapshot> {
        let rx = self.snapshot_rx.lock().ok()?;
        let snapshot = rx.borrow().clone();
        Some(snapshot)
    }

    pub fn subscribe_snapshots(&self) -> Option<tokio::sync::watch::Receiver<SupervisorSnapshot>> {
        let rx = self.snapshot_rx.lock().ok()?;
        Some(rx.clone())
    }

    async fn wait_for_snapshot<F>(&self, mut predicate: F) -> Result<SupervisorSnapshot>
    where
        F: FnMut(&SupervisorSnapshot) -> bool,
    {
        let mut rx = self
            .subscribe_snapshots()
            .context("supervisor snapshot subscription unavailable")?;
        if predicate(&rx.borrow()) {
            return Ok(rx.borrow().clone());
        }
        tokio::time::timeout(std::time::Duration::from_secs(30), async move {
            loop {
                rx.changed()
                    .await
                    .context("supervisor snapshot channel closed")?;
                if predicate(&rx.borrow()) {
                    return Ok(rx.borrow().clone());
                }
            }
        })
        .await
        .context("timed out waiting for supervisor state")?
    }

    pub async fn ensure_profile_running(&self, profile: &str) -> Result<()> {
        if self
            .current_snapshot()
            .as_ref()
            .and_then(|snapshot| snapshot.profiles.get(profile))
            .is_some_and(|state| state.child_alive && state.up_connected)
        {
            return Ok(());
        }
        self.send(SupervisorCommand::StartUp {
            profile: profile.to_string(),
        });
        let _ = self
            .wait_for_snapshot(|snapshot| {
                snapshot
                    .profiles
                    .get(profile)
                    .is_some_and(|state| state.child_alive && state.up_connected)
            })
            .await?;
        Ok(())
    }

    pub async fn spawn_managed_process(&self, profile: &str, args: diag::SpawnArgs) -> Result<u32> {
        let existing_slots = self
            .current_snapshot()
            .and_then(|snapshot| snapshot.profiles.get(profile).cloned())
            .and_then(|state| state.process_list_snapshot)
            .map(|snapshot| snapshot.procs.keys().copied().collect::<HashSet<u32>>())
            .unwrap_or_default();

        self.send(SupervisorCommand::StartDaemon {
            profile: profile.to_string(),
            args,
        });

        let snapshot = self
            .wait_for_snapshot(|snapshot| {
                snapshot
                    .profiles
                    .get(profile)
                    .and_then(|state| state.process_list_snapshot.as_ref())
                    .is_some_and(|plist| {
                        plist.procs.iter().any(|(task_pgid, entry)| {
                            !existing_slots.contains(task_pgid)
                                && matches!(entry.status, diag::ProcessStatus::Alive)
                        })
                    })
            })
            .await?;

        snapshot
            .profiles
            .get(profile)
            .and_then(|state| state.process_list_snapshot.as_ref())
            .and_then(|plist| {
                plist
                    .procs
                    .iter()
                    .filter(|(task_pgid, entry)| {
                        !existing_slots.contains(task_pgid)
                            && matches!(entry.status, diag::ProcessStatus::Alive)
                    })
                    .max_by_key(|(_, entry)| {
                        entry
                            .spawned_at
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|delta| delta.as_micros())
                            .unwrap_or(0)
                    })
                    .map(|(task_pgid, _)| *task_pgid)
            })
            .context("managed process spawned but no new task pgid was observed")
    }

    pub async fn stop_managed_process(&self, profile: &str, task_pgid: u32) -> Result<()> {
        self.send(SupervisorCommand::KillManagedProcess {
            profile: profile.to_string(),
            task_pgid,
        });
        let _ = self
            .wait_for_snapshot(|snapshot| {
                !snapshot
                    .profiles
                    .get(profile)
                    .and_then(|state| state.process_list_snapshot.as_ref())
                    .and_then(|plist| plist.procs.get(&task_pgid))
                    .is_some_and(|entry| {
                        matches!(
                            entry.status,
                            diag::ProcessStatus::Alive | diag::ProcessStatus::Terminating
                        )
                    })
            })
            .await?;
        Ok(())
    }

    /// Drain accumulated PTY bytes for a specific process.
    /// Returns the buffered bytes (may be empty) and removes them from the shared buffer.
    pub fn drain_pty(&self, profile: &ContainerName, pid: u32) -> Vec<u8> {
        let mut guard = match self.pty_buf.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        guard
            .get_mut(profile)
            .and_then(|m| m.remove(&pid))
            .unwrap_or_default()
    }

    pub fn wait_for_pty(&self, profile: &ContainerName, pid: u32, observed_generation: u64) -> u64 {
        self.pty_wake_state
            .wait_for_change(profile, pid, observed_generation)
    }

    pub fn wake_pty_waiters(&self) {
        self.pty_wake_state.wake_all();
    }

    /// Register an external PTY viewport so the supervisor repaints only it
    /// (instead of the main window) when PTY data arrives.
    pub fn set_pty_viewport(&self, id: egui::ViewportId) {
        if let Ok(mut guard) = self.pty_viewport_id.lock() {
            *guard = Some(id);
        }
    }

    /// Clear the external PTY viewport registration.
    pub fn clear_pty_viewport(&self) {
        if let Ok(mut guard) = self.pty_viewport_id.lock() {
            *guard = None;
        }
    }
}

pub struct SupervisorTask {
    cmd_tx: mpsc::UnboundedSender<SupervisorCommand>,
    cmd_rx: mpsc::UnboundedReceiver<SupervisorCommand>,
    snapshot_tx: tokio::sync::watch::Sender<SupervisorSnapshot>,
    process_raw_log_tx: std_mpsc::Sender<ProcessRawLogUpdate>,
    ectx: egui::Context,
    pty_buf: SharedPtyBuf,
    pty_wake_state: SharedPtyWakeState,
    pty_viewport_id: SharedPtyViewportId,
}

impl SupervisorTask {
    pub async fn run(self) {
        info!("supervisor task starting");
        let mut supervisor = Supervisor::new(
            self.cmd_tx.clone(),
            self.cmd_rx,
            self.snapshot_tx,
            self.process_raw_log_tx,
            self.ectx,
            self.pty_buf,
            self.pty_wake_state,
            self.pty_viewport_id,
        );
        if let Err(err) = supervisor.run().await {
            error!("supervisor stopped: {err:?}");
        }
        info!("supervisor task exiting");
    }
}

struct DiagState {
    accumulator: DiagAccumulator,
    dns_state: Option<diag::DnsState>,
    routing_state: Option<diag::RoutingState>,
    proxy_stats: HashMap<ProxyID, ProxyStats>,
    /// Rolling local copy of raw `DiagEvent`s (traffic log).
    /// Gets pre-populated via `QueryRecentDiagEvents` when first accessed.
    diag_event_log: VecDeque<DiagEvent>,
    /// Client-side reconstruction of the server's live connection-tracking state.
    /// Updated via `ConnsState::apply_event` on every live event and overwritten
    /// on `ConnsStateSnapshot` (from `QueryConnsState`).
    conns_state: diag::ConnsState,
}

/// Cached disk state for a profile — hotconfig + template.
/// Refreshed explicitly on Load/Reload commands; used by emit_snapshot to avoid
/// reading config files from disk on every diag event.
struct CachedProfileConfig {
    hotconfig: HotConfig,
    hotconfig_value: serde_json::Value,
    template: TemplateConfig,
    template_value: serde_json::Value,
    sandbox_status: Option<SandboxStatus>,
    template_error: Option<String>,
}

#[derive(Debug, Clone)]
enum PendingRootDaemonOp {
    InitializeBasisNamespace,
    SaveHotconfig { profile: ContainerName },
    SaveProfile { profile: ContainerName },
    SaveConstants,
    LoadConstants,
    CreateProfile { name: ContainerName },
}

#[derive(Clone, Debug, Default)]
struct ConnectionStatus {
    state: ConnectionState,
    last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionTarget {
    Up,
    Diag,
}

impl ConnectionTarget {
    fn label(self) -> &'static str {
        match self {
            Self::Up => "sp up",
            Self::Diag => "diag",
        }
    }
}

impl Default for DiagState {
    fn default() -> Self {
        Self {
            accumulator: DiagAccumulator::new(512, 256),
            dns_state: None,
            routing_state: None,
            proxy_stats: HashMap::new(),
            diag_event_log: VecDeque::new(),
            conns_state: diag::ConnsState::default(),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct ProfileNamespaceState {
    up: Option<NamespaceIndicator>,
    keeper: Option<NamespaceIndicator>,
}

fn command_name(cmd: &SupervisorCommand) -> &'static str {
    match cmd {
        SupervisorCommand::StartUp { .. } => "StartUp",
        SupervisorCommand::StartServe { .. } => "StartServe",
        SupervisorCommand::StopServe { .. } => "StopServe",
        SupervisorCommand::StartDaemon { .. } => "StartDaemon",
        SupervisorCommand::CreateVeth { .. } => "CreateVeth",
        SupervisorCommand::SaveHotconfigPrivileged { .. } => "SaveHotconfigPrivileged",
        SupervisorCommand::SaveProfilePrivileged { .. } => "SaveProfilePrivileged",
        SupervisorCommand::SaveConstantsPrivileged { .. } => "SaveConstantsPrivileged",
        SupervisorCommand::LoadConstantsPrivileged => "LoadConstantsPrivileged",
        SupervisorCommand::SetPersonalRuntimeState { .. } => "SetPersonalRuntimeState",
        SupervisorCommand::CreateProfilePrivileged { .. } => "CreateProfilePrivileged",
        SupervisorCommand::RunSandbox { .. } => "RunSandbox",
        SupervisorCommand::SpawnPty { .. } => "SpawnPty",
        SupervisorCommand::DeleteContainer { .. } => "DeleteContainer",
        SupervisorCommand::StopContainer { .. } => "StopContainer",
        SupervisorCommand::KillContainer { .. } => "KillContainer",
        SupervisorCommand::KillManagedProcess { .. } => "KillManagedProcess",
        SupervisorCommand::QueryRawLogs { .. } => "QueryRawLogs",
        SupervisorCommand::StopQueryRawLogs { .. } => "StopQueryRawLogs",
        SupervisorCommand::AttachPty { .. } => "AttachPty",
        SupervisorCommand::DetachPty { .. } => "DetachPty",
        SupervisorCommand::PtyInput { .. } => "PtyInput",
        SupervisorCommand::PtyResize { .. } => "PtyResize",
        SupervisorCommand::StartHotconfigDaemons { .. } => "StartHotconfigDaemons",
        SupervisorCommand::Ctrl { .. } => "Ctrl",
        SupervisorCommand::ReloadHotconfig(_) => "ReloadHotconfig",
        SupervisorCommand::ReloadProfile(_) => "ReloadProfile",
        SupervisorCommand::LoadProfile(_) => "LoadProfile",
        SupervisorCommand::LoadProfiles(_) => "LoadProfiles",
        SupervisorCommand::RefreshNamespaces => "RefreshNamespaces",
        SupervisorCommand::Init => "Init",
        SupervisorCommand::OnTabOpen { .. } => "OnTabOpen",
        SupervisorCommand::SetTrafficSubscription { .. } => "SetTrafficSubscription",
    }
}

fn command_profile(cmd: &SupervisorCommand) -> Option<&str> {
    match cmd {
        SupervisorCommand::StartUp { profile }
        | SupervisorCommand::StartServe { profile }
        | SupervisorCommand::StopServe { profile }
        | SupervisorCommand::SaveHotconfigPrivileged { profile, .. }
        | SupervisorCommand::SaveProfilePrivileged { profile, .. }
        | SupervisorCommand::SetPersonalRuntimeState { profile, .. }
        | SupervisorCommand::DeleteContainer { profile }
        | SupervisorCommand::StopContainer { profile }
        | SupervisorCommand::KillContainer { profile }
        | SupervisorCommand::ReloadHotconfig(profile)
        | SupervisorCommand::ReloadProfile(profile)
        | SupervisorCommand::LoadProfile(profile)
        | SupervisorCommand::StartHotconfigDaemons { profile }
        | SupervisorCommand::OnTabOpen { profile, .. } => Some(profile.as_str()),
        SupervisorCommand::StartDaemon { profile, .. }
        | SupervisorCommand::CreateVeth { profile, .. }
        | SupervisorCommand::RunSandbox { profile, .. }
        | SupervisorCommand::SpawnPty { profile, .. }
        | SupervisorCommand::KillManagedProcess { profile, .. }
        | SupervisorCommand::QueryRawLogs { profile, .. }
        | SupervisorCommand::StopQueryRawLogs { profile, .. }
        | SupervisorCommand::AttachPty { profile, .. }
        | SupervisorCommand::DetachPty { profile, .. }
        | SupervisorCommand::PtyInput { profile, .. }
        | SupervisorCommand::PtyResize { profile, .. }
        | SupervisorCommand::Ctrl { profile, .. }
        | SupervisorCommand::SetTrafficSubscription {
            profile: Some(profile),
        } => Some(profile.as_str()),
        SupervisorCommand::CreateProfilePrivileged { name, .. } => Some(name.as_str()),
        SupervisorCommand::SaveConstantsPrivileged { .. }
        | SupervisorCommand::LoadConstantsPrivileged
        | SupervisorCommand::LoadProfiles(_)
        | SupervisorCommand::RefreshNamespaces
        | SupervisorCommand::Init
        | SupervisorCommand::SetTrafficSubscription { profile: None } => None,
    }
}

fn daemon_event_name(event: &diag::DaemonEvent) -> &'static str {
    match event {
        diag::DaemonEvent::Spawned { .. } => "Spawned",
        diag::DaemonEvent::ProcessExit { .. } => "ProcessExit",
        diag::DaemonEvent::ProcessListSnapshot(_) => "ProcessListSnapshot",
        diag::DaemonEvent::Error { .. } => "Error",
        diag::DaemonEvent::Pong => "Pong",
        diag::DaemonEvent::Stopping => "Stopping",
        diag::DaemonEvent::Log(_) => "Log",
        diag::DaemonEvent::RecentLogs(_) => "RecentLogs",
        diag::DaemonEvent::RawLogs { .. } => "RawLogs",
        diag::DaemonEvent::PtyOutput { .. } => "PtyOutput",
        diag::DaemonEvent::PtyScrollback { .. } => "PtyScrollback",
        diag::DaemonEvent::Personal(_) => "Personal",
    }
}

fn diag_event_name(event: &DiagEvent) -> &'static str {
    match event {
        DiagEvent::Accept { .. } => "Accept",
        DiagEvent::Dispatched { .. } => "Dispatched",
        DiagEvent::Route { .. } => "Route",
        DiagEvent::Connected { .. } => "Connected",
        DiagEvent::Finished { .. } => "Finished",
        DiagEvent::DnsResolved { .. } => "DnsResolved",
        DiagEvent::DnsQuery { .. } => "DnsQuery",
        DiagEvent::Wait { .. } => "Wait",
        DiagEvent::WaitEnded { .. } => "WaitEnded",
        DiagEvent::HotConfigReloaded { .. } => "HotConfigReloaded",
        DiagEvent::HotConfigSnapshot { .. } => "HotConfigSnapshot",
        DiagEvent::DnsState { .. } => "DnsState",
        DiagEvent::RoutingState { .. } => "RoutingState",
        DiagEvent::UplinkStatsSnapshot { .. } => "UplinkStatsSnapshot",
        DiagEvent::Log(_) => "Log",
        DiagEvent::RecentLogs(_) => "RecentLogs",
        DiagEvent::RecentDiagEvents(_) => "RecentDiagEvents",
        DiagEvent::ConnsStateSnapshot { .. } => "ConnsStateSnapshot",
    }
}

struct Supervisor {
    cmd_rx: mpsc::UnboundedReceiver<SupervisorCommand>,
    event_tx: mpsc::UnboundedSender<SupervisorEvent>,
    event_rx: mpsc::UnboundedReceiver<SupervisorEvent>,
    snapshot_tx: tokio::sync::watch::Sender<SupervisorSnapshot>,
    process_raw_log_tx: std_mpsc::Sender<ProcessRawLogUpdate>,
    process_raw_log_subscription: Option<(ContainerName, u32, usize, Option<u64>)>,
    ectx: egui::Context,
    nsproxy_path: PathBuf,
    known_profiles: HashSet<ContainerName>,
    daemon_catalog: HashMap<ContainerName, Vec<ShellArgs>>,
    spawned_daemons: HashSet<String>,
    process_list_snapshot: HashMap<ContainerName, diag::ProcessListSnapshot>,
    up_cmd: HashMap<ContainerName, mpsc::UnboundedSender<diag::DaemonRequest>>,
    diag_cmd: HashMap<ContainerName, mpsc::UnboundedSender<ControlCommand>>,
    up_connection: HashMap<ContainerName, ConnectionStatus>,
    diag_connection: HashMap<ContainerName, ConnectionStatus>,
    root_daemon_cmd: Option<mpsc::UnboundedSender<diag::RootDaemonRequest>>,
    root_daemon_connection: ConnectionStatus,
    root_daemon_attempt: Arc<Mutex<ConnectionBackoff>>,
    pending_root_daemon_ops: HashMap<u64, PendingRootDaemonOp>,
    initialize_basis_namespace_pending: bool,
    namespace_warning: Option<String>,
    next_root_daemon_op_id: u64,
    hotconfig_editor_status: Option<EditorStatus>,
    profile_editor_status: Option<EditorStatus>,
    constants_editor_status: Option<EditorStatus>,
    constants_editor_content: Option<String>,
    personal_runtime_state: diag::personal::PersonalRuntimeState,
    root_daemon_logs: SharedLevelLogRings,
    diag_state: HashMap<ContainerName, DiagState>,
    ns_alive_status: HashMap<ContainerName, NsAliveStatus>,
    up_logs: HashMap<ContainerName, SharedLevelLogRings>,
    veth_status: HashMap<ContainerName, Vec<VethStatus>>,
    container_lifecycle: HashMap<ContainerName, ContainerLifecycleState>,
    up_attempt: HashMap<ContainerName, Arc<Mutex<ConnectionBackoff>>>,
    diag_attempt: HashMap<ContainerName, Arc<Mutex<ConnectionBackoff>>>,
    /// Cached config (hotconfig + template) per profile; refreshed on explicit Load/Reload.
    config_cache: HashMap<ContainerName, CachedProfileConfig>,
    /// Cached full NsAlive per profile; refreshed in refresh_profile_status_inner.
    ns_alive_cache: HashMap<ContainerName, NsAlive>,
    /// Cached namespace indicators per profile; refreshed in refresh_profile_status_inner.
    profile_ns_cache: HashMap<ContainerName, ProfileNamespaceState>,
    /// Cached namespace indicators for the UI process itself.
    ui_ns_cache: NamespaceIndicator,
    /// Shared PTY byte buffer — written here, drained by UI thread.
    pty_buf: SharedPtyBuf,
    /// Event-driven wake state for PTY readers waiting on new bytes.
    pty_wake_state: SharedPtyWakeState,
    /// Viewport ID of the external PTY window, if any.
    pty_viewport_id: SharedPtyViewportId,
    /// Notified whenever PTY data arrives.  A dedicated tokio task awaits this
    /// and calls request_repaint() once per batch, regardless of how many
    /// notify_one() calls fire in rapid succession.
    pty_repaint_notify: Arc<tokio::sync::Notify>,
    /// Baseline slot PID set captured when the UI requests StartDaemon.
    /// Used on the actor thread to detect newly spawned process slots.
    pending_auto_open_logs: HashMap<ContainerName, HashSet<u32>>,
    sandbox_in_flight: HashSet<ContainerName>,
    pending_start_sandbox: HashSet<ContainerName>,
    /// Profiles that already have a sandbox_status.json file watcher spawned.
    sandbox_status_watchers: HashSet<ContainerName>,
    /// Last computed "open raw logs for this process" target sent to UI.
    auto_open_logs_target: Option<AutoOpenLogsTarget>,
    /// Monotonic token for auto-open targets so UI can consume each target once.
    auto_open_logs_token: u64,
    /// Path to the UI-side control socket.  Spawned processes connect here.
    control_sock_path: PathBuf,
    /// Wall-clock time recorded immediately after successfully forking `sp up`.
    /// Used by `up_pid_alive` to reject PIDs belonging to a different process
    /// that happened to reuse the same PID after the original `sp up` exited.
    up_start_time: HashMap<ContainerName, SystemTime>,
    traffic_subscription: Option<ContainerName>,
}

impl Supervisor {
    fn merge_process_list_snapshot(
        existing: Option<&diag::ProcessListSnapshot>,
        incoming: &mut diag::ProcessListSnapshot,
    ) {
        let Some(existing) = existing else {
            return;
        };

        for (task_pgid, existing_entry) in &existing.procs {
            let Some(incoming_entry) = incoming.procs.get_mut(task_pgid) else {
                continue;
            };

            if existing_entry.spawned_at == incoming_entry.spawned_at
                && matches!(existing_entry.status, diag::ProcessStatus::Killed)
                && !matches!(incoming_entry.status, diag::ProcessStatus::Killed)
            {
                incoming_entry.status = diag::ProcessStatus::Killed;
            }
        }
    }

    fn start_up_profile(&mut self, profile: ContainerName) {
        info!(profile = profile.as_str(), "starting sp up flow");
        self.set_container_lifecycle(&profile, ContainerLifecycleState::Starting);
        // Clear stale process list from any previous sp up instance so restart
        // always shows a clean slate — new sp up sends its own fresh snapshot.
        self.process_list_snapshot.remove(&profile);
        self.pending_start_sandbox.insert(profile.clone());
        self.reset_backoff(&profile);
        let cli = Cli {
            conf: None,
            root: None,
            no_wrap_check: false,
            control_socket: Some(self.control_sock_path.clone()),
            cmd: MainCommand::Up {
                profile: profile.clone(),
                cmd: None,
                simulate_protocol_no_upgrade: false,
                simulate_conn_close: false,
                simulate_slow_shutdown: false,
            },
        };
        {
            let logs = self
                .up_logs
                .entry(profile.clone())
                .or_insert_with(|| Arc::new(RwLock::new(LevelLogView::default())))
                .clone();
            logs.write().unwrap_or_else(|e| e.into_inner()).clear();
        }
        push_up_log(
            &mut self.up_logs,
            &profile,
            diag::LogEntry {
                ts: diag::Timestamp::now(),
                level: "INFO".to_string(),
                target: "supervisor".to_string(),
                message: "Starting container...".to_string(),
                fields: Vec::new(),
            },
        );
        match spawn_nsproxy_cli(&self.nsproxy_path, &cli) {
            Ok(spawned) => {
                spawn_bootstrap_log_reader(
                    profile.clone(),
                    BootstrapLogStream::Stdout,
                    spawned.stdout_r,
                    self.event_tx.clone(),
                );
                spawn_bootstrap_log_reader(
                    profile.clone(),
                    BootstrapLogStream::Stderr,
                    spawned.stderr_r,
                    self.event_tx.clone(),
                );
                self.up_start_time
                    .insert(profile.clone(), SystemTime::now());
                info!(
                    profile = profile.as_str(),
                    pid = spawned.pid.as_raw(),
                    "spawned sp up process"
                );
            }
            Err(err) => {
                self.pending_start_sandbox.remove(&profile);
                self.set_container_lifecycle(&profile, ContainerLifecycleState::Stopped);
                warn!("failed to start sp up for {}: {err:?}", profile);
            }
        }
        self.known_profiles.insert(profile.clone());
        self.refresh_profile_status(&profile);
    }

    fn next_editor_status_token(&mut self) -> u64 {
        let token = self.next_root_daemon_op_id;
        self.next_root_daemon_op_id = self.next_root_daemon_op_id.saturating_add(1);
        token
    }

    fn publish_editor_status(
        &mut self,
        op: &PendingRootDaemonOp,
        ok: bool,
        token: u64,
        message: impl Into<String>,
    ) {
        let profile = match op {
            PendingRootDaemonOp::InitializeBasisNamespace => None,
            PendingRootDaemonOp::SaveHotconfig { profile }
            | PendingRootDaemonOp::SaveProfile { profile } => Some(profile.clone()),
            PendingRootDaemonOp::SaveConstants | PendingRootDaemonOp::LoadConstants => None,
            PendingRootDaemonOp::CreateProfile { name } => Some(name.clone()),
        };
        let status = EditorStatus {
            token,
            ok,
            profile,
            message: message.into(),
        };
        match op {
            PendingRootDaemonOp::InitializeBasisNamespace => {}
            PendingRootDaemonOp::SaveHotconfig { .. } => {
                self.hotconfig_editor_status = Some(status);
            }
            PendingRootDaemonOp::SaveProfile { .. } | PendingRootDaemonOp::CreateProfile { .. } => {
                self.profile_editor_status = Some(status);
            }
            PendingRootDaemonOp::SaveConstants | PendingRootDaemonOp::LoadConstants => {
                self.constants_editor_status = Some(status);
            }
        }
    }

    fn fail_inflight_root_daemon_ops(&mut self, message: impl AsRef<str>) {
        let message = message.as_ref().to_string();
        let ops = std::mem::take(&mut self.pending_root_daemon_ops);
        for (_op_id, op) in ops {
            if matches!(op, PendingRootDaemonOp::InitializeBasisNamespace) {
                self.namespace_warning = Some(message.clone());
                continue;
            }
            let token = self.next_editor_status_token();
            self.publish_editor_status(&op, false, token, message.clone());
        }
    }

    fn new(
        _cmd_tx: mpsc::UnboundedSender<SupervisorCommand>,
        cmd_rx: mpsc::UnboundedReceiver<SupervisorCommand>,
        snapshot_tx: tokio::sync::watch::Sender<SupervisorSnapshot>,
        process_raw_log_tx: std_mpsc::Sender<ProcessRawLogUpdate>,
        ectx: egui::Context,
        pty_buf: SharedPtyBuf,
        pty_wake_state: SharedPtyWakeState,
        pty_viewport_id: SharedPtyViewportId,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let control_sock_path =
            state_paths::persist_root().join(format!("nsproxy-ui-{}.sock", std::process::id()));
        Self {
            cmd_rx,
            event_tx,
            event_rx,
            snapshot_tx,
            process_raw_log_tx,
            process_raw_log_subscription: None,
            ectx,
            nsproxy_path: which::which("sproxy").unwrap(),
            known_profiles: HashSet::new(),
            daemon_catalog: HashMap::new(),
            spawned_daemons: HashSet::new(),
            process_list_snapshot: HashMap::new(),
            up_cmd: HashMap::new(),
            diag_cmd: HashMap::new(),
            up_connection: HashMap::new(),
            diag_connection: HashMap::new(),
            root_daemon_cmd: None,
            root_daemon_connection: ConnectionStatus::default(),
            root_daemon_attempt: Arc::new(Mutex::new(ConnectionBackoff::default())),
            pending_root_daemon_ops: HashMap::new(),
            initialize_basis_namespace_pending: false,
            namespace_warning: None,
            next_root_daemon_op_id: 1,
            hotconfig_editor_status: None,
            profile_editor_status: None,
            constants_editor_status: None,
            constants_editor_content: None,
            personal_runtime_state: diag::personal::PersonalRuntimeState::default(),
            root_daemon_logs: Arc::new(RwLock::new(LevelLogView::default())),
            diag_state: HashMap::new(),
            ns_alive_status: HashMap::new(),
            up_logs: HashMap::new(),
            veth_status: HashMap::new(),
            container_lifecycle: HashMap::new(),
            up_attempt: HashMap::new(),
            diag_attempt: HashMap::new(),
            config_cache: HashMap::new(),
            ns_alive_cache: HashMap::new(),
            profile_ns_cache: HashMap::new(),
            ui_ns_cache: probe_namespace_indicator(std::process::id() as i32).unwrap_or_default(),
            pty_buf,
            pty_wake_state,
            pty_viewport_id,
            pty_repaint_notify: Arc::new(tokio::sync::Notify::new()),
            pending_auto_open_logs: HashMap::new(),
            sandbox_in_flight: HashSet::new(),
            pending_start_sandbox: HashSet::new(),
            sandbox_status_watchers: HashSet::new(),
            auto_open_logs_target: None,
            auto_open_logs_token: 0,
            control_sock_path,
            up_start_time: HashMap::new(),
            traffic_subscription: None,
        }
    }

    fn set_container_lifecycle(
        &mut self,
        profile: &ContainerName,
        lifecycle: ContainerLifecycleState,
    ) {
        self.container_lifecycle.insert(profile.clone(), lifecycle);
    }

    /// Repaint the appropriate viewport when PTY data arrives.
    /// If an external PTY viewport is registered, repaint only that viewport.
    /// Otherwise repaint the main window (for the inline PTY panel case).
    ///
    /// We cap to ~120 fps with a delay so that rapid PTY output (e.g. typing
    /// echo or htop redrawing) doesn't call request_repaint() hundreds of
    /// times per second and pin the render loop at uncapped frame rate.
    /// The supervisor actor may receive one PtyOutput chunk per echo byte,
    /// so without this every keystroke could trigger dozens of immediate
    /// repaints back-to-back. 8 ms gives ~120 fps max repaint rate, which
    /// is plenty for interactive terminal use.
    fn repaint_pty_target(&self) {
        // Wake the dedicated repaint task; multiple concurrent calls coalesce.
        self.pty_repaint_notify.notify_one();
    }

    fn container_lifecycle(&self, profile: &ContainerName) -> ContainerLifecycleState {
        self.container_lifecycle
            .get(profile)
            .copied()
            .unwrap_or_default()
    }

    fn reconcile_container_lifecycle(
        &mut self,
        profile: &ContainerName,
        child_alive: bool,
        start_in_flight: bool,
    ) {
        let previous = self.container_lifecycle(profile);
        let next = if child_alive {
            match previous {
                ContainerLifecycleState::Stopping { attempt } => {
                    ContainerLifecycleState::Stopping { attempt }
                }
                ContainerLifecycleState::Killing { attempt } => {
                    ContainerLifecycleState::Killing { attempt }
                }
                ContainerLifecycleState::Stopped
                | ContainerLifecycleState::Starting
                | ContainerLifecycleState::Running => ContainerLifecycleState::Running,
            }
        } else {
            match previous {
                ContainerLifecycleState::Starting if start_in_flight => {
                    ContainerLifecycleState::Starting
                }
                ContainerLifecycleState::Stopped
                | ContainerLifecycleState::Starting
                | ContainerLifecycleState::Running
                | ContainerLifecycleState::Stopping { .. }
                | ContainerLifecycleState::Killing { .. } => ContainerLifecycleState::Stopped,
            }
        };
        self.set_container_lifecycle(profile, next);
    }

    /// Spawn a one-time file-watcher for `sandbox_status.json` for `profile` if not already running.
    fn ensure_sandbox_status_watcher(&mut self, profile: &ContainerName) {
        if self.sandbox_status_watchers.contains(profile) {
            return;
        }
        self.sandbox_status_watchers.insert(profile.clone());
        let path = state_paths::sandbox_status(profile.as_str());
        let profile = profile.clone();
        let event_tx = self.event_tx.clone();
        tokio::spawn(async move {
            // Watch the parent directory so we also catch the initial create.
            let watch_dir = path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| path.clone());
            let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
            let mut watcher = match RecommendedWatcher::new(
                move |res: std::result::Result<Event, notify::Error>| {
                    if let Ok(ev) = res {
                        let relevant =
                            matches!(
                                ev.kind,
                                EventKind::Modify(ModifyKind::Data(_))
                                    | EventKind::Create(_)
                                    | EventKind::Remove(_)
                            ) && ev.paths.iter().any(|p| p.ends_with("sandbox_status.json"));
                        if relevant {
                            let _ = tx.try_send(());
                        }
                    }
                },
                notify::Config::default(),
            ) {
                Ok(w) => w,
                Err(e) => {
                    warn!(
                        profile = profile.as_str(),
                        "sandbox_status watcher init failed: {e}"
                    );
                    return;
                }
            };
            if let Err(e) = watcher.watch(&watch_dir, notify::RecursiveMode::NonRecursive) {
                warn!(
                    profile = profile.as_str(),
                    "sandbox_status watcher start failed: {e}"
                );
                return;
            }
            while rx.recv().await.is_some() {
                // Debounce: drain any rapid-fire extras.
                while let Ok(()) = rx.try_recv() {}
                // read_sandbox_status enforces the boot_id invariant and purges stale files.
                let status = read_sandbox_status(profile.as_str());
                let _ = event_tx.send(SupervisorEvent::SandboxStatusChanged {
                    profile: profile.clone(),
                    status,
                });
            }
        });
    }

    /// Re-read hotconfig and template from disk for `profile` and store in the cache.
    /// Called on explicit Load/Reload commands.  `emit_snapshot` reads from this cache.
    fn refresh_config_cache(&mut self, profile: &ContainerName) {
        let hotconfig = load_hotconfig_from_disk(profile).unwrap_or_default();
        let hotconfig_value = serde_json::to_value(&hotconfig).unwrap_or(serde_json::json!({}));
        let (template, template_error) = match load_template_from_disk(profile) {
            Ok(t) => (t, None),
            Err(e) => (TemplateConfig::default(), Some(e)),
        };
        let template_value = serde_json::to_value(&template).unwrap_or(serde_json::json!({}));
        let sandbox_status = load_sandbox_status_from_disk(profile);
        self.config_cache.insert(
            profile.clone(),
            CachedProfileConfig {
                hotconfig,
                hotconfig_value,
                template,
                template_value,
                sandbox_status,
                template_error,
            },
        );
        self.ensure_sandbox_status_watcher(profile);
    }

    /// Merge the route held by the live serve process into a configuration
    /// being persisted. This avoids overwriting a proxy selection with the
    /// independent HotConfig editor copy.
    fn merge_live_route_into_hotconfig(&self, profile: &ContainerName, hotconfig: &mut HotConfig) {
        let Some(routing) = self
            .diag_state
            .get(profile)
            .and_then(|state| state.routing_state.as_ref())
        else {
            return;
        };

        hotconfig.route = match &routing.selected_proxy {
            Some(proxy_id) => HotRoute::SimpleProxy {
                proxy_id: proxy_id.clone(),
            },
            None => HotRoute::None,
        };
    }

    fn spawn_sandbox_reconcile(&mut self, profile: &ContainerName, reason: &str) {
        if !self
            .ns_alive_status
            .get(profile)
            .map(|status| status.child_alive)
            .unwrap_or(false)
        {
            push_up_log(
                &mut self.up_logs,
                profile,
                plain_log_entry(
                    "INFO",
                    "supervisor",
                    format!("Skipping sandbox reconcile ({reason}): container is not running yet"),
                ),
            );
            return;
        }

        if !self.sandbox_in_flight.insert(profile.clone()) {
            push_up_log(
                &mut self.up_logs,
                profile,
                plain_log_entry(
                    "INFO",
                    "supervisor",
                    format!("Sandbox reconcile already running ({reason})"),
                ),
            );
            return;
        }

        push_up_log(
            &mut self.up_logs,
            profile,
            plain_log_entry(
                "INFO",
                "supervisor",
                format!("Running sp sandbox ({reason})"),
            ),
        );

        let cli = Cli {
            conf: None,
            root: None,
            no_wrap_check: false,
            control_socket: None,
            cmd: MainCommand::Sandbox {
                profile: profile.clone(),
            },
        };

        match spawn_nsproxy_cli(&self.nsproxy_path, &cli) {
            Ok(spawned) => {
                spawn_child_log_reader(
                    profile.clone(),
                    BootstrapLogStream::Stdout,
                    spawned.stdout_r,
                    self.event_tx.clone(),
                    |profile, stream, line| SupervisorEvent::SandboxProcessLog {
                        profile,
                        stream,
                        line,
                    },
                );
                spawn_child_log_reader(
                    profile.clone(),
                    BootstrapLogStream::Stderr,
                    spawned.stderr_r,
                    self.event_tx.clone(),
                    |profile, stream, line| SupervisorEvent::SandboxProcessLog {
                        profile,
                        stream,
                        line,
                    },
                );
                spawn_child_waiter(
                    profile.clone(),
                    spawned.pid,
                    self.event_tx.clone(),
                    |profile, success, detail| SupervisorEvent::SandboxFinished {
                        profile,
                        success,
                        detail,
                    },
                );
            }
            Err(err) => {
                self.sandbox_in_flight.remove(profile);
                push_up_log(
                    &mut self.up_logs,
                    profile,
                    plain_log_entry(
                        "WARN",
                        "supervisor",
                        format!("Failed to spawn sp sandbox: {err}"),
                    ),
                );
            }
        }
    }

    fn spawn_veth(
        &mut self,
        profile: &ContainerName,
        spec: HotVeth,
        reason: &str,
    ) {
        let cli = Cli {
            conf: None,
            root: None,
            no_wrap_check: false,
            control_socket: None,
            cmd: MainCommand::Veth {
                src: spec.src.parse().unwrap_or_else(|_| nsproxy_core::NsArg::Container(profile.clone())),
                dst: spec.dst.parse().unwrap_or_else(|_| nsproxy_core::NsArg::Container(profile.clone())),
                veth_name: spec.veth_name,
                src_ip4: spec.src_ip4,
                dst_ip4: spec.dst_ip4,
                prefix_len: spec.prefix_len,
                log: None,
            },
        };
        self.veth_status.insert(
            profile.clone(),
            vec![VethStatus {
                success: true,
                detail: format!("creation requested ({reason})"),
            }],
        );
        match spawn_nsproxy_cli(&self.nsproxy_path, &cli) {
            Ok(spawned) => {
                spawn_child_log_reader(
                    profile.clone(),
                    BootstrapLogStream::Stdout,
                    spawned.stdout_r,
                    self.event_tx.clone(),
                    |profile, stream, line| SupervisorEvent::VethProcessLog {
                        profile,
                        stream,
                        line,
                    },
                );
                spawn_child_log_reader(
                    profile.clone(),
                    BootstrapLogStream::Stderr,
                    spawned.stderr_r,
                    self.event_tx.clone(),
                    |profile, stream, line| SupervisorEvent::VethProcessLog {
                        profile,
                        stream,
                        line,
                    },
                );
                spawn_child_waiter(
                    profile.clone(),
                    spawned.pid,
                    self.event_tx.clone(),
                    |profile, success, detail| SupervisorEvent::VethFinished {
                        profile,
                        success,
                        detail,
                    },
                );
            }
            Err(err) => {
                let detail = format!("failed to start veth command: {err}");
                self.veth_status.insert(
                    profile.clone(),
                    vec![VethStatus {
                        success: false,
                        detail: detail.clone(),
                    }],
                );
                push_up_log(
                    &mut self.up_logs,
                    profile,
                    plain_log_entry("WARN", "veth", detail),
                );
            }
        }
    }

    /// Send `EnsureDbus` to sp up for `profile` if:
    /// - the profile has `dbus: container` in TemplateConfig
    /// - the persisted sandbox status shows the sandbox is already `Pivoted`
    /// - sp up is currently connected
    fn maybe_ensure_dbus(&mut self, profile: &ContainerName) {
        let dbus_enabled = load_template_from_disk(profile)
            .map(|t| t.dbus == nsproxy_core::DbusMode::Container)
            .unwrap_or(false);
        if !dbus_enabled {
            return;
        }
        let sandbox_status = load_sandbox_status_from_disk(profile);
        let sandbox_ready = sandbox_status.as_ref().is_some_and(|s| {
            s.detected_state == nsproxy_core::sandbox::SandboxState::Pivoted
                || s.configured_mode == nsproxy_core::SandboxMode::Overlay
        });
        if !sandbox_ready {
            info!(
                profile = profile.as_str(),
                sandbox_status = ?sandbox_status.as_ref().map(|s| (&s.configured_mode, &s.detected_state)),
                "maybe_ensure_dbus: sandbox not ready yet, skipping"
            );
            return;
        }
        if let Some(tx) = self.up_cmd.get(profile) {
            let _ = tx.send(diag::DaemonRequest::EnsureDbus);
            push_up_log(
                &mut self.up_logs,
                profile,
                plain_log_entry("INFO", "supervisor", "Ensuring sp dbus is running"),
            );
        } else {
            warn!(
                profile = profile.as_str(),
                "maybe_ensure_dbus: up_cmd tx not present, cannot send EnsureDbus"
            );
        }
    }

    async fn run(&mut self) -> Result<()> {
        info!("supervisor run loop entered");
        self.emit_snapshot();
        // Bind the control socket and spawn the accept loop.
        // Spawned processes connect here and identify themselves with a ControlSocketGreeting.
        let ctrl_path = self.control_sock_path.clone();
        let event_tx_ctrl = self.event_tx.clone();
        tokio::spawn(async move {
            control_socket_accept_loop(ctrl_path, event_tx_ctrl).await;
        });
        // Deduplicated PTY repaint task.  Many notify_one() calls while the
        // task is already running coalesce into a single pending wake-up, so
        // we fire request_repaint() at most once per "batch" of PTY data with
        // no arbitrary timer boundary.
        {
            let notify = self.pty_repaint_notify.clone();
            let ectx = self.ectx.clone();
            let pty_viewport_id = self.pty_viewport_id.clone();
            tokio::spawn(async move {
                loop {
                    notify.notified().await;
                    let vp = pty_viewport_id.lock().ok().and_then(|g| *g);
                    if let Some(viewport_id) = vp {
                        ectx.request_repaint_of(viewport_id);
                    } else {
                        ectx.request_repaint();
                    }
                }
            });
        }
        let mut process_raw_log_poll = tokio::time::interval(std::time::Duration::from_secs(1));
        process_raw_log_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        process_raw_log_poll.tick().await;
        loop {
            tokio::select! {
                Some(cmd) = self.cmd_rx.recv() => {
                    // PtyInput/PtyResize don't change any snapshot-visible state;
                    // skip emit_snapshot() to avoid a redundant request_repaint()
                    // on every keystroke (the PTY repaint is handled by the
                    // coalescing pty_repaint_notify task via repaint_pty_target()).
                    let needs_snapshot = !matches!(
                        cmd,
                        SupervisorCommand::PtyInput { .. }
                            | SupervisorCommand::PtyResize { .. }
                            | SupervisorCommand::QueryRawLogs { .. }
                            | SupervisorCommand::StopQueryRawLogs { .. }
                    );
                    self.handle_command(cmd).await;
                    if needs_snapshot {
                        self.emit_snapshot();
                    }
                }
                Some(ev) = self.event_rx.recv() => {
                    let needs_snapshot = self.event_requires_snapshot(&ev);
                    self.handle_event(ev);
                    if needs_snapshot {
                        self.emit_snapshot();
                    }
                }
                _ = process_raw_log_poll.tick(), if self.process_raw_log_subscription.is_some() => {
                    self.poll_process_raw_logs();
                }
                else => break,
            }
        }
        info!("supervisor run loop exiting");
        Ok(())
    }

    fn poll_process_raw_logs(&self) {
        let Some((profile, pid, limit, after_seq)) = &self.process_raw_log_subscription else {
            return;
        };
        if let Some(tx) = self.up_cmd.get(profile) {
            let _ = tx.send(diag::DaemonRequest::QueryRawLogs {
                task_pgid: *pid,
                limit: *limit,
                after_seq: *after_seq,
            });
        }
    }

    async fn handle_command(&mut self, cmd: SupervisorCommand) {
        let command = command_name(&cmd);
        let profile = command_profile(&cmd).unwrap_or("<global>").to_string();
        let started = std::time::Instant::now();
        info!(command, profile, "supervisor handling command");
        match cmd {
            SupervisorCommand::StartUp { profile } => {
                self.start_up_profile(profile);
            }
            SupervisorCommand::StartServe { profile } => {
                info!(
                    profile = profile.as_str(),
                    "starting sp serve via up daemon"
                );
                self.known_profiles.insert(profile.clone());
                // Fresh backoff — intentional start, connect immediately.
                self.reset_backoff(&profile);
                self.ensure_up_client(&profile);
                push_up_log(
                    &mut self.up_logs,
                    &profile,
                    diag::LogEntry {
                        ts: diag::Timestamp::now(),
                        level: "INFO".to_string(),
                        target: "supervisor".to_string(),
                        message: "Starting sp serve...".to_string(),
                        fields: Vec::new(),
                    },
                );
                let cli = Cli {
                    conf: None,
                    root: None,
                    no_wrap_check: false,
                    control_socket: Some(self.control_sock_path.clone()),
                    cmd: MainCommand::Serve {
                        profile: profile.clone(),
                        tun_name: None,
                        simple: None,
                        no_default: false,
                        log: None,
                        clash: None,
                        no_dns_capture: None,
                        internal_dns_server: None,
                    },
                };
                match bincode::serialize(&cli) {
                    Ok(cli_bincode) => {
                        if let Some(tx) = self.up_cmd.get(&profile) {
                            info!(
                                profile = profile.as_str(),
                                bytes = cli_bincode.len(),
                                "sending SpawnCli to up daemon"
                            );
                            let _ = tx.send(diag::DaemonRequest::SpawnCli {
                                cli_bincode,
                                ns: diag::NamespaceSpawn::Outside,
                            });
                        }
                    }
                    Err(err) => warn!("failed to serialize serve cli for {}: {err}", profile),
                }
                self.refresh_profile_status(&profile);
            }
            SupervisorCommand::StopServe { profile } => {
                info!(profile = profile.as_str(), "stopping sp serve");
                let ns_meta = state_paths::profile_ns_meta(profile.as_str());
                if let Ok(ns_alive) = read_ns_alive(&ns_meta) {
                    if let Some(pid) = ns_alive.serve_pid {
                        info!(
                            profile = profile.as_str(),
                            pid, "sending SIGTERM to serve pid"
                        );
                        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                    }
                }
                self.refresh_profile_status(&profile);
            }
            SupervisorCommand::StartDaemon { profile, args } => {
                info!(profile = profile.as_str(), exec = ?args.exec, cwd = ?args.cwd, argc = args.args.len(), "starting managed daemon");
                self.known_profiles.insert(profile.clone());
                let existing_slots = self
                    .process_list_snapshot
                    .get(&profile)
                    .map(|snap| snap.procs.keys().copied().collect::<HashSet<u32>>())
                    .unwrap_or_default();
                self.pending_auto_open_logs
                    .insert(profile.clone(), existing_slots);
                self.ensure_up_client(&profile);
                if let Some(tx) = self.up_cmd.get(&profile) {
                    info!(profile = profile.as_str(), exec = ?args.exec, argc = args.args.len(), "sending Spawn request to up daemon");
                    let _ = tx.send(diag::DaemonRequest::Spawn { args });
                }
            }
            SupervisorCommand::CreateVeth {
                profile,
                peer,
                veth_name,
                src_ip4,
                dst_ip4,
                prefix_len,
            } => {
                self.spawn_veth(
                    &profile,
                    HotVeth {
                        src: profile.clone(),
                        dst: peer,
                        veth_name,
                        src_ip4,
                        dst_ip4,
                        prefix_len,
                    },
                    "temporary",
                );
            }
            SupervisorCommand::SaveHotconfigPrivileged { profile, content } => {
                let content = match serde_json::from_str::<HotConfig>(&content) {
                    Ok(mut hotconfig) => {
                        self.merge_live_route_into_hotconfig(&profile, &mut hotconfig);
                        hotconfig.process();
                        serde_json::to_string_pretty(&hotconfig).unwrap_or(content)
                    }
                    Err(_) => content,
                };
                self.queue_root_daemon_op(
                    diag::RootDaemonOp::WriteFile {
                        path: state_paths::hot_config(profile.as_str()),
                        content: content.into_bytes(),
                        create_parent: true,
                    },
                    PendingRootDaemonOp::SaveHotconfig { profile },
                );
            }
            SupervisorCommand::SaveProfilePrivileged { profile, content } => {
                self.queue_root_daemon_op(
                    diag::RootDaemonOp::WriteFile {
                        path: state_paths::profile_config(profile.as_str()),
                        content: content.into_bytes(),
                        create_parent: true,
                    },
                    PendingRootDaemonOp::SaveProfile { profile },
                );
            }
            SupervisorCommand::SaveConstantsPrivileged { content } => {
                self.queue_root_daemon_op(
                    diag::RootDaemonOp::WriteFile {
                        path: state_paths::constants_config(),
                        content: content.into_bytes(),
                        create_parent: true,
                    },
                    PendingRootDaemonOp::SaveConstants,
                );
            }
            SupervisorCommand::LoadConstantsPrivileged => {
                self.queue_root_daemon_op(
                    diag::RootDaemonOp::ReadFile {
                        path: state_paths::constants_config(),
                    },
                    PendingRootDaemonOp::LoadConstants,
                );
            }
            SupervisorCommand::SetPersonalRuntimeState { profile, state } => {
                self.personal_runtime_state = state.clone();
                self.ensure_up_client(&profile);
                if let Some(tx) = self.up_cmd.get(&profile) {
                    let _ = tx.send(diag::DaemonRequest::Personal(
                        diag::personal::PersonalDaemonRequest::SetState(state),
                    ));
                }
            }
            SupervisorCommand::CreateProfilePrivileged {
                name,
                profile_content,
                hot_content,
            } => {
                self.queue_root_daemon_op(
                    diag::RootDaemonOp::CreateProfile {
                        name: name.clone(),
                        profile_content,
                        hot_content,
                    },
                    PendingRootDaemonOp::CreateProfile { name },
                );
            }
            SupervisorCommand::RunSandbox { profile, reason } => {
                info!(
                    profile = profile.as_str(),
                    reason, "running sandbox reconcile"
                );
                self.known_profiles.insert(profile.clone());
                self.refresh_profile_status(&profile);
                self.spawn_sandbox_reconcile(&profile, &reason);
            }
            SupervisorCommand::SpawnPty { profile, args } => {
                info!(profile = profile.as_str(), exec = ?args.exec, cwd = ?args.cwd, argc = args.args.len(), "starting PTY-managed process");
                self.known_profiles.insert(profile.clone());
                self.ensure_up_client(&profile);
                if let Some(tx) = self.up_cmd.get(&profile) {
                    let _ = tx.send(diag::DaemonRequest::SpawnPty { args });
                }
            }
            SupervisorCommand::DeleteContainer { profile } => {
                info!(
                    profile = profile.as_str(),
                    "deleting container via sp down --rm"
                );
                push_up_log(
                    &mut self.up_logs,
                    &profile,
                    diag::LogEntry {
                        ts: diag::Timestamp::now(),
                        level: "INFO".to_string(),
                        target: "supervisor".to_string(),
                        message: "Deleting container...".to_string(),
                        fields: Vec::new(),
                    },
                );
                let cli = Cli {
                    conf: None,
                    root: None,
                    no_wrap_check: false,
                    control_socket: None,
                    cmd: MainCommand::Down {
                        profile: profile.clone(),
                        rm: true,
                    },
                };
                match spawn_nsproxy_cli(&self.nsproxy_path, &cli) {
                    Ok(spawned) => {
                        spawn_child_log_reader(
                            profile.clone(),
                            BootstrapLogStream::Stdout,
                            spawned.stdout_r,
                            self.event_tx.clone(),
                            |profile, stream, line| SupervisorEvent::DeleteProcessLog {
                                profile,
                                stream,
                                line,
                            },
                        );
                        spawn_child_log_reader(
                            profile.clone(),
                            BootstrapLogStream::Stderr,
                            spawned.stderr_r,
                            self.event_tx.clone(),
                            |profile, stream, line| SupervisorEvent::DeleteProcessLog {
                                profile,
                                stream,
                                line,
                            },
                        );
                        spawn_child_waiter(
                            profile,
                            spawned.pid,
                            self.event_tx.clone(),
                            |profile, success, detail| SupervisorEvent::DeleteContainerFinished {
                                profile,
                                success,
                                detail,
                            },
                        );
                    }
                    Err(err) => {
                        warn!(
                            profile = profile.as_str(),
                            "failed to spawn sp down: {err:?}"
                        );
                        push_up_log(
                            &mut self.up_logs,
                            &profile,
                            diag::LogEntry {
                                ts: diag::Timestamp::now(),
                                level: "WARN".to_string(),
                                target: "supervisor".to_string(),
                                message: format!("Failed to delete container: {err}"),
                                fields: Vec::new(),
                            },
                        );
                    }
                }
            }
            SupervisorCommand::StopContainer { profile } => {
                info!(
                    profile = profile.as_str(),
                    "requesting graceful container stop via up daemon"
                );
                self.reset_backoff(&profile);
                push_up_log(
                    &mut self.up_logs,
                    &profile,
                    diag::LogEntry {
                        ts: diag::Timestamp::now(),
                        level: "INFO".to_string(),
                        target: "supervisor".to_string(),
                        message: "Stopping container...".to_string(),
                        fields: Vec::new(),
                    },
                );
                self.refresh_profile_state_only(&profile);
                let still_running = self
                    .ns_alive_status
                    .get(&profile)
                    .is_some_and(|status| status.child_alive);

                if !still_running {
                    info!(
                        profile = profile.as_str(),
                        "stop requested while profile already stopped"
                    );
                    self.set_container_lifecycle(&profile, ContainerLifecycleState::Stopped);
                    push_up_log(
                        &mut self.up_logs,
                        &profile,
                        diag::LogEntry {
                            ts: diag::Timestamp::now(),
                            level: "INFO".to_string(),
                            target: "supervisor".to_string(),
                            message: "Profile already stopped".to_string(),
                            fields: Vec::new(),
                        },
                    );
                    self.refresh_profile_status(&profile);
                    return;
                }

                self.set_container_lifecycle(
                    &profile,
                    ContainerLifecycleState::Stopping { attempt: 1 },
                );

                // The pid watcher is spawned when the connection actually closes
                // (ConnectionUpdate::Up::Disconnected while Stopping/Killing), not here.
                // sp up may take several seconds to kill its children before exiting;
                // starting the quick-succession poll at that moment is the right trigger.

                if let Some(tx) = self.up_cmd.get(&profile) {
                    info!(
                        profile = profile.as_str(),
                        "sending Stop request to up daemon"
                    );
                    if tx.send(diag::DaemonRequest::Stop).is_ok() {
                        push_up_log(
                            &mut self.up_logs,
                            &profile,
                            diag::LogEntry {
                                ts: diag::Timestamp::now(),
                                level: "INFO".to_string(),
                                target: "supervisor".to_string(),
                                message: "Requested graceful stop via sp up daemon".to_string(),
                                fields: Vec::new(),
                            },
                        );
                    } else {
                        warn!("failed to send stop request for {}", profile);
                        push_up_log(
                            &mut self.up_logs,
                            &profile,
                            diag::LogEntry {
                                ts: diag::Timestamp::now(),
                                level: "WARN".to_string(),
                                target: "supervisor".to_string(),
                                message:
                                    "Failed to send graceful stop; retry to force kill container"
                                        .to_string(),
                                fields: Vec::new(),
                            },
                        );
                    }
                } else {
                    self.ensure_up_client(&profile);
                    push_up_log(
                        &mut self.up_logs,
                        &profile,
                        diag::LogEntry {
                            ts: diag::Timestamp::now(),
                            level: "WARN".to_string(),
                            target: "supervisor".to_string(),
                            message: "sp up daemon unavailable; retry to force kill container"
                                .to_string(),
                            fields: Vec::new(),
                        },
                    );
                }
                self.refresh_profile_status(&profile);
            }
            SupervisorCommand::KillContainer { profile } => {
                info!(
                    profile = profile.as_str(),
                    "forcing container kill via metadata fallback"
                );
                self.reset_backoff(&profile);
                push_up_log(
                    &mut self.up_logs,
                    &profile,
                    diag::LogEntry {
                        ts: diag::Timestamp::now(),
                        level: "INFO".to_string(),
                        target: "supervisor".to_string(),
                        message: "Killing container...".to_string(),
                        fields: Vec::new(),
                    },
                );
                self.refresh_profile_state_only(&profile);
                let still_running = self
                    .ns_alive_status
                    .get(&profile)
                    .is_some_and(|status| status.child_alive);

                if !still_running {
                    self.set_container_lifecycle(&profile, ContainerLifecycleState::Stopped);
                    push_up_log(
                        &mut self.up_logs,
                        &profile,
                        diag::LogEntry {
                            ts: diag::Timestamp::now(),
                            level: "INFO".to_string(),
                            target: "supervisor".to_string(),
                            message: "Profile already stopped".to_string(),
                            fields: Vec::new(),
                        },
                    );
                    self.refresh_profile_status(&profile);
                    return;
                }

                let next_attempt = self.container_lifecycle(&profile).stop_attempt().max(1) + 1;
                self.set_container_lifecycle(
                    &profile,
                    ContainerLifecycleState::Killing {
                        attempt: next_attempt,
                    },
                );
                fallback_stop_profile_from_metadata(&profile, &mut self.up_logs);
                // Pid watcher is triggered by ConnectionUpdate::Disconnected (see handle_event).
                self.refresh_profile_status(&profile);
            }
            SupervisorCommand::KillManagedProcess { profile, task_pgid } => {
                info!(
                    profile = profile.as_str(),
                    task_pgid, "killing managed task"
                );
                if let Some(tx) = self.up_cmd.get(&profile) {
                    if tx.send(diag::DaemonRequest::Kill { task_pgid }).is_err() {
                        warn!(
                            "failed to send kill request for {} task pgid {}",
                            profile, task_pgid
                        );
                    }
                }
                self.refresh_profile_status(&profile);
            }
            SupervisorCommand::QueryRawLogs {
                profile,
                pid,
                limit,
                after_seq,
            } => {
                self.process_raw_log_subscription = Some((profile, pid, limit, after_seq));
                self.poll_process_raw_logs();
            }
            SupervisorCommand::StopQueryRawLogs { profile, pid } => {
                if self
                    .process_raw_log_subscription
                    .as_ref()
                    .is_some_and(|active| active.0 == profile && active.1 == pid)
                {
                    self.process_raw_log_subscription = None;
                }
            }
            SupervisorCommand::AttachPty { profile, pid } => {
                if let Some(tx) = self.up_cmd.get(&profile) {
                    let _ = tx.send(diag::DaemonRequest::AttachPty { task_pgid: pid });
                }
            }
            SupervisorCommand::DetachPty { profile, pid } => {
                if let Some(tx) = self.up_cmd.get(&profile) {
                    let _ = tx.send(diag::DaemonRequest::DetachPty { task_pgid: pid });
                }
            }
            SupervisorCommand::PtyInput { profile, pid, data } => {
                if let Some(tx) = self.up_cmd.get(&profile) {
                    let _ = tx.send(diag::DaemonRequest::PtyInput {
                        task_pgid: pid,
                        data,
                    });
                }
            }
            SupervisorCommand::PtyResize {
                profile,
                pid,
                cols,
                rows,
            } => {
                if let Some(tx) = self.up_cmd.get(&profile) {
                    let _ = tx.send(diag::DaemonRequest::PtyResize {
                        task_pgid: pid,
                        cols,
                        rows,
                    });
                }
            }
            SupervisorCommand::StartHotconfigDaemons { profile } => {
                info!(profile = profile.as_str(), "starting hotconfig daemons");
                self.spawn_hotconfig_daemons(&profile);
            }
            SupervisorCommand::Ctrl { profile, cmd } => {
                info!(profile = profile.as_str(), cmd = ?cmd, "dispatching diag control command");
                let selected_proxy = match &cmd {
                    ControlCommand::SetSimpleRouting { proxy_id } => Some(proxy_id.clone()),
                    _ => None,
                };
                if let Some(proxy_id) = selected_proxy.as_ref() {
                    self.diag_state
                        .entry(profile.clone())
                        .or_default()
                        .routing_state = Some(diag::RoutingState {
                        selected_proxy: Some(proxy_id.clone()),
                    });
                }
                let _ = self.send_diag_cmd(&profile, cmd);
                if selected_proxy.is_some() {
                    let _ = self.send_diag_cmd(&profile, ControlCommand::QueryRoutingState);
                }
            }
            SupervisorCommand::ReloadHotconfig(profile) => {
                info!(profile = profile.as_str(), "reloading hotconfig");
                self.refresh_config_cache(&profile);
                if let Ok(list) = load_hotconfig_daemons(profile.as_str()) {
                    info!(
                        profile = profile.as_str(),
                        daemon_count = list.len(),
                        "loaded hotconfig daemons from disk"
                    );
                    self.daemon_catalog.insert(profile.clone(), list);
                }
                let _ = self.send_diag_cmd(&profile, ControlCommand::QueryHotConfig);
            }
            SupervisorCommand::ReloadProfile(profile) => {
                self.refresh_config_cache(&profile);
            }
            SupervisorCommand::LoadProfile(profile) => {
                info!(profile = profile.as_str(), "loading profile status");
                self.known_profiles.insert(profile.clone());
                self.refresh_config_cache(&profile);
                self.refresh_profile_status(&profile);
            }
            SupervisorCommand::LoadProfiles(profiles) => {
                info!(
                    profile_count = profiles.len(),
                    "loading status for multiple profiles"
                );
                for profile in profiles {
                    self.known_profiles.insert(profile.clone());
                    self.refresh_config_cache(&profile);
                    self.refresh_profile_status(&profile);
                }
            }
            SupervisorCommand::RefreshNamespaces => {
                self.ui_ns_cache =
                    probe_namespace_indicator(std::process::id() as i32).unwrap_or_default();
                let profiles: Vec<_> = self.known_profiles.iter().cloned().collect();
                for profile in profiles {
                    self.refresh_profile_state_only(&profile);
                }
            }
            SupervisorCommand::Init => {
                info!("initializing supervisor profiles from disk");
                self.ensure_root_daemon_client();
                self.initialize_basis_namespace_pending = true;
                if self.root_daemon_connection.state == ConnectionState::Connected {
                    self.initialize_basis_namespace_pending = false;
                    self.queue_root_daemon_op(
                        diag::RootDaemonOp::InitializeBasisNamespace,
                        PendingRootDaemonOp::InitializeBasisNamespace,
                    );
                }
                if let Ok(profile_infos) = crate::profile_loader::list_profiles() {
                    let discovered: HashSet<_> =
                        profile_infos.iter().map(|info| info.name.clone()).collect();
                    let existing: Vec<_> = self.known_profiles.iter().cloned().collect();
                    for profile in existing {
                        if !discovered.contains(&profile) {
                            self.remove_profile(profile.as_str());
                        }
                    }
                    info!(
                        profile_count = profile_infos.len(),
                        "discovered profiles on disk"
                    );
                    for info in profile_infos {
                        let profile = info.name;
                        self.known_profiles.insert(profile.clone());
                        self.refresh_config_cache(&profile);
                        self.refresh_profile_status(&profile);
                    }
                }
            }
            SupervisorCommand::OnTabOpen { profile, tab } => {
                info!(profile = profile.as_str(), tab = ?tab, "tab opened");
                self.known_profiles.insert(profile.clone());
                self.refresh_profile_status(&profile);
                match tab {
                    TabKind::Hotconfig => {
                        self.refresh_config_cache(&profile);
                        let _ = self.send_diag_cmd(&profile, ControlCommand::QueryHotConfig);
                    }
                    TabKind::ProfileEditor => {
                        self.refresh_config_cache(&profile);
                        if let Ok(list) = load_hotconfig_daemons(profile.as_str()) {
                            self.daemon_catalog.insert(profile.clone(), list);
                        }
                    }
                    TabKind::Dns => {
                        let _ = self.send_diag_cmd(&profile, ControlCommand::QueryDnsState);
                    }
                    TabKind::Traffic => {}
                    TabKind::Proxies => {
                        let _ = self.send_diag_cmd(&profile, ControlCommand::QueryUplinkStats);
                        let _ = self.send_diag_cmd(&profile, ControlCommand::QueryRoutingState);
                    }
                    TabKind::Processes => {}
                }
            }
            SupervisorCommand::SetTrafficSubscription { profile } => {
                self.set_traffic_subscription(profile);
            }
        }
        info!(
            command,
            profile,
            elapsed_ms = started.elapsed().as_millis(),
            "supervisor finished command"
        );
    }

    fn refresh_profile_status(&mut self, profile: &ContainerName) {
        self.refresh_profile_status_inner(profile, true);
    }

    fn refresh_profile_state_only(&mut self, profile: &ContainerName) {
        self.refresh_profile_status_inner(profile, false);
    }

    fn refresh_profile_status_inner(&mut self, profile: &ContainerName, rearm_clients: bool) {
        let _had_up_client = self.up_cmd.contains_key(profile);
        let had_diag_client = self.diag_cmd.contains_key(profile);
        let diag_connection_state = self
            .diag_connection
            .get(profile)
            .map(|status| status.state)
            .unwrap_or_default();
        let had_child_alive = self
            .ns_alive_status
            .get(profile)
            .map(|status| status.child_alive)
            .unwrap_or(false);
        let ns_meta = state_paths::profile_ns_meta(profile.as_str());
        let (child_alive, child_pid, serve_alive, serve_pid, up_alive, up_pid) = if ns_meta.exists()
        {
            match read_ns_alive(&ns_meta) {
                Ok(ns_alive) => {
                    let child_pid = ns_alive.child_pid.filter(|&p| pid_exists(p));
                    let serve_pid = ns_alive.serve_pid.filter(|&p| pid_exists(p));
                    let up_pid = ns_alive.up_pid.filter(|&p| pid_exists(p));
                    let result = (
                        child_pid.is_some(),
                        child_pid.map(|p| p as i32),
                        serve_pid.is_some(),
                        serve_pid.map(|p| p as i32),
                        up_pid.is_some(),
                        up_pid.map(|p| p as i32),
                    );
                    // Cache the full struct so emit_snapshot doesn't need to re-read it.
                    self.ns_alive_cache.insert(profile.clone(), ns_alive);
                    result
                }
                Err(_) => {
                    self.ns_alive_cache.remove(profile);
                    (false, None, false, None, false, None)
                }
            }
        } else {
            self.ns_alive_cache.remove(profile);
            (false, None, false, None, false, None)
        };

        self.ns_alive_status.insert(
            profile.clone(),
            NsAliveStatus {
                profile: profile.clone(),
                child_alive,
                child_pid,
                serve_alive,
                serve_pid,
                up_alive,
                up_pid,
            },
        );

        let up_ns = up_pid.and_then(probe_namespace_indicator);
        let keeper_ns = child_pid.and_then(probe_namespace_indicator);
        if up_ns.is_some() || keeper_ns.is_some() {
            self.profile_ns_cache.insert(
                profile.clone(),
                ProfileNamespaceState {
                    up: up_ns,
                    keeper: keeper_ns,
                },
            );
        } else {
            self.profile_ns_cache.remove(profile);
        }

        let start_in_flight = matches!(
            self.container_lifecycle(profile),
            ContainerLifecycleState::Starting
        );
        self.reconcile_container_lifecycle(profile, child_alive, start_in_flight);

        if !child_alive {
            if !start_in_flight {
                self.pending_start_sandbox.remove(profile);
            }
            self.process_list_snapshot.remove(profile);
            if start_in_flight {
                // Container is in Starting state — sp up hasn't written ns_alive yet.
                // Wait for the daemon's reverse control-socket connection.
                debug!(
                    profile = profile.as_str(),
                    "child not yet alive but start is in-flight; awaiting up daemon control connection"
                );
            } else {
                info!(
                    profile = profile.as_str(),
                    "child dead and no start in-flight; dropping up_cmd tx (will cancel up_client_loop)"
                );
                self.up_cmd.remove(profile);
                self.up_connection.remove(profile);
            }
        }

        if !serve_alive {
            if had_diag_client || diag_connection_state == ConnectionState::Connecting {
                // sp serve is starting — ProcessListSnapshot told us it's alive but it
                // hasn't yet bound tun_diag.sock (or written serve_pid to ns_alive).
                // Preserve the diag client tx so the retry loop keeps going.
                debug!(
                    profile = profile.as_str(),
                    "serve not yet visible on disk but diag client is in-flight; preserving diag_cmd tx"
                );
            } else {
                self.diag_cmd.remove(profile);
                self.diag_connection.remove(profile);
            }
        }

        if rearm_clients && child_alive {
            self.ensure_up_client(profile);
        }
        if rearm_clients && serve_alive {
            self.ensure_diag_client(profile);
        }
        if child_alive && !had_child_alive && self.pending_start_sandbox.remove(profile) {
            self.spawn_sandbox_reconcile(profile, "container startup");
        } else if child_alive && !had_child_alive {
            // Container came alive but no sandbox reconcile was pending (restart after
            // sandbox already applied).  Check the persisted sandbox status and start
            // dbus immediately if the sandbox is already pivoted.
            self.maybe_ensure_dbus(profile);
        }
    }

    fn handle_event(&mut self, ev: SupervisorEvent) {
        match ev {
            SupervisorEvent::DiagEvent { profile, event } => {
                let event_name = diag_event_name(&event);
                debug!(
                    profile = profile.as_str(),
                    event = event_name,
                    "received diag event"
                );
                let state = self.diag_state.entry(profile.clone()).or_default();
                state.accumulator.ingest(&event);
                state.conns_state.apply_event(&event);
                const MAX_DIAG_EVENTS: usize = 512;
                match &event {
                    DiagEvent::RecentDiagEvents(_) | DiagEvent::ConnsStateSnapshot { .. } => {}
                    _ => {
                        state.diag_event_log.push_back(event.clone());
                        if state.diag_event_log.len() > MAX_DIAG_EVENTS {
                            state.diag_event_log.pop_front();
                        }
                    }
                }
                match event {
                    DiagEvent::DnsState { state: dns, .. } => state.dns_state = Some(dns),
                    DiagEvent::RoutingState { state: routing, .. } => {
                        state.routing_state = Some(routing)
                    }
                    DiagEvent::UplinkStatsSnapshot { stats, .. } => state.proxy_stats = stats,
                    DiagEvent::Log(entry) => {
                        push_profile_log(&mut self.up_logs, &profile, LogSource::Serve, entry);
                    }
                    DiagEvent::RecentLogs(entries) => {
                        replace_profile_logs_for_source(
                            &mut self.up_logs,
                            &profile,
                            LogSource::Serve,
                            entries,
                        );
                    }
                    DiagEvent::RecentDiagEvents(entries) => {
                        if state.diag_event_log.is_empty() {
                            state.diag_event_log.extend(entries);
                        }
                    }
                    DiagEvent::ConnsStateSnapshot { state: snap, .. } => {
                        state.conns_state = snap;
                    }
                    _ => {}
                }
            }
            SupervisorEvent::ConnectionUpdate {
                profile,
                target,
                state,
                error,
            } => {
                info!(profile = profile.as_str(), target = target.label(), state = ?state, error = ?error, "connection state updated");
                self.update_connection_status(profile.clone(), target, state.clone(), error);
                // When sp up closes its socket during an intentional stop, that is the
                // definitive signal that it is shutting down.  Kick off the quick-succession
                // pid poll NOW — sp up has just closed its socket and is about to exit, so
                // the 50 ms check fires right as the process disappears.
                if target == ConnectionTarget::Up && state == ConnectionState::Disconnected {
                    if profile == "basic" {
                        self.personal_runtime_state =
                            diag::personal::PersonalRuntimeState::default();
                    }
                    let lc = self.container_lifecycle(&profile);
                    if matches!(
                        lc,
                        ContainerLifecycleState::Stopping { .. }
                            | ContainerLifecycleState::Killing { .. }
                    ) {
                        // Use ns_alive_cache for the raw pid — it is stored without pid_exists
                        // filtering, so it works correctly even across privilege boundaries.
                        let raw_up_pid = self
                            .ns_alive_cache
                            .get(&profile)
                            .and_then(|a| a.up_pid)
                            .or_else(|| {
                                let ns_meta = state_paths::profile_ns_meta(profile.as_str());
                                read_ns_alive(&ns_meta).ok().and_then(|a| a.up_pid)
                            });
                        let event_tx = self.event_tx.clone();
                        let profile_name = profile.clone();
                        let started_at = self.up_start_time.get(&profile).copied();
                        if let Some(pid) = raw_up_pid {
                            tokio::spawn(async move {
                                watch_up_pid_exit(profile_name, pid, started_at, event_tx).await;
                            });
                        } else {
                            // No pid on record; treat stream closure as process exit.
                            tokio::spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                                let _ = event_tx.send(SupervisorEvent::UpDaemonExited {
                                    profile: profile_name,
                                });
                            });
                        }
                    }
                }
                let profile_for_refresh = profile.clone();
                self.refresh_profile_state_only(&profile_for_refresh);
            }
            SupervisorEvent::UpEvent { profile, event } => {
                let event_name = daemon_event_name(&event);
                info!(
                    profile = profile.as_str(),
                    event = event_name,
                    "received up daemon event"
                );
                if let diag::DaemonEvent::Error { msg } = &event {
                    self.record_connection_error(&profile, ConnectionTarget::Up, msg.clone());
                }
                if let diag::DaemonEvent::Log(entry) = event {
                    push_up_log(&mut self.up_logs, &profile, entry);
                } else if let diag::DaemonEvent::RecentLogs(entries) = event {
                    replace_profile_logs_for_source(
                        &mut self.up_logs,
                        &profile,
                        LogSource::Up,
                        entries,
                    );
                } else if let diag::DaemonEvent::RawLogs {
                    task_pgid,
                    reset,
                    start_seq,
                    next_seq,
                    logs,
                } = event
                {
                    let _ = self.process_raw_log_tx.send(ProcessRawLogUpdate {
                        profile: profile.clone(),
                        task_pgid,
                        reset,
                        start_seq,
                        next_seq,
                        logs,
                    });
                    if let Some(active) = self.process_raw_log_subscription.as_mut() {
                        if active.0 == profile && active.1 == task_pgid {
                            active.3 = Some(next_seq);
                        }
                    }
                    self.ectx.request_repaint();
                } else if let diag::DaemonEvent::PtyScrollback { task_pgid, data } = event {
                    {
                        let mut guard = self.pty_buf.lock().unwrap_or_else(|e| e.into_inner());
                        guard
                            .entry(profile.clone())
                            .or_default()
                            .insert(task_pgid, data);
                    }
                    self.pty_wake_state.notify_pty_data(&profile, task_pgid);
                    self.repaint_pty_target();
                } else if let diag::DaemonEvent::PtyOutput { task_pgid, data } = event {
                    {
                        let mut guard = self.pty_buf.lock().unwrap_or_else(|e| e.into_inner());
                        guard
                            .entry(profile.clone())
                            .or_default()
                            .entry(task_pgid)
                            .or_default()
                            .extend(data);
                    }
                    self.pty_wake_state.notify_pty_data(&profile, task_pgid);
                    self.repaint_pty_target();
                } else if let diag::DaemonEvent::ProcessExit { task_pgid } = event {
                    if let Some(snapshot) = self.process_list_snapshot.get_mut(&profile) {
                        if let Some(entry) = snapshot.procs.get_mut(&task_pgid) {
                            entry.status = diag::ProcessStatus::Killed;
                        }
                    }
                    if let Some(status) = self.ns_alive_status.get_mut(&profile) {
                        if status.serve_pid == Some(task_pgid as i32) {
                            status.serve_alive = false;
                        }
                    }
                } else if let diag::DaemonEvent::Personal(
                    diag::personal::PersonalDaemonEvent::State(state),
                ) = event
                {
                    self.personal_runtime_state = state;
                } else if let diag::DaemonEvent::ProcessListSnapshot(mut snapshot) = event {
                    if let Some(status) = self.ns_alive_status.get_mut(&profile) {
                        // `snapshot.serve` is the PID of the sp-serve process (0 = none).
                        // Its live status lives inside `snapshot.procs[serve_pid].status`.
                        let (new_serve_pid, new_serve_alive) = if snapshot.serve != 0 {
                            match snapshot.procs.get(&snapshot.serve).map(|e| &e.status) {
                                Some(
                                    diag::ProcessStatus::Alive | diag::ProcessStatus::Terminating,
                                ) => (Some(snapshot.serve as i32), true),
                                Some(diag::ProcessStatus::Killed) | None => {
                                    (Some(snapshot.serve as i32), false)
                                }
                                Some(diag::ProcessStatus::Vacant) => (None, false),
                            }
                        } else {
                            (None, false)
                        };

                        let was_alive = status.serve_alive;
                        status.serve_pid = new_serve_pid;
                        status.serve_alive = new_serve_alive;

                        if new_serve_alive {
                            self.ensure_diag_client(&profile);
                        } else if was_alive {
                            // Serve just died — tear down the diag connection.
                            self.diag_cmd.remove(&profile);
                            self.update_connection_status(
                                profile.clone(),
                                ConnectionTarget::Diag,
                                ConnectionState::Disconnected,
                                if snapshot.serve != 0 {
                                    Some("sp serve process exited".to_string())
                                } else {
                                    Some("sp serve process not running".to_string())
                                },
                            );
                        }
                    }
                    if let Some(existing_slots) = self.pending_auto_open_logs.get(&profile) {
                        let newest_spawned = snapshot
                            .procs
                            .iter()
                            .filter(|(pid, _)| !existing_slots.contains(pid))
                            .max_by_key(|(_, entry)| {
                                entry
                                    .spawned_at
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_micros())
                                    .unwrap_or(0)
                            })
                            .map(|(pid, _)| *pid);
                        if let Some(pid) = newest_spawned {
                            self.auto_open_logs_token = self.auto_open_logs_token.saturating_add(1);
                            self.auto_open_logs_target = Some(AutoOpenLogsTarget {
                                profile: profile.clone(),
                                pid,
                                token: self.auto_open_logs_token,
                            });
                            self.pending_auto_open_logs.remove(&profile);
                        }
                    }

                    Self::merge_process_list_snapshot(
                        self.process_list_snapshot.get(&profile),
                        &mut snapshot,
                    );
                    self.process_list_snapshot.insert(profile, snapshot);
                }
            }
            SupervisorEvent::InjectUpStream { profile, stream } => {
                info!(
                    profile = profile.as_str(),
                    "control socket: up daemon connected, starting direct stream handler"
                );
                self.known_profiles.insert(profile.clone());
                // `sp up` writes ns_alive before it can complete this authenticated
                // control handshake. Refresh on that readiness boundary without
                // rearming an outbound client connection.
                self.refresh_profile_state_only(&profile);
                // Replace cmd channel — dropping old sender exits any retry loop cleanly.
                let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<diag::DaemonRequest>();
                self.up_cmd.insert(profile.clone(), cmd_tx);
                let event_tx = self.event_tx.clone();
                let profile_name = profile.clone();
                tokio::spawn(async move {
                    run_injected_up_stream(profile_name, stream, cmd_rx, event_tx).await;
                });
            }
            SupervisorEvent::InjectDiagStream { profile, stream } => {
                info!(
                    profile = profile.as_str(),
                    "control socket: serve daemon connected, starting direct stream handler"
                );
                self.known_profiles.insert(profile.clone());
                // Replace cmd channel — dropping old sender exits any retry loop cleanly.
                let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<ControlCommand>();
                self.diag_cmd.insert(profile.clone(), cmd_tx);
                let event_tx = self.event_tx.clone();
                let profile_name = profile.clone();
                tokio::spawn(async move {
                    run_injected_diag_stream(profile_name, stream, cmd_rx, event_tx).await;
                });
            }
            SupervisorEvent::InjectRootDaemonStream { stream } => {
                info!("control socket: root daemon connected, starting direct stream handler");
                let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<diag::RootDaemonRequest>();
                self.root_daemon_cmd = Some(cmd_tx);
                let event_tx = self.event_tx.clone();
                let nsproxy_path = self.nsproxy_path.clone();
                let control_sock_path = self.control_sock_path.clone();
                tokio::spawn(async move {
                    run_injected_root_daemon_stream(
                        stream,
                        cmd_rx,
                        event_tx,
                        nsproxy_path,
                        control_sock_path,
                    )
                    .await;
                });
            }
            SupervisorEvent::RootDaemonConnectionUpdate { state, error } => {
                self.root_daemon_connection.state = state;
                self.root_daemon_connection.last_error = error.clone();
                if state == ConnectionState::Connected
                    && self.initialize_basis_namespace_pending
                {
                    self.initialize_basis_namespace_pending = false;
                    self.queue_root_daemon_op(
                        diag::RootDaemonOp::InitializeBasisNamespace,
                            PendingRootDaemonOp::InitializeBasisNamespace,
                    );
                }
                if state != ConnectionState::Connected {
                    let detail = error.unwrap_or_else(|| "root daemon disconnected".to_string());
                    self.fail_inflight_root_daemon_ops(detail);
                }
            }
                    SupervisorEvent::RootDaemonEvent { event } => {
                let pending = self.pending_root_daemon_ops.remove(&event.op_id);
                match event.result {
                    diag::RootDaemonResult::Pong { version } => {
                        if let Some(op) = pending.as_ref() {
                            self.publish_editor_status(
                                op,
                                true,
                                event.op_id,
                                format!("root daemon pong ({version})"),
                            );
                        }
                    }
                    diag::RootDaemonResult::ReadFile { content, .. } => {
                        self.constants_editor_content = Some(content);
                        if let Some(op) = pending.as_ref() {
                            self.publish_editor_status(
                                op,
                                true,
                                event.op_id,
                                "loaded constants.json",
                            );
                        }
                    }
                    diag::RootDaemonResult::NamespaceInitialized {
                        current, basis_ns, ..
                    } => {
                        self.namespace_warning = (!current.ino_eq(&basis_ns))
                            .then(|| "UI namespace differs from recorded basis".to_owned());
                    }
                    diag::RootDaemonResult::Ok {
                        message, profile, ..
                    } => {
                        if let Some(op) = pending.as_ref() {
                            self.publish_editor_status(op, true, event.op_id, message.clone());
                            match op {
                                PendingRootDaemonOp::InitializeBasisNamespace => {}
                                PendingRootDaemonOp::SaveHotconfig { profile } => {
                                    self.refresh_config_cache(profile);
                                    self.refresh_profile_status(profile);
                                    self.spawn_sandbox_reconcile(profile, "hotconfig saved");
                                }
                                PendingRootDaemonOp::SaveProfile { profile } => {
                                    self.refresh_config_cache(profile);
                                    self.refresh_profile_status(profile);
                                    self.spawn_sandbox_reconcile(profile, "profile saved");
                                }
                                PendingRootDaemonOp::SaveConstants => {}
                                PendingRootDaemonOp::LoadConstants => {}
                                PendingRootDaemonOp::CreateProfile { name } => {
                                    self.known_profiles.insert(name.clone());
                                    self.refresh_config_cache(name);
                                    self.refresh_profile_status(name);
                                }
                            }
                        }
                    }
                    diag::RootDaemonResult::Error {
                        message, profile, ..
                    } => {
                        if let Some(op) = pending.as_ref() {
                            if matches!(op, PendingRootDaemonOp::InitializeBasisNamespace) {
                                self.namespace_warning = Some(message);
                            } else {
                                self.publish_editor_status(op, false, event.op_id, message);
                            }
                        }
                    }
                }
            }
            SupervisorEvent::RootDaemonLog { entry } => {
                push_global_log(&self.root_daemon_logs, LogSource::RootDaemon, entry);
            }
            SupervisorEvent::RootDaemonRecentLogs { entries } => {
                replace_global_logs_for_source(
                    &self.root_daemon_logs,
                    LogSource::RootDaemon,
                    entries,
                );
            }
            SupervisorEvent::UpDaemonExited { profile } => {
                let lc = self.container_lifecycle(&profile);
                if !matches!(
                    lc,
                    ContainerLifecycleState::Stopping { .. }
                        | ContainerLifecycleState::Killing { .. }
                ) {
                    info!(
                        profile = profile.as_str(),
                        "UpDaemonExited received but lifecycle is {:?}; ignoring", lc
                    );
                } else {
                    info!(
                        profile = profile.as_str(),
                        "sp up process confirmed exited; transitioning to Stopped"
                    );
                    self.set_container_lifecycle(&profile, ContainerLifecycleState::Stopped);
                    self.up_cmd.remove(&profile);
                    self.diag_cmd.remove(&profile);
                    push_up_log(
                        &mut self.up_logs,
                        &profile,
                        diag::LogEntry {
                            ts: diag::Timestamp::now(),
                            level: "INFO".to_string(),
                            target: "supervisor".to_string(),
                            message: "Container stopped".to_string(),
                            fields: Vec::new(),
                        },
                    );
                    self.refresh_profile_status(&profile);
                }
            }
            SupervisorEvent::BootstrapUpLog {
                profile,
                stream,
                line,
            } => {
                // Only keep bootstrap stdio while the up socket is not connected yet.
                // Once connected, authoritative daemon logs arrive via DaemonEvent::Log.
                let connected = self
                    .up_connection
                    .get(&profile)
                    .is_some_and(|s| s.state == ConnectionState::Connected);
                if !connected {
                    let level = match stream {
                        BootstrapLogStream::Stdout => "INFO",
                        BootstrapLogStream::Stderr => "WARN",
                    };
                    push_up_log(
                        &mut self.up_logs,
                        &profile,
                        diag::LogEntry {
                            ts: diag::Timestamp::now(),
                            level: level.to_string(),
                            target: "sp-up-bootstrap".to_string(),
                            message: line,
                            fields: Vec::new(),
                        },
                    );
                }
            }
            SupervisorEvent::DeleteProcessLog {
                profile,
                stream,
                line,
            } => {
                let level = match stream {
                    BootstrapLogStream::Stdout => "INFO",
                    BootstrapLogStream::Stderr => "WARN",
                };
                push_up_log(
                    &mut self.up_logs,
                    &profile,
                    diag::LogEntry {
                        ts: diag::Timestamp::now(),
                        level: level.to_string(),
                        target: "sp-down".to_string(),
                        message: line,
                        fields: Vec::new(),
                    },
                );
            }
            SupervisorEvent::SandboxProcessLog {
                profile,
                stream,
                line,
            } => {
                let level = match stream {
                    BootstrapLogStream::Stdout => "INFO",
                    BootstrapLogStream::Stderr => "WARN",
                };
                push_up_log(
                    &mut self.up_logs,
                    &profile,
                    diag::LogEntry {
                        ts: diag::Timestamp::now(),
                        level: level.to_string(),
                        target: "sp-sandbox".to_string(),
                        message: line,
                        fields: Vec::new(),
                    },
                );
            }
            SupervisorEvent::DeleteContainerFinished {
                profile,
                success,
                detail,
            } => {
                if success {
                    info!(profile = profile.as_str(), "container deleted: {detail}");
                    push_up_log(
                        &mut self.up_logs,
                        &profile,
                        diag::LogEntry {
                            ts: diag::Timestamp::now(),
                            level: "INFO".to_string(),
                            target: "supervisor".to_string(),
                            message: "Container deleted from disk. Refresh to remove from list."
                                .to_string(),
                            fields: Vec::new(),
                        },
                    );
                    self.finalize_deleted_profile_view(profile.as_str());
                } else {
                    warn!(
                        profile = profile.as_str(),
                        "container delete failed: {detail}"
                    );
                    push_up_log(
                        &mut self.up_logs,
                        &profile,
                        diag::LogEntry {
                            ts: diag::Timestamp::now(),
                            level: "WARN".to_string(),
                            target: "supervisor".to_string(),
                            message: format!("Delete failed: {detail}"),
                            fields: Vec::new(),
                        },
                    );
                    self.refresh_profile_status(&profile);
                }
            }
            SupervisorEvent::SandboxStatusChanged { profile, status } => {
                if let Some(cache) = self.config_cache.get_mut(&profile) {
                    cache.sandbox_status = status;
                }
            }
            SupervisorEvent::SandboxFinished {
                profile,
                success,
                detail,
            } => {
                self.sandbox_in_flight.remove(&profile);
                self.refresh_config_cache(&profile);
                self.refresh_profile_status(&profile);
                push_up_log(
                    &mut self.up_logs,
                    &profile,
                    plain_log_entry(
                        if success { "INFO" } else { "WARN" },
                        "supervisor",
                        if success {
                            format!("Sandbox reconcile finished successfully ({detail})")
                        } else {
                            format!("Sandbox reconcile failed ({detail})")
                        },
                    ),
                );
                if success {
                    self.maybe_ensure_dbus(&profile);
                }
            }
            SupervisorEvent::VethProcessLog {
                profile,
                stream: _stream,
                line,
            } => {
                push_up_log(
                    &mut self.up_logs,
                    &profile,
                    plain_log_entry("INFO", "veth", line),
                );
            }
            SupervisorEvent::VethFinished {
                profile,
                success,
                detail,
            } => {
                self.veth_status.insert(
                    profile.clone(),
                    vec![VethStatus {
                        success,
                        detail: detail.clone(),
                    }],
                );
                push_up_log(
                    &mut self.up_logs,
                    &profile,
                    plain_log_entry(
                        if success { "INFO" } else { "WARN" },
                        "veth",
                        if success {
                            format!("Veth creation finished ({detail})")
                        } else {
                            format!("Veth creation failed ({detail})")
                        },
                    ),
                );
            }
        }
    }

    fn remove_profile(&mut self, profile: &str) {
        self.known_profiles.remove(profile);
        self.daemon_catalog.remove(profile);
        self.process_list_snapshot.remove(profile);
        self.up_cmd.remove(profile);
        self.diag_cmd.remove(profile);
        self.up_connection.remove(profile);
        self.diag_connection.remove(profile);
        self.diag_state.remove(profile);
        self.ns_alive_status.remove(profile);
        self.up_logs.remove(profile);
        self.container_lifecycle.remove(profile);
        self.up_attempt.remove(profile);
        self.diag_attempt.remove(profile);
        self.config_cache.remove(profile);
        self.ns_alive_cache.remove(profile);
        self.profile_ns_cache.remove(profile);
        self.pending_auto_open_logs.remove(profile);
        self.sandbox_in_flight.remove(profile);
        self.pending_start_sandbox.remove(profile);
        self.up_start_time.remove(profile);
        self.spawned_daemons
            .retain(|key| !key.starts_with(&format!("{}:", profile)));
        if let Ok(mut guard) = self.pty_buf.lock() {
            guard.remove(profile);
        }
        if let Ok(mut guard) = self.pty_wake_state.generations.lock() {
            guard.remove(profile);
        }
        if self
            .auto_open_logs_target
            .as_ref()
            .is_some_and(|target| target.profile == profile)
        {
            self.auto_open_logs_target = None;
        }
    }

    fn finalize_deleted_profile_view(&mut self, profile: &str) {
        self.process_list_snapshot.remove(profile);
        self.up_cmd.remove(profile);
        self.diag_cmd.remove(profile);
        self.up_connection.remove(profile);
        self.diag_connection.remove(profile);
        self.diag_state.remove(profile);
        self.ns_alive_status.insert(
            profile.to_string(),
            NsAliveStatus {
                profile: profile.to_string(),
                child_alive: false,
                child_pid: None,
                serve_alive: false,
                serve_pid: None,
                up_alive: false,
                up_pid: None,
            },
        );
        self.set_container_lifecycle(&profile.to_string(), ContainerLifecycleState::Stopped);
        self.ns_alive_cache.remove(profile);
        self.profile_ns_cache.remove(profile);
        self.pending_auto_open_logs.remove(profile);
        self.up_start_time.remove(profile);
        self.spawned_daemons
            .retain(|key| !key.starts_with(&format!("{}:", profile)));
        if let Ok(mut guard) = self.pty_buf.lock() {
            guard.remove(profile);
        }
        if let Ok(mut guard) = self.pty_wake_state.generations.lock() {
            guard.remove(profile);
        }
        if self
            .auto_open_logs_target
            .as_ref()
            .is_some_and(|target| target.profile == profile)
        {
            self.auto_open_logs_target = None;
        }
    }

    fn send_diag_cmd(&mut self, profile: &ContainerName, cmd: ControlCommand) -> bool {
        if !self.diag_cmd.contains_key(profile) {
            info!(profile = profile.as_str(), cmd = ?cmd, "starting diag client for command");
            self.ensure_diag_client(profile);
        }
        info!(profile = profile.as_str(), cmd = ?cmd, "sending diag command");
        self.diag_cmd
            .get(profile)
            .is_some_and(|tx| tx.send(cmd).is_ok())
    }

    fn event_requires_snapshot(&self, ev: &SupervisorEvent) -> bool {
        match ev {
            SupervisorEvent::UpEvent {
                event: diag::DaemonEvent::PtyOutput { .. },
                ..
            }
            | SupervisorEvent::UpEvent {
                event: diag::DaemonEvent::PtyScrollback { .. },
                ..
            }
            | SupervisorEvent::UpEvent {
                event: diag::DaemonEvent::RawLogs { .. },
                ..
            } => false,
            SupervisorEvent::DiagEvent { profile, event } => {
                !diag_event_is_traffic_only(event) || self.is_traffic_subscribed(profile.as_str())
            }
            _ => true,
        }
    }

    fn is_traffic_subscribed(&self, profile: &str) -> bool {
        self.traffic_subscription.as_deref() == Some(profile)
    }

    fn set_traffic_subscription(&mut self, profile: Option<ContainerName>) {
        if self.traffic_subscription == profile {
            return;
        }

        let previous = self.traffic_subscription.take();

        if let Some(old_profile) = previous {
            if self.diag_cmd.contains_key(&old_profile) {
                let _ = self.send_diag_cmd(
                    &old_profile,
                    ControlCommand::SetTrackConns { enabled: false },
                );
            }
        }

        if let Some(profile) = profile {
            self.traffic_subscription = Some(profile.clone());
            self.known_profiles.insert(profile.clone());
            self.refresh_profile_status(&profile);
            let _ = self.send_diag_cmd(&profile, ControlCommand::SetTrackConns { enabled: true });
            let _ = self.send_diag_cmd(&profile, ControlCommand::QueryRoutingState);
            let _ = self.send_diag_cmd(
                &profile,
                ControlCommand::QueryRecentDiagEvents {
                    limit: diag::DIAG_EVENT_RING_CAP,
                },
            );
            let _ = self.send_diag_cmd(&profile, ControlCommand::QueryConnsState);
        }
    }

    fn update_connection_status(
        &mut self,
        profile: ContainerName,
        target: ConnectionTarget,
        state: ConnectionState,
        error: Option<String>,
    ) {
        let status_map = match target {
            ConnectionTarget::Up => &mut self.up_connection,
            ConnectionTarget::Diag => &mut self.diag_connection,
        };
        let status = status_map.entry(profile.clone()).or_default();
        let prev_state = status.state;
        let prev_error = status.last_error.clone();

        status.state = state;
        if state == ConnectionState::Connected {
            status.last_error = None;
        } else if let Some(err) = error.clone() {
            status.last_error = Some(err);
        }

        // Suppress connection-state log noise during intentional stop/kill: the sp up
        // connection closing is expected and should not appear as an event in the log panel.
        let is_intentional_stop = target == ConnectionTarget::Up
            && matches!(
                self.container_lifecycle(&profile),
                ContainerLifecycleState::Stopping { .. } | ContainerLifecycleState::Killing { .. }
            );

        if prev_state != state && !is_intentional_stop {
            match state {
                ConnectionState::Connected => push_up_log(
                    &mut self.up_logs,
                    &profile,
                    diag::LogEntry {
                        ts: diag::Timestamp::now(),
                        level: "INFO".to_string(),
                        target: "supervisor".to_string(),
                        message: format!("{} connected", target.label()),
                        fields: Vec::new(),
                    },
                ),
                ConnectionState::Disconnected => push_up_log(
                    &mut self.up_logs,
                    &profile,
                    diag::LogEntry {
                        ts: diag::Timestamp::now(),
                        level: "INFO".to_string(),
                        target: "supervisor".to_string(),
                        message: format!("{} disconnected", target.label()),
                        fields: Vec::new(),
                    },
                ),
                ConnectionState::NoRetry => push_up_log(
                    &mut self.up_logs,
                    &profile,
                    diag::LogEntry {
                        ts: diag::Timestamp::now(),
                        level: "WARN".to_string(),
                        target: "supervisor".to_string(),
                        message: format!(
                            "{} upgrade rejected — no further retries",
                            target.label()
                        ),
                        fields: Vec::new(),
                    },
                ),
                ConnectionState::Connecting => {}
            }
        }

        if let Some(err) = error {
            if prev_error.as_deref() != Some(err.as_str()) && !is_intentional_stop {
                push_up_log(
                    &mut self.up_logs,
                    &profile,
                    diag::LogEntry {
                        ts: diag::Timestamp::now(),
                        level: "WARN".to_string(),
                        target: "supervisor".to_string(),
                        message: format!("{} error: {}", target.label(), err),
                        fields: Vec::new(),
                    },
                );
            }
        }
    }

    fn record_connection_error(
        &mut self,
        profile: &ContainerName,
        target: ConnectionTarget,
        error: String,
    ) {
        let status_map = match target {
            ConnectionTarget::Up => &mut self.up_connection,
            ConnectionTarget::Diag => &mut self.diag_connection,
        };
        let status = status_map.entry(profile.clone()).or_default();
        if status.last_error.as_deref() == Some(error.as_str()) {
            return;
        }
        status.last_error = Some(error.clone());
        push_up_log(
            &mut self.up_logs,
            profile,
            diag::LogEntry {
                ts: diag::Timestamp::now(),
                level: "WARN".to_string(),
                target: "supervisor".to_string(),
                message: format!("{} error: {}", target.label(), error),
                fields: Vec::new(),
            },
        );
    }

    fn reset_backoff(&mut self, profile: &ContainerName) {
        if let Some(b) = self.up_backoff_for(profile) {
            b.lock().unwrap().reset();
        }
        if let Some(b) = self.diag_backoff_for(profile) {
            b.lock().unwrap().reset();
        }
    }

    fn up_backoff_for(&mut self, profile: &ContainerName) -> Option<Arc<Mutex<ConnectionBackoff>>> {
        self.up_attempt.get(profile).cloned()
    }

    fn diag_backoff_for(
        &mut self,
        profile: &ContainerName,
    ) -> Option<Arc<Mutex<ConnectionBackoff>>> {
        self.diag_attempt.get(profile).cloned()
    }

    fn ensure_up_client(&mut self, profile: &ContainerName) {
        if self.up_cmd.contains_key(profile) {
            return;
        }
        info!(profile = profile.as_str(), "spawning up client loop");
        let (tx, rx) = mpsc::unbounded_channel();
        self.up_cmd.insert(profile.clone(), tx);
        let event_tx = self.event_tx.clone();
        let profile_name = profile.clone();
        // Reuse existing backoff so urgency survives across loop restarts within a session.
        // A deliberate restart resets it via reset_backoff().
        let backoff = self
            .up_attempt
            .entry(profile.clone())
            .or_insert_with(|| Arc::new(Mutex::new(ConnectionBackoff::default())))
            .clone();
        tokio::spawn(async move {
            up_client_loop(profile_name, rx, event_tx, backoff).await;
        });
    }

    fn ensure_diag_client(&mut self, profile: &ContainerName) {
        if self.diag_cmd.contains_key(profile) {
            return;
        }
        info!(profile = profile.as_str(), "spawning diag client loop");
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        self.diag_cmd.insert(profile.clone(), cmd_tx);
        let profile_name = profile.clone();
        let event_tx = self.event_tx.clone();
        // Reuse existing backoff so urgency survives across loop restarts within a session.
        let backoff = self
            .diag_attempt
            .entry(profile.clone())
            .or_insert_with(|| Arc::new(Mutex::new(ConnectionBackoff::default())))
            .clone();
        tokio::spawn(async move {
            diag_client_loop(profile_name, cmd_rx, event_tx, backoff).await;
        });
    }

    fn start_root_daemon_process(&mut self) {
        match try_start_root_daemon_process(&self.nsproxy_path, &self.control_sock_path) {
            Ok(_) => {}
            Err(err) => {
                self.root_daemon_connection.state = ConnectionState::Disconnected;
                self.root_daemon_connection.last_error = Some(err.to_string());
            }
        }
    }

    fn ensure_root_daemon_client(&mut self) {
        if self.root_daemon_cmd.is_some() {
            return;
        }
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        self.root_daemon_cmd = Some(cmd_tx);
        let event_tx = self.event_tx.clone();
        let backoff = self.root_daemon_attempt.clone();
        let nsproxy_path = self.nsproxy_path.clone();
        let control_sock_path = self.control_sock_path.clone();
        tokio::spawn(async move {
            root_daemon_client_loop(cmd_rx, event_tx, backoff, nsproxy_path, control_sock_path)
                .await;
        });

        if !diag::root_daemon_sock_path().exists() {
            self.start_root_daemon_process();
        }
    }

    fn queue_root_daemon_op(&mut self, op: diag::RootDaemonOp, pending: PendingRootDaemonOp) {
        self.ensure_root_daemon_client();
        if self.root_daemon_connection.state != ConnectionState::Connected {
            let detail = self
                .root_daemon_connection
                .last_error
                .clone()
                .unwrap_or_else(|| "root daemon is not connected".to_string());
            let token = self.next_editor_status_token();
            self.publish_editor_status(&pending, false, token, detail);
            return;
        }
        let op_id = self.next_root_daemon_op_id;
        self.next_root_daemon_op_id = self.next_root_daemon_op_id.saturating_add(1);
        let req = diag::RootDaemonRequest { op_id, op };
        match self.root_daemon_cmd.as_ref() {
            Some(tx) => {
                if tx.send(req).is_err() {
                    self.root_daemon_cmd = None;
                    self.root_daemon_connection.state = ConnectionState::Disconnected;
                    self.root_daemon_connection.last_error =
                        Some("root daemon command channel dropped".to_string());
                    let token = self.next_editor_status_token();
                    self.publish_editor_status(
                        &pending,
                        false,
                        token,
                        "root daemon command channel dropped",
                    );
                } else {
                    self.pending_root_daemon_ops.insert(op_id, pending);
                }
            }
            None => {
                self.root_daemon_connection.state = ConnectionState::Disconnected;
                self.root_daemon_connection.last_error =
                    Some("root daemon channel unavailable".to_string());
                let token = self.next_editor_status_token();
                self.publish_editor_status(
                    &pending,
                    false,
                    token,
                    "root daemon channel unavailable",
                );
            }
        }
    }

    fn spawn_hotconfig_daemons(&mut self, profile: &ContainerName) {
        let list = self
            .daemon_catalog
            .get(profile)
            .cloned()
            .unwrap_or_default();
        if list.is_empty() {
            return;
        }
        self.ensure_up_client(profile);
        for args in list {
            let key = daemon_key(profile, &args);
            if self.spawned_daemons.insert(key) {
                if let Some(tx) = self.up_cmd.get(profile) {
                    let exec_resolved = if let Some(name) = &args.shell {
                        match which::which(name) {
                            Ok(p) => Some(p.to_string_lossy().to_string()),
                            Err(_) => Some(name.clone()),
                        }
                    } else {
                        None
                    };

                    let spawn_args = diag::SpawnArgs {
                        uid: args.uid,
                        gid: args.gid,
                        exec: exec_resolved,
                        cwd: args.cwd,
                        gids: args.gids,
                        args: args.args,
                        ringbuf_size: None,
                        application: None,
                        ns: diag::NamespaceSpawn::Inside,
                    };
                    let _ = tx.send(diag::DaemonRequest::Spawn { args: spawn_args });
                }
            }
        }
    }

    fn emit_snapshot(&mut self) {
        let started = std::time::Instant::now();
        let mut profiles: BTreeMap<ContainerName, ContainerState> = BTreeMap::new();

        for profile in &self.known_profiles {
            // Use cached config to avoid per-event disk reads.
            // A default is produced inline when the cache entry is absent (first frame
            // before an explicit Load command populates it).
            let (
                hotconfig,
                hotconfig_value,
                template,
                template_value,
                sandbox_status,
                template_error,
            ) = if let Some(c) = self.config_cache.get(profile) {
                (
                    c.hotconfig.clone(),
                    c.hotconfig_value.clone(),
                    c.template.clone(),
                    c.template_value.clone(),
                    c.sandbox_status.clone(),
                    c.template_error.clone(),
                )
            } else {
                let hc = HotConfig::default();
                let hv = serde_json::json!({});
                let tc = TemplateConfig::default();
                let tv = serde_json::json!({});
                (hc, hv, tc, tv, None, None)
            };

            let ns_status = self
                .ns_alive_status
                .get(profile)
                .cloned()
                .unwrap_or_default();
            // Use cached NsAlive (updated in refresh_profile_status_inner).
            let ns_alive = if ns_status.child_alive || ns_status.serve_alive {
                self.ns_alive_cache.get(profile).cloned()
            } else {
                None
            };

            let diag = self.diag_state.get(profile);
            let up_connection = self.up_connection.get(profile).cloned().unwrap_or_default();
            let diag_connection = self
                .diag_connection
                .get(profile)
                .cloned()
                .unwrap_or_default();
            let diag_connected = diag_connection.state == ConnectionState::Connected;

            profiles.insert(
                profile.clone(),
                ContainerState {
                    process_list_snapshot: self.process_list_snapshot.get(profile).cloned(),
                    container_lifecycle: self.container_lifecycle(profile),
                    child_pid: ns_status.child_pid,
                    child_alive: ns_status.child_alive,
                    up_connected: up_connection.state == ConnectionState::Connected,
                    up_connection: up_connection.state,
                    up_error: up_connection.last_error,
                    serve_pid: ns_status.serve_pid,
                    serve_alive: ns_status.serve_alive,
                    diag_connection: diag_connection.state,
                    diag_error: diag_connection.last_error,
                    hotconfig,
                    template,
                    sandbox_status,
                    template_error,
                    routing_state: diag.and_then(|d| d.routing_state.clone()),
                    dns_state: diag.and_then(|d| d.dns_state.clone()),
                    diag_connected,
                    diag_summary: diag.and_then(build_diag_summary),
                    traffic: if self.is_traffic_subscribed(profile.as_str()) {
                        diag.map(build_traffic_snapshot).unwrap_or_default()
                    } else {
                        TrafficSnapshot::default()
                    },
                    proxy_stats: diag.map(|d| d.proxy_stats.clone()).unwrap_or_default(),
                    hotconfig_value,
                    template_value,
                    ns_alive,
                    up_ns: self
                        .profile_ns_cache
                        .get(profile)
                        .and_then(|v| v.up.clone()),
                    keeper_ns: self
                        .profile_ns_cache
                        .get(profile)
                        .and_then(|v| v.keeper.clone()),
                    logs_by_level: self
                        .up_logs
                        .get(profile)
                        .cloned()
                        .unwrap_or_else(|| Arc::new(RwLock::new(LevelLogView::default()))),
                    diag_event_log: if self.is_traffic_subscribed(profile.as_str()) {
                        diag.map(|d| d.diag_event_log.iter().cloned().collect())
                            .unwrap_or_default()
                    } else {
                        Vec::new()
                    },
                    conns_state: if self.is_traffic_subscribed(profile.as_str()) {
                        diag.map(|d| d.conns_state.clone()).unwrap_or_default()
                    } else {
                        diag::ConnsState::default()
                    },
                    veth_status: self
                        .veth_status
                        .get(profile)
                        .cloned()
                        .or_else(|| load_veth_status_from_disk(profile))
                        .unwrap_or_default(),
                    pty_streams: HashMap::new(),
                },
            );
        }

        let _ = self.snapshot_tx.send(SupervisorSnapshot {
            profiles,
            ui_ns: self.ui_ns_cache.clone(),
            namespace_warning: self.namespace_warning.clone(),
            root_daemon_connection: self.root_daemon_connection.state,
            root_daemon_error: self.root_daemon_connection.last_error.clone(),
            hotconfig_editor_status: self.hotconfig_editor_status.clone(),
            profile_editor_status: self.profile_editor_status.clone(),
            constants_editor_status: self.constants_editor_status.clone(),
            constants_editor_content: self.constants_editor_content.clone(),
            personal_runtime_state: self.personal_runtime_state.clone(),
            root_daemon_logs: self.root_daemon_logs.clone(),
            auto_open_logs_target: self.auto_open_logs_target.clone(),
            generated_at: SystemTime::now(),
        });
        let elapsed = started.elapsed();
        if elapsed >= std::time::Duration::from_millis(50) {
            info!(
                profile_count = self.known_profiles.len(),
                elapsed_ms = elapsed.as_millis(),
                "slow supervisor snapshot emission"
            );
        }
        self.ectx.request_repaint();
    }
}

#[derive(Clone, Debug, Default)]
pub struct NsAliveStatus {
    pub profile: ContainerName,
    pub child_alive: bool,
    pub child_pid: Option<i32>,
    pub serve_alive: bool,
    pub serve_pid: Option<i32>,
    pub up_alive: bool,
    pub up_pid: Option<i32>,
}

#[derive(Debug)]
enum SupervisorEvent {
    DiagEvent {
        profile: ContainerName,
        event: DiagEvent,
    },
    UpEvent {
        profile: ContainerName,
        event: diag::DaemonEvent,
    },
    ConnectionUpdate {
        profile: ContainerName,
        target: ConnectionTarget,
        state: ConnectionState,
        error: Option<String>,
    },
    /// A ready `UpDaemonStream` has been delivered by the control socket accept loop.
    InjectUpStream {
        profile: ContainerName,
        stream: diag::UpDaemonStream,
    },
    /// A ready `DiagEventStream` has been delivered by the control socket accept loop.
    InjectDiagStream {
        profile: ContainerName,
        stream: diag::DiagEventStream,
    },
    InjectRootDaemonStream {
        stream: diag::RootDaemonStream,
    },
    RootDaemonConnectionUpdate {
        state: ConnectionState,
        error: Option<String>,
    },
    RootDaemonEvent {
        event: diag::RootDaemonEvent,
    },
    RootDaemonLog {
        entry: diag::LogEntry,
    },
    RootDaemonRecentLogs {
        entries: Vec<diag::LogEntry>,
    },
    /// `sp up` process has been confirmed dead by `kill(0)`; lifecycle transitions to Stopped.
    /// Sub-processes (sp serve, sandbox child) are owned by sp up and need no separate tracking.
    UpDaemonExited {
        profile: ContainerName,
    },
    /// Bootstrap stderr/stdout captured directly from spawned `sp up` before
    /// the up-daemon socket stream is connected.
    BootstrapUpLog {
        profile: ContainerName,
        stream: BootstrapLogStream,
        line: String,
    },
    DeleteProcessLog {
        profile: ContainerName,
        stream: BootstrapLogStream,
        line: String,
    },
    SandboxProcessLog {
        profile: ContainerName,
        stream: BootstrapLogStream,
        line: String,
    },
    DeleteContainerFinished {
        profile: ContainerName,
        success: bool,
        detail: String,
    },
    SandboxFinished {
        profile: ContainerName,
        success: bool,
        detail: String,
    },
    VethProcessLog {
        profile: ContainerName,
        stream: BootstrapLogStream,
        line: String,
    },
    VethFinished {
        profile: ContainerName,
        success: bool,
        detail: String,
    },
    /// Fired when `sandbox_status.json` on disk changes for a profile.
    SandboxStatusChanged {
        profile: ContainerName,
        status: Option<SandboxStatus>,
    },
}

#[derive(Debug, Clone, Copy)]
enum BootstrapLogStream {
    Stdout,
    Stderr,
}

/// Timestamp-based exponential backoff for connection retry loops.
///
/// Urgency increases whenever a connection (or connect attempt) ends faster than
/// [`STABLE_THRESHOLD`].  A connection that stays up longer than the threshold resets
/// urgency to 0 on the next disconnect.  Call [`ConnectionBackoff::reset`] for an
/// intentional restart so the loop connects immediately without any delay.
#[derive(Debug, Default)]
struct ConnectionBackoff {
    /// When the last successful `connect()` call completed (stream handed to caller).
    connected_at: Option<Instant>,
    /// Current urgency level; drives the pre-connect delay via [`urgency_delay`].
    urgency: u32,
}

/// A connection lasting longer than this is considered stable; urgency resets to 0.
const STABLE_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(2);

static ROOT_DAEMON_START_ATTEMPTED: AtomicBool = AtomicBool::new(false);

impl ConnectionBackoff {
    /// Return the delay that should be observed before the next connect attempt.
    /// Does not mutate state; call [`record_connected`] once the stream is established.
    fn next_delay(&self) -> std::time::Duration {
        urgency_delay(self.urgency)
    }

    /// Record that a live connection has been established.  The elapsed time is
    /// measured from this point on [`record_disconnect`].
    fn record_connected(&mut self) {
        self.connected_at = Some(Instant::now());
    }

    /// Record that a connection ended (cleanly or with an error).  Urgency is
    /// incremented when the connection (or the failed connect attempt) lasted
    /// less than [`STABLE_THRESHOLD`]; otherwise it resets to 0.
    fn record_disconnect(&mut self) {
        if let Some(at) = self.connected_at.take() {
            if at.elapsed() < STABLE_THRESHOLD {
                self.urgency = self.urgency.saturating_add(1).min(8);
            } else {
                self.urgency = 0;
            }
        } else {
            // connect() itself failed — always counts as unstable.
            self.urgency = self.urgency.saturating_add(1).min(8);
        }
    }

    /// Explicitly reset urgency and timing state.  Call this before an intentional
    /// restart (StartUp, StopContainer, KillContainer) so the first reconnect
    /// attempt proceeds without delay.
    fn reset(&mut self) {
        self.urgency = 0;
        self.connected_at = None;
    }
}

/// Delay before the next connect attempt given the current urgency level.
/// urgency=0 means "connect immediately" (no prior failures).
fn urgency_delay(urgency: u32) -> std::time::Duration {
    match urgency {
        0 => std::time::Duration::ZERO,
        1 => std::time::Duration::from_millis(200),
        2 => std::time::Duration::from_millis(500),
        3 => std::time::Duration::from_secs(1),
        4 => std::time::Duration::from_secs(2),
        5 => std::time::Duration::from_secs(4),
        _ => std::time::Duration::from_secs(8),
    }
}

fn report_connection_update(
    event_tx: &mpsc::UnboundedSender<SupervisorEvent>,
    profile: &ContainerName,
    target: ConnectionTarget,
    state: ConnectionState,
    error: Option<String>,
) {
    let _ = event_tx.send(SupervisorEvent::ConnectionUpdate {
        profile: profile.clone(),
        target,
        state,
        error,
    });
}

async fn up_stream_loop(
    profile: &ContainerName,
    stream: diag::UpDaemonStream,
    cmd_rx: &mut mpsc::UnboundedReceiver<diag::DaemonRequest>,
    event_tx: &mpsc::UnboundedSender<SupervisorEvent>,
) -> Result<()> {
    let (mut reader, mut writer) = stream.split();

    writer
        .send_unstable_request(&diag::DaemonRequest::GetProcessList)
        .await
        .context("request initial process list")?;
    writer
        .send_unstable_request(&diag::DaemonRequest::Personal(
            diag::personal::PersonalDaemonRequest::GetState,
        ))
        .await
        .context("request personal runtime state")?;
    writer
        .send_unstable_request(&diag::DaemonRequest::QueryRecentLogs {
            limit: diag::LOG_RING_CAP,
        })
        .await
        .context("request recent up daemon logs")?;
    info!(
        profile = profile.as_str(),
        "requested initial up daemon process list"
    );

    loop {
        tokio::select! {
            res = reader.next_event() => {
                match res.context("read up daemon event")? {
                    Some(diag::UpWireEvent::Unstable(event)) => {
                        debug!(profile = profile.as_str(), event = daemon_event_name(&event), "forwarding up daemon event");
                        let _ = event_tx.send(SupervisorEvent::UpEvent {
                            profile: profile.clone(),
                            event,
                        });
                    }
                    Some(diag::UpWireEvent::Stable(event)) => {
                        debug!(profile = profile.as_str(), event = ?event, "ignoring stable up-wire event in ui loop");
                    }
                    None => anyhow::bail!("up daemon closed connection"),
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(cmd) => {
                        debug!(profile = profile.as_str(), cmd = ?cmd, "sending request to up daemon");
                        writer
                            .send_unstable_request(&cmd)
                            .await
                            .with_context(|| format!("send up daemon request: {cmd:?}"))?
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

/// Sleep for `duration`, but return `true` early if `cmd_rx` is closed (all senders dropped).
/// Commands that arrive during the sleep are discarded — they buffer in the channel and will
/// be processed once the connection is re-established.
async fn sleep_or_cancelled<T>(
    duration: std::time::Duration,
    cmd_rx: &mut mpsc::UnboundedReceiver<T>,
) -> bool {
    let sleep = tokio::time::sleep(duration);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            _ = &mut sleep => return false,
            msg = cmd_rx.recv() => {
                if msg.is_none() {
                    return true; // channel closed — supervisor dropped us
                }
                // command arrived during backoff; discard and keep sleeping
            }
        }
    }
}

enum RootDaemonConnectOutcome {
    Ready(diag::RootDaemonStream),
    RestartRequired { message: String },
}

async fn verify_root_daemon_stream(
    mut stream: diag::RootDaemonStream,
) -> Result<RootDaemonConnectOutcome> {
    let local_hash = diag::protocol_version().to_string();
    stream
        .send_stable_request(&diag::StableRequest::Upgrade {
            build_tree_hash: local_hash.clone(),
        })
        .await
        .context("request root daemon protocol upgrade")?;

    let Some(event) = stream
        .next_wire_event()
        .await
        .context("read root daemon upgrade response")?
    else {
        anyhow::bail!("root daemon closed during protocol upgrade");
    };

    match event {
        diag::RootDaemonWireEvent::Stable(diag::StableEvent::UpgradeAccepted {
            build_tree_hash,
        }) => {
            if build_tree_hash == local_hash {
                Ok(RootDaemonConnectOutcome::Ready(stream))
            } else if diag::protocol_lenient() {
                warn!(
                    local_hash = %local_hash,
                    remote_hash = %build_tree_hash,
                    "continuing after root-daemon protocol version mismatch"
                );
                Ok(RootDaemonConnectOutcome::Ready(stream))
            } else {
                let message = format!(
                    "sp daemon version mismatch: {}; restarting",
                    diag::protocol_mismatch_message(&local_hash, &build_tree_hash)
                );
                let _ = stream
                    .send_stable_request(&diag::StableRequest::GracefulShutdown)
                    .await;
                Ok(RootDaemonConnectOutcome::RestartRequired { message })
            }
        }
        diag::RootDaemonWireEvent::Stable(diag::StableEvent::UpgradeRejected { msg }) => {
            let message = format!("sp daemon version mismatch: {msg}; restarting");
            let _ = stream
                .send_stable_request(&diag::StableRequest::GracefulShutdown)
                .await;
            Ok(RootDaemonConnectOutcome::RestartRequired { message })
        }
        diag::RootDaemonWireEvent::Stable(diag::StableEvent::Error { msg }) => {
            anyhow::bail!("root daemon stable protocol error: {msg}")
        }
        other => anyhow::bail!("unexpected root daemon upgrade response: {other:?}"),
    }
}

/// Accept loop for the UI-side control socket.
/// Spawned processes (sp up, sp serve) connect here, write a `ControlSocketGreeting`,
/// and then the normal wire protocol takes over in the supervisor's client loops
/// via inject channels.
async fn control_socket_accept_loop(
    path: PathBuf,
    event_tx: mpsc::UnboundedSender<SupervisorEvent>,
) {
    // Remove a stale socket from a previous session if present.
    let _ = std::fs::remove_file(&path);
    let listener = match tokio::net::UnixListener::bind(&path) {
        Ok(l) => l,
        Err(err) => {
            warn!(path = %path.display(), error = %err, "failed to bind UI control socket; event-triggered connections disabled");
            return;
        }
    };
    info!(path = %path.display(), "UI control socket listening");
    loop {
        match listener.accept().await {
            Ok((mut stream, _addr)) => {
                let event_tx = event_tx.clone();
                tokio::spawn(async move {
                    if let Err(err) = diag::control_handshake_server(&mut stream).await {
                        warn!(error = %err, "control socket: handshake mismatch, disconnecting");
                        return;
                    }
                    match diag::read_control_greeting(&mut stream).await {
                        Ok(Some(diag::ControlSocketGreeting::UpDaemon { name })) => {
                            info!(profile = %name, "control socket: received UpDaemon greeting");
                            let up_stream = diag::UpDaemonStream::from_stream(stream);
                            let _ = event_tx.send(SupervisorEvent::InjectUpStream {
                                profile: name.into(),
                                stream: up_stream,
                            });
                        }
                        Ok(Some(diag::ControlSocketGreeting::ServeDaemon { name })) => {
                            info!(profile = %name, "control socket: received ServeDaemon greeting");
                            let diag_stream = diag::DiagEventStream::from_stream(stream);
                            let _ = event_tx.send(SupervisorEvent::InjectDiagStream {
                                profile: name.into(),
                                stream: diag_stream,
                            });
                        }
                        Ok(Some(diag::ControlSocketGreeting::RootDaemon)) => {
                            info!("control socket: received RootDaemon greeting");
                            let daemon_stream = diag::RootDaemonStream::from_stream(stream);
                            let _ = event_tx.send(SupervisorEvent::InjectRootDaemonStream {
                                stream: daemon_stream,
                            });
                        }
                        Ok(None) => {
                            warn!("control socket: connection closed before greeting");
                        }
                        Err(err) => {
                            warn!(error = %err, "control socket: failed to read greeting");
                        }
                    }
                });
            }
            Err(err) => {
                warn!(error = %err, "control socket accept error");
            }
        }
    }
}

/// Drive an already-connected `UpDaemonStream` that arrived via the UI control socket.
/// Completely bypasses backoff, pid-checks and retry logic — the stream is live and ready.
async fn run_injected_up_stream(
    profile: ContainerName,
    stream: diag::UpDaemonStream,
    mut cmd_rx: mpsc::UnboundedReceiver<diag::DaemonRequest>,
    event_tx: mpsc::UnboundedSender<SupervisorEvent>,
) {
    report_connection_update(
        &event_tx,
        &profile,
        ConnectionTarget::Up,
        ConnectionState::Connected,
        None,
    );
    match up_stream_loop(&profile, stream, &mut cmd_rx, &event_tx).await {
        Ok(()) => {
            info!(profile = profile.as_str(), "inject up stream: clean exit");
        }
        Err(err) => {
            info!(profile = profile.as_str(), error = %err, "inject up stream: disconnected");
            report_connection_update(
                &event_tx,
                &profile,
                ConnectionTarget::Up,
                ConnectionState::Disconnected,
                Some(err.to_string()),
            );
        }
    }
}

/// Drive an already-connected `DiagEventStream` that arrived via the UI control socket.
/// Completely bypasses backoff, pid-checks and retry logic — the stream is live and ready.
async fn run_injected_diag_stream(
    profile: ContainerName,
    mut stream: diag::DiagEventStream,
    mut cmd_rx: mpsc::UnboundedReceiver<ControlCommand>,
    event_tx: mpsc::UnboundedSender<SupervisorEvent>,
) {
    report_connection_update(
        &event_tx,
        &profile,
        ConnectionTarget::Diag,
        ConnectionState::Connected,
        None,
    );
    for cmd in [
        ControlCommand::QueryDnsState,
        ControlCommand::QueryRoutingState,
        ControlCommand::QueryHotConfig,
        ControlCommand::QueryUplinkStats,
        ControlCommand::QueryRecentLogs {
            limit: diag::LOG_RING_CAP,
        },
    ] {
        if let Err(err) = stream.send_cmd(&cmd).await {
            report_connection_update(
                &event_tx,
                &profile,
                ConnectionTarget::Diag,
                ConnectionState::Disconnected,
                Some(format!("initial query {cmd:?}: {err}")),
            );
            return;
        }
    }
    match diag_stream_loop(&profile, stream, &mut cmd_rx, &event_tx).await {
        Ok(()) => {
            info!(profile = profile.as_str(), "inject diag stream: clean exit");
        }
        Err(err) => {
            info!(profile = profile.as_str(), error = %err, "inject diag stream: disconnected");
            report_connection_update(
                &event_tx,
                &profile,
                ConnectionTarget::Diag,
                ConnectionState::Disconnected,
                Some(err.to_string()),
            );
        }
    }
}

async fn root_daemon_stream_loop(
    stream: diag::RootDaemonStream,
    cmd_rx: &mut mpsc::UnboundedReceiver<diag::RootDaemonRequest>,
    event_tx: &mpsc::UnboundedSender<SupervisorEvent>,
) -> Result<()> {
    let (mut reader, mut writer) = stream.split();

    writer
        .send_query_recent_logs(diag::LOG_RING_CAP)
        .await
        .context("request root daemon recent logs")?;

    loop {
        tokio::select! {
            res = reader.next_wire_event() => {
                match res.context("read root daemon wire event")? {
                    Some(diag::RootDaemonWireEvent::Unstable(event)) => {
                        let _ = event_tx.send(SupervisorEvent::RootDaemonEvent { event });
                    }
                    Some(diag::RootDaemonWireEvent::Log(entry)) => {
                        let _ = event_tx.send(SupervisorEvent::RootDaemonLog { entry });
                    }
                    Some(diag::RootDaemonWireEvent::RecentLogs(entries)) => {
                        let _ = event_tx.send(SupervisorEvent::RootDaemonRecentLogs { entries });
                    }
                    Some(diag::RootDaemonWireEvent::Stable(diag::StableEvent::Error { msg })) => {
                        anyhow::bail!("root daemon stable protocol error: {msg}")
                    }
                    Some(other) => anyhow::bail!("unexpected root daemon wire event: {other:?}"),
                    None => anyhow::bail!("root daemon closed connection"),
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(cmd) => {
                        if let Err(err) = writer.send_request(&cmd).await {
                            return Err(err).context("send root daemon request");
                        }
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

async fn run_injected_root_daemon_stream(
    stream: diag::RootDaemonStream,
    mut cmd_rx: mpsc::UnboundedReceiver<diag::RootDaemonRequest>,
    event_tx: mpsc::UnboundedSender<SupervisorEvent>,
    nsproxy_path: PathBuf,
    control_sock_path: PathBuf,
) {
    let stream = match verify_root_daemon_stream(stream).await {
        Ok(RootDaemonConnectOutcome::Ready(stream)) => stream,
        Ok(RootDaemonConnectOutcome::RestartRequired { message }) => {
            let restart_message = message.clone();
            let _ = event_tx.send(SupervisorEvent::RootDaemonConnectionUpdate {
                state: ConnectionState::Connecting,
                error: Some(restart_message),
            });
            match try_start_root_daemon_process(&nsproxy_path, &control_sock_path) {
                Ok(true) => {}
                Ok(false) => {
                    let _ = event_tx.send(SupervisorEvent::RootDaemonConnectionUpdate {
                        state: ConnectionState::NoRetry,
                        error: Some(message),
                    });
                }
                Err(err) => {
                    let _ = event_tx.send(SupervisorEvent::RootDaemonConnectionUpdate {
                        state: ConnectionState::NoRetry,
                        error: Some(format!("failed to restart sp daemon: {err}")),
                    });
                }
            }
            return;
        }
        Err(err) => {
            let _ = event_tx.send(SupervisorEvent::RootDaemonConnectionUpdate {
                state: ConnectionState::Disconnected,
                error: Some(err.to_string()),
            });
            return;
        }
    };

    let _ = event_tx.send(SupervisorEvent::RootDaemonConnectionUpdate {
        state: ConnectionState::Connected,
        error: None,
    });
    if let Err(err) = root_daemon_stream_loop(stream, &mut cmd_rx, &event_tx).await {
        let _ = event_tx.send(SupervisorEvent::RootDaemonConnectionUpdate {
            state: ConnectionState::Disconnected,
            error: Some(err.to_string()),
        });
    }
}

async fn root_daemon_client_loop(
    mut cmd_rx: mpsc::UnboundedReceiver<diag::RootDaemonRequest>,
    event_tx: mpsc::UnboundedSender<SupervisorEvent>,
    backoff: Arc<Mutex<ConnectionBackoff>>,
    nsproxy_path: PathBuf,
    control_sock_path: PathBuf,
) {
    let sock = diag::root_daemon_sock_path();
    let mut restart_note: Option<String> = None;

    loop {
        let delay = backoff.lock().unwrap().next_delay();
        if !delay.is_zero() {
            if sleep_or_cancelled(delay, &mut cmd_rx).await {
                return;
            }
        }

        let _ = event_tx.send(SupervisorEvent::RootDaemonConnectionUpdate {
            state: ConnectionState::Connecting,
            error: None,
        });

        match diag::connect_root_daemon(&sock).await {
            Ok(stream) => {
                let stream = match verify_root_daemon_stream(stream).await {
                    Ok(RootDaemonConnectOutcome::Ready(stream)) => stream,
                    Ok(RootDaemonConnectOutcome::RestartRequired { message }) => {
                        let _ = event_tx.send(SupervisorEvent::RootDaemonConnectionUpdate {
                            state: ConnectionState::Connecting,
                            error: Some(message.clone()),
                        });
                        match try_start_root_daemon_process(&nsproxy_path, &control_sock_path) {
                            Ok(true) => {
                                backoff.lock().unwrap().reset();
                                restart_note = Some(message);
                            }
                            Ok(false) => {
                                backoff.lock().unwrap().record_disconnect();
                                let _ =
                                    event_tx.send(SupervisorEvent::RootDaemonConnectionUpdate {
                                        state: ConnectionState::NoRetry,
                                        error: Some(message),
                                    });
                                return;
                            }
                            Err(err) => {
                                backoff.lock().unwrap().record_disconnect();
                                let _ =
                                    event_tx.send(SupervisorEvent::RootDaemonConnectionUpdate {
                                        state: ConnectionState::NoRetry,
                                        error: Some(format!("failed to restart sp daemon: {err}")),
                                    });
                                return;
                            }
                        }
                        continue;
                    }
                    Err(err) => {
                        let err_text = err.to_string();
                        if !ROOT_DAEMON_START_ATTEMPTED.load(Ordering::Relaxed) {
                            let restart_message = format!(
                                "root daemon initial handshake failed: {err_text}; restarting once"
                            );
                            let _ = event_tx.send(SupervisorEvent::RootDaemonConnectionUpdate {
                                state: ConnectionState::Connecting,
                                error: Some(restart_message),
                            });
                            match try_start_root_daemon_process(&nsproxy_path, &control_sock_path) {
                                Ok(true) => {
                                    backoff.lock().unwrap().reset();
                                    continue;
                                }
                                Ok(false) => {
                                    backoff.lock().unwrap().reset();
                                    continue;
                                }
                                Err(restart_err) => {
                                    backoff.lock().unwrap().record_disconnect();
                                    let _ = event_tx.send(SupervisorEvent::RootDaemonConnectionUpdate {
                                        state: ConnectionState::Disconnected,
                                        error: Some(format!(
                                            "failed to restart sp daemon after initial handshake error: {restart_err}"
                                        )),
                                    });
                                    continue;
                                }
                            }
                        }
                        backoff.lock().unwrap().record_disconnect();
                        let _ = event_tx.send(SupervisorEvent::RootDaemonConnectionUpdate {
                            state: ConnectionState::Disconnected,
                            error: Some(err_text),
                        });
                        continue;
                    }
                };

                backoff.lock().unwrap().record_connected();
                let _ = event_tx.send(SupervisorEvent::RootDaemonConnectionUpdate {
                    state: ConnectionState::Connected,
                    error: restart_note.take(),
                });
                match root_daemon_stream_loop(stream, &mut cmd_rx, &event_tx).await {
                    Ok(()) => return,
                    Err(err) => {
                        backoff.lock().unwrap().record_disconnect();
                        let _ = event_tx.send(SupervisorEvent::RootDaemonConnectionUpdate {
                            state: ConnectionState::Disconnected,
                            error: Some(err.to_string()),
                        });
                    }
                }
            }
            Err(err) => {
                let err_text = format!("failed to connect to {}: {err}", sock.display());
                if !ROOT_DAEMON_START_ATTEMPTED.load(Ordering::Relaxed) {
                    let _ = event_tx.send(SupervisorEvent::RootDaemonConnectionUpdate {
                        state: ConnectionState::Connecting,
                        error: Some(format!("{err_text}; restarting once")),
                    });
                    match try_start_root_daemon_process(&nsproxy_path, &control_sock_path) {
                        Ok(true) => {
                            backoff.lock().unwrap().reset();
                            continue;
                        }
                        Ok(false) => {
                            backoff.lock().unwrap().reset();
                            continue;
                        }
                        Err(restart_err) => {
                            backoff.lock().unwrap().record_disconnect();
                            let _ = event_tx.send(SupervisorEvent::RootDaemonConnectionUpdate {
                                state: ConnectionState::Disconnected,
                                error: Some(format!(
                                    "failed to restart sp daemon after initial connect error: {restart_err}"
                                )),
                            });
                            continue;
                        }
                    }
                }
                backoff.lock().unwrap().record_disconnect();
                let _ = event_tx.send(SupervisorEvent::RootDaemonConnectionUpdate {
                    state: ConnectionState::Disconnected,
                    error: Some(err_text),
                });
            }
        }
    }
}

async fn up_client_loop(
    profile: ContainerName,
    mut cmd_rx: mpsc::UnboundedReceiver<diag::DaemonRequest>,
    event_tx: mpsc::UnboundedSender<SupervisorEvent>,
    backoff: Arc<Mutex<ConnectionBackoff>>,
) {
    let sock = diag::up_sock_path(profile.as_str());
    info!(profile = profile.as_str(), sock = %sock.display(), "up client loop starting");
    loop {
        let delay = backoff.lock().unwrap().next_delay();
        if !delay.is_zero() {
            info!(
                profile = profile.as_str(),
                delay_ms = delay.as_millis(),
                urgency = backoff.lock().unwrap().urgency,
                "up client backing off before next connect"
            );
            if sleep_or_cancelled(delay, &mut cmd_rx).await {
                warn!(
                    profile = profile.as_str(),
                    "up client loop cancelled during backoff: supervisor dropped up_cmd tx"
                );
                return;
            }
        }
        // Before attempting to (re-)connect, verify the sp up process is still running.
        // up_pid is None while the process is still starting up — allow the attempt.
        // Once it has been written and the process is gone, exit the loop.
        {
            let ns_meta = state_paths::profile_ns_meta(profile.as_str());
            if let Ok(ns_alive) = read_ns_alive(&ns_meta) {
                if let Some(up_pid) = ns_alive.up_pid {
                    if !pid_exists(up_pid) {
                        info!(
                            profile = profile.as_str(),
                            up_pid, "up process is gone; exiting up client loop"
                        );
                        report_connection_update(
                            &event_tx,
                            &profile,
                            ConnectionTarget::Up,
                            ConnectionState::Disconnected,
                            Some(format!("sp up process (pid {up_pid}) is gone")),
                        );
                        return;
                    }
                }
            }
        }
        report_connection_update(
            &event_tx,
            &profile,
            ConnectionTarget::Up,
            ConnectionState::Connecting,
            None,
        );
        match diag::connect_up_daemon(&sock).await {
            Ok(stream) => {
                backoff.lock().unwrap().record_connected();
                info!(profile = profile.as_str(), sock = %sock.display(), "connected to up daemon socket");
                report_connection_update(
                    &event_tx,
                    &profile,
                    ConnectionTarget::Up,
                    ConnectionState::Connected,
                    None,
                );
                match up_stream_loop(&profile, stream, &mut cmd_rx, &event_tx).await {
                    Ok(()) => {
                        info!(
                            profile = profile.as_str(),
                            "up client loop exiting cleanly (cmd_rx closed)"
                        );
                        return;
                    }
                    Err(err) => {
                        backoff.lock().unwrap().record_disconnect();
                        info!(profile = profile.as_str(), error = %err, "up daemon connection dropped, will retry");
                        report_connection_update(
                            &event_tx,
                            &profile,
                            ConnectionTarget::Up,
                            ConnectionState::Disconnected,
                            Some(err.to_string()),
                        );
                    }
                }
            }
            Err(err) => {
                backoff.lock().unwrap().record_disconnect();
                debug!(
                    profile = profile.as_str(),
                    sock = %sock.display(),
                    error = %err,
                    "failed to connect to up daemon socket"
                );
                // If the remote rejected our upgrade due to a build hash mismatch,
                // record a terminal NoRetry state so we stop frantic reconnect attempts.
                let err_str = err.to_string();
                if err_str.contains("build hash mismatch") {
                    info!(
                        profile = profile.as_str(),
                        "up daemon upgrade rejected: build hash mismatch; stopping retries"
                    );
                    report_connection_update(
                        &event_tx,
                        &profile,
                        ConnectionTarget::Up,
                        ConnectionState::NoRetry,
                        Some(format!("failed to connect to {}: {err}", sock.display())),
                    );
                    // Do not continue retrying for this profile.
                    return;
                }

                report_connection_update(
                    &event_tx,
                    &profile,
                    ConnectionTarget::Up,
                    ConnectionState::Disconnected,
                    Some(format!("failed to connect to {}: {err}", sock.display())),
                );
            }
        }
    }
}

async fn diag_client_loop(
    profile: ContainerName,
    mut cmd_rx: mpsc::UnboundedReceiver<ControlCommand>,
    event_tx: mpsc::UnboundedSender<SupervisorEvent>,
    backoff: Arc<Mutex<ConnectionBackoff>>,
) {
    let sock = diag::diag_sock_path(profile.as_str());
    info!(profile = profile.as_str(), sock = %sock.display(), "diag client loop starting");
    loop {
        let delay = backoff.lock().unwrap().next_delay();
        if !delay.is_zero() {
            info!(
                profile = profile.as_str(),
                delay_ms = delay.as_millis(),
                urgency = backoff.lock().unwrap().urgency,
                "diag client backing off before next connect"
            );
            if sleep_or_cancelled(delay, &mut cmd_rx).await {
                info!(
                    profile = profile.as_str(),
                    "diag client loop cancelled during backoff"
                );
                return;
            }
        }
        // Before attempting to (re-)connect, verify sp serve is still running.
        // serve_pid is None while the process is still starting up — allow the attempt.
        // Once it has been written and the process is gone, exit the loop.
        {
            let ns_meta = state_paths::profile_ns_meta(profile.as_str());
            if let Ok(ns_alive) = read_ns_alive(&ns_meta) {
                if let Some(serve_pid) = ns_alive.serve_pid {
                    if !pid_exists(serve_pid) {
                        info!(
                            profile = profile.as_str(),
                            serve_pid, "serve process is gone; exiting diag client loop"
                        );
                        report_connection_update(
                            &event_tx,
                            &profile,
                            ConnectionTarget::Diag,
                            ConnectionState::Disconnected,
                            Some(format!("sp serve process (pid {serve_pid}) is gone")),
                        );
                        return;
                    }
                }
            }
        }
        report_connection_update(
            &event_tx,
            &profile,
            ConnectionTarget::Diag,
            ConnectionState::Connecting,
            None,
        );
        match diag::connect(&sock).await {
            Ok(stream) => {
                backoff.lock().unwrap().record_connected();
                info!(profile = profile.as_str(), sock = %sock.display(), "connected to diag socket");
                report_connection_update(
                    &event_tx,
                    &profile,
                    ConnectionTarget::Diag,
                    ConnectionState::Connected,
                    None,
                );
                if diag_stream_drive(&profile, stream, &mut cmd_rx, &event_tx, &backoff).await {
                    info!(
                        profile = profile.as_str(),
                        "diag client loop exiting cleanly (cmd_rx closed)"
                    );
                    return;
                }
            }
            Err(err) => {
                backoff.lock().unwrap().record_disconnect();
                debug!("diag connect failed for {}: {err:?}", profile);
                report_connection_update(
                    &event_tx,
                    &profile,
                    ConnectionTarget::Diag,
                    ConnectionState::Disconnected,
                    Some(format!("failed to connect to {}: {err}", sock.display())),
                );
            }
        }
    }
}

/// Send initial snapshot-query commands and then drive the stream loop.
/// Returns `true` if the loop should exit cleanly (cmd_rx closed), `false` to continue reconnecting.
async fn diag_stream_drive(
    profile: &ContainerName,
    mut stream: DiagEventStream,
    cmd_rx: &mut mpsc::UnboundedReceiver<ControlCommand>,
    event_tx: &mpsc::UnboundedSender<SupervisorEvent>,
    backoff: &Arc<Mutex<ConnectionBackoff>>,
) -> bool {
    for cmd in [
        ControlCommand::QueryDnsState,
        ControlCommand::QueryRoutingState,
        ControlCommand::QueryHotConfig,
        ControlCommand::QueryUplinkStats,
        ControlCommand::QueryRecentLogs {
            limit: diag::LOG_RING_CAP,
        },
    ] {
        info!(profile = profile.as_str(), cmd = ?cmd, "sending initial diag command");
        if let Err(err) = stream.send_cmd(&cmd).await {
            info!(profile = profile.as_str(), cmd = ?cmd, error = %err, "failed to send initial diag command, will retry");
            report_connection_update(
                event_tx,
                profile,
                ConnectionTarget::Diag,
                ConnectionState::Disconnected,
                Some(format!("send initial diag command {cmd:?}: {err}")),
            );
            backoff.lock().unwrap().record_disconnect();
            return false;
        }
    }
    match diag_stream_loop(profile, stream, cmd_rx, event_tx).await {
        Ok(()) => true,
        Err(err) => {
            backoff.lock().unwrap().record_disconnect();
            info!(profile = profile.as_str(), error = %err, "diag connection dropped, will retry");
            report_connection_update(
                event_tx,
                profile,
                ConnectionTarget::Diag,
                ConnectionState::Disconnected,
                Some(err.to_string()),
            );
            false
        }
    }
}

async fn diag_stream_loop(
    profile: &ContainerName,
    stream: DiagEventStream,
    cmd_rx: &mut mpsc::UnboundedReceiver<ControlCommand>,
    event_tx: &mpsc::UnboundedSender<SupervisorEvent>,
) -> Result<()> {
    let (mut reader, mut writer) = stream.split();

    loop {
        tokio::select! {
            res = reader.next() => {
                match res.context("read diag event")? {
                    Some(event) => {
                        debug!(profile = profile.as_str(), event = diag_event_name(&event), "forwarding diag event");
                        let _ = event_tx.send(SupervisorEvent::DiagEvent {
                            profile: profile.clone(),
                            event,
                        });
                    }
                    None => anyhow::bail!("diag socket closed"),
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(cmd) => {
                        debug!(profile = profile.as_str(), cmd = ?cmd, "sending command to diag socket");
                        writer
                            .send_cmd(&cmd)
                            .await
                            .with_context(|| format!("send diag command: {cmd:?}"))?
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

fn daemon_key(profile: &ContainerName, args: &ShellArgs) -> String {
    let payload = serde_json::to_string(args).unwrap_or_default();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    payload.hash(&mut hasher);
    format!("{}:{:x}", profile, hasher.finish())
}

fn build_diag_summary(state: &DiagState) -> Option<DiagSummary> {
    if state.accumulator.conns.is_empty() {
        return None;
    }
    let active = state
        .accumulator
        .conns
        .values()
        .filter(|conn| conn.finished_ts.is_none())
        .count();

    Some(DiagSummary {
        total_conns: state.accumulator.conns.len(),
        active_conns: active,
    })
}

fn build_traffic_snapshot(state: &DiagState) -> TrafficSnapshot {
    let acc = &state.accumulator;
    TrafficSnapshot {
        conn_order: acc.conn_order.clone(),
        conns: acc.conns.clone(),
        loop_avg_us: acc.loop_stats.avg_us(),
        loop_max_us: acc.loop_stats.max_us(),
        loop_min_us: acc.loop_stats.min_us(),
        loop_samples: acc.loop_stats.recent.len(),
    }
}

fn diag_event_is_traffic_only(event: &DiagEvent) -> bool {
    matches!(
        event,
        DiagEvent::Accept { .. }
            | DiagEvent::Dispatched { .. }
            | DiagEvent::Route { .. }
            | DiagEvent::Connected { .. }
            | DiagEvent::Finished { .. }
            | DiagEvent::DnsResolved { .. }
            | DiagEvent::DnsQuery { .. }
            | DiagEvent::Wait { .. }
            | DiagEvent::WaitEnded { .. }
            | DiagEvent::RecentDiagEvents(_)
            | DiagEvent::ConnsStateSnapshot { .. }
    )
}

fn default_nsproxy_path() -> PathBuf {
    if let Ok(current) = std::env::current_exe() {
        if let Some(parent) = current.parent() {
            let candidate = parent.join("nsproxy");
            if candidate.exists() {
                return candidate;
            }
        }
    }
    PathBuf::from("nsproxy")
}

/// Direct spawning by UI
struct SpawnedCli {
    pid: Pid,
    stdout_r: i32,
    stderr_r: i32,
}

/// Direct spawning by UI
fn spawn_nsproxy_cli(path: &Path, cli: &Cli) -> Result<SpawnedCli> {
    let fd_file = cli_to_inheritable_fd(cli)?;
    let fd = fd_file.as_raw_fd();

    let mut stdout_pipe = [0; 2];
    let mut stderr_pipe = [0; 2];
    unsafe {
        if libc::pipe(stdout_pipe.as_mut_ptr()) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if libc::pipe(stderr_pipe.as_mut_ptr()) != 0 {
            libc::close(stdout_pipe[0]);
            libc::close(stdout_pipe[1]);
            return Err(std::io::Error::last_os_error().into());
        }
    }

    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            unsafe {
                libc::close(stdout_pipe[1]);
                libc::close(stderr_pipe[1]);
            }
            Ok(SpawnedCli {
                pid: child,
                stdout_r: stdout_pipe[0],
                stderr_r: stderr_pipe[0],
            })
        }
        ForkResult::Child => {
            unsafe {
                libc::close(stdout_pipe[0]);
                libc::close(stderr_pipe[0]);
            }
            let _ = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
            let _ = unsafe { libc::setsid() };
            unsafe {
                libc::dup2(stdout_pipe[1], libc::STDOUT_FILENO);
                libc::dup2(stderr_pipe[1], libc::STDERR_FILENO);
                libc::close(stdout_pipe[1]);
                libc::close(stderr_pipe[1]);
            }
            let fd_str = fd.to_string();
            let argv = [to_cstr(path.to_string_lossy().as_ref()), to_cstr(&fd_str)];
            let envs: Vec<_> = std::env::vars()
                .map(|(k, v)| {
                    let mut s = k;
                    s.push('=');
                    s.push_str(&v);
                    to_cstr(&s)
                })
                .collect();
            let _ = execve(&to_cstr(path.to_string_lossy().as_ref()), &argv, &envs);
            std::process::exit(127);
        }
    }
}

fn spawn_root_daemon_process(nsproxy_path: &Path, control_sock_path: &Path) -> Result<()> {
    let cli = Cli {
        conf: None,
        root: None,
        no_wrap_check: false,
        control_socket: Some(control_sock_path.to_path_buf()),
        cmd: MainCommand::Daemon { cmd: None },
    };
    let _ = spawn_nsproxy_cli_detached(nsproxy_path, &cli)?;
    Ok(())
}

fn try_start_root_daemon_process(nsproxy_path: &Path, control_sock_path: &Path) -> Result<bool> {
    if ROOT_DAEMON_START_ATTEMPTED.swap(true, Ordering::SeqCst) {
        return Ok(false);
    }
    spawn_root_daemon_process(nsproxy_path, control_sock_path)?;
    Ok(true)
}

fn spawn_nsproxy_cli_detached(path: &Path, cli: &Cli) -> Result<Pid> {
    let fd_file = cli_to_inheritable_fd(cli)?;
    let fd = fd_file.as_raw_fd();

    match unsafe { fork()? } {
        ForkResult::Parent { child } => Ok(child),
        ForkResult::Child => {
            let _ = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
            let _ = unsafe { libc::setsid() };
            let fd_str = fd.to_string();
            let argv = [to_cstr(path.to_string_lossy().as_ref()), to_cstr(&fd_str)];
            let envs: Vec<_> = std::env::vars()
                .map(|(k, v)| {
                    let mut s = k;
                    s.push('=');
                    s.push_str(&v);
                    to_cstr(&s)
                })
                .collect();
            let _ = execve(&to_cstr(path.to_string_lossy().as_ref()), &argv, &envs);
            std::process::exit(127);
        }
    }
}

fn spawn_bootstrap_log_reader(
    profile: ContainerName,
    stream: BootstrapLogStream,
    fd: i32,
    event_tx: mpsc::UnboundedSender<SupervisorEvent>,
) {
    spawn_child_log_reader(profile, stream, fd, event_tx, |profile, stream, line| {
        SupervisorEvent::BootstrapUpLog {
            profile,
            stream,
            line,
        }
    });
}

fn spawn_child_log_reader<F>(
    profile: ContainerName,
    stream: BootstrapLogStream,
    fd: i32,
    event_tx: mpsc::UnboundedSender<SupervisorEvent>,
    event_builder: F,
) where
    F: Fn(ContainerName, BootstrapLogStream, String) -> SupervisorEvent + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let file = unsafe { File::from_raw_fd(fd) };
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let msg = line.trim_end_matches(['\r', '\n']).to_string();
                    if msg.is_empty() {
                        continue;
                    }
                    let _ = event_tx.send(event_builder(profile.clone(), stream, msg));
                }
                Err(err) => {
                    let _ = event_tx.send(event_builder(
                        profile.clone(),
                        stream,
                        format!("log read error: {err}"),
                    ));
                    break;
                }
            }
        }
    });
}

fn spawn_child_waiter<F>(
    profile: ContainerName,
    pid: Pid,
    event_tx: mpsc::UnboundedSender<SupervisorEvent>,
    event_builder: F,
) where
    F: FnOnce(ContainerName, bool, String) -> SupervisorEvent + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut status: libc::c_int = 0;
        let wait_rc = unsafe { libc::waitpid(pid.as_raw(), &mut status, 0) };
        let (success, detail) = if wait_rc < 0 {
            (
                false,
                format!(
                    "waitpid failed for pid {}: {}",
                    pid.as_raw(),
                    std::io::Error::last_os_error()
                ),
            )
        } else if unsafe { libc::WIFEXITED(status) } {
            let code = unsafe { libc::WEXITSTATUS(status) };
            (code == 0, format!("exit code {code}"))
        } else if unsafe { libc::WIFSIGNALED(status) } {
            let signal = unsafe { libc::WTERMSIG(status) };
            (false, format!("terminated by signal {signal}"))
        } else {
            (false, format!("unexpected wait status {status}"))
        };
        let _ = event_tx.send(event_builder(profile, success, detail));
    });
}

fn load_hotconfig_daemons(profile: &str) -> Result<Vec<ShellArgs>> {
    let path = state_paths::hot_config(profile);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(&path)?;
    let hot: HotConfig = serde_json::from_str(&content)?;
    Ok(hot.daemons)
}

fn load_hotconfig_from_disk(profile: &ContainerName) -> Option<HotConfig> {
    let path = state_paths::hot_config(profile.as_str());
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(_) => return Some(HotConfig::default()),
    };
    match serde_json::from_str::<HotConfig>(&content) {
        Ok(hot) => Some(hot),
        Err(err) => {
            warn!("invalid hotconfig JSON on disk for {}: {err}", profile);
            Some(HotConfig::default())
        }
    }
}

fn load_sandbox_status_from_disk(profile: &ContainerName) -> Option<SandboxStatus> {
    read_sandbox_status(profile.as_str())
}

fn load_veth_status_from_disk(profile: &ContainerName) -> Option<Vec<VethStatus>> {
    let content = std::fs::read_to_string(state_paths::veth_status(profile.as_str())).ok()?;
    let snapshot = serde_json::from_str::<nsproxy_core::VethStatusSnapshot>(&content).ok()?;
    Some(
        snapshot
            .entries
            .into_iter()
            .map(|entry| VethStatus {
                success: entry.success,
                detail: entry.detail,
            })
            .collect(),
    )
}

fn pid_exists(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

fn probe_namespace_indicator(pid: i32) -> Option<NamespaceIndicator> {
    let mnt = ExactNS::from_source((PidPath::N(pid), "mnt")).ok();
    let net = ExactNS::from_source((PidPath::N(pid), "net")).ok();
    let pid_ns = ExactNS::from_source((PidPath::N(pid), "pid")).ok();
    if mnt.is_none() && net.is_none() && pid_ns.is_none() {
        return None;
    }
    Some(NamespaceIndicator {
        mnt: mnt.map(|v| format!("{}", v.unique)),
        net: net.map(|v| format!("{}", v.unique)),
        pid: pid_ns.map(|v| format!("{}", v.unique)),
    })
}

/// Read the wall-clock start time of a process by parsing `/proc/{pid}/stat` and
/// `/proc/stat` (for the system boot time).  Returns `None` if either file is
/// unreadable or the relevant fields are missing/unparseable.
///
/// The `starttime` field (field 22 in `/proc/pid/stat`, 1-indexed) is expressed in
/// clock ticks since boot.  Combined with the `btime` field from `/proc/stat` it
/// gives the absolute Unix timestamp of when the process was forked.
fn read_proc_start_time(pid: u32) -> Option<SystemTime> {
    // Boot time: read btime from /proc/stat.
    let stat_content = std::fs::read_to_string("/proc/stat").ok()?;
    let btime_secs: u64 = stat_content
        .lines()
        .find(|l| l.starts_with("btime "))?
        .split_ascii_whitespace()
        .nth(1)?
        .parse()
        .ok()?;

    // Process starttime (ticks since boot) from /proc/{pid}/stat.
    // Field 2 (comm) can contain spaces and parens; find the last ')' to skip it safely.
    let pid_stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = pid_stat.rfind(')')? + 1;
    // Fields after comm (0-indexed): 0=state 1=ppid … 19=starttime (field 22 overall).
    let starttime_ticks: u64 = pid_stat[after_comm..]
        .split_ascii_whitespace()
        .nth(19)?
        .parse()
        .ok()?;

    let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
    if ticks_per_sec == 0 {
        return None;
    }
    let start_secs = btime_secs + starttime_ticks / ticks_per_sec;
    let start_subsec_ns = (starttime_ticks % ticks_per_sec) * 1_000_000_000 / ticks_per_sec;
    Some(SystemTime::UNIX_EPOCH + std::time::Duration::new(start_secs, start_subsec_ns as u32))
}

/// Like `pid_exists` but correctly treats `EPERM` as alive, and additionally probes
/// `/proc/{pid}/status` and `/proc/{pid}/stat` to catch three cases where `kill(0)` lies:
///
/// - **Zombie**: the process has already exited but hasn't been reaped yet.
///   `kill(0)` returns 0 for zombies; `/proc/{pid}/status` State field shows 'Z'.
///
/// - **PID reuse (by name)**: the original `sp up` died and a different process
///   inherited the PID.  Caught via the `Name:` field in `/proc/{pid}/status`.
///
/// - **PID reuse (by start time)**: if `started_at` is provided, we compare the
///   process's kernel-recorded start time (from `/proc/{pid}/stat`) against it.
///   Any process whose start time is more than 5 s after our recorded spawn time
///   cannot be the original `sp up`.
///
/// The philosophy is *prove it dead*: any evidence that the PID no longer belongs
/// to the original `sp up` process is treated as death.
fn up_pid_alive(pid: u32, started_at: Option<SystemTime>) -> bool {
    // Fast path: ESRCH → definitely dead.
    let r = unsafe { libc::kill(pid as libc::pid_t, 0) };
    let kill_sees_it = if r == 0 {
        true
    } else {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        match errno {
            e if e == libc::ESRCH => return false, // gone
            e if e == libc::EPERM => true,         // different uid/ns but exists
            _ => return false,                     // unexpected → treat as dead
        }
    };

    // /proc/status cross-check: zombie state or name-based PID reuse.
    let status_path = format!("/proc/{pid}/status");
    match std::fs::read_to_string(&status_path) {
        Err(_) => {
            // /proc entry is gone (race with ESRCH) → dead.
            return false;
        }
        Ok(content) => {
            let mut state_char: Option<char> = None;
            let mut proc_name: Option<String> = None;
            for line in content.lines() {
                if let Some(v) = line.strip_prefix("State:") {
                    state_char = v.trim().chars().next();
                } else if let Some(v) = line.strip_prefix("Name:") {
                    proc_name = Some(v.trim().to_owned());
                }
                if state_char.is_some() && proc_name.is_some() {
                    break;
                }
            }

            // Zombie: process has already called exit(); just awaiting reap.
            if state_char == Some('Z') {
                return false;
            }

            // Name-based PID reuse: comm no longer matches what sp up would show.
            // Linux truncates argv[0] basename to 15 chars for the comm field.
            if let Some(ref name) = proc_name {
                if name != "nsproxy" && name != "sp" {
                    return false;
                }
            }
        }
    }

    // Start-time-based PID reuse: compare kernel-recorded process start time against
    // the wall-clock time we captured immediately after fork().
    // A reused PID will have a start time strictly after our recorded spawn time;
    // we allow a 5-second forward window to absorb any clock jitter.
    if let Some(recorded) = started_at {
        if let Some(proc_start) = read_proc_start_time(pid) {
            const REUSE_WINDOW: std::time::Duration = std::time::Duration::from_secs(5);
            if proc_start > recorded + REUSE_WINDOW {
                info!(
                    pid,
                    "sp up PID reuse detected via start-time mismatch: \
                     proc_start={proc_start:?} recorded={recorded:?}"
                );
                return false;
            }
        }
    }

    kill_sees_it
}

/// Poll `up_pid` with `kill(pid, 0)` until it returns `ESRCH`, then send `UpDaemonExited`.
///
/// Schedule: 50 ms → 200 ms → 1 s (quick succession after a stop request), then 2 s
/// intervals up to a 30-second hard timeout that forces the transition regardless.
///
/// Only `sp up` is polled here.  Sub-processes (`sp serve`, sandbox child) are directly
/// owned by `sp up` which will `waitpid()` them — we learn about those exits event-driven
/// via `DaemonEvent::ProcessListSnapshot`.  Zero file-descriptors are consumed.
async fn watch_up_pid_exit(
    profile: ContainerName,
    up_pid: u32,
    started_at: Option<SystemTime>,
    event_tx: mpsc::UnboundedSender<SupervisorEvent>,
) {
    info!("waiting for sp up (pid {up_pid}) to exit");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    for delay_ms in [50u64, 200, 1000, 200, 200, 200, 2000] {
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        if !up_pid_alive(up_pid, started_at) {
            info!(
                profile = profile.as_str(),
                up_pid, "sp up exited (kill(0) → ESRCH)"
            );
            let _ = event_tx.send(SupervisorEvent::UpDaemonExited { profile });
            return;
        } else {
            info!(
                profile = profile.as_str(),
                up_pid, "sp up still alive after {} ms", delay_ms
            );
        }
    }
    // Quick succession exhausted; fall back to 2-second periodic polling.
    loop {
        if tokio::time::Instant::now() >= deadline {
            warn!(
                profile = profile.as_str(),
                up_pid, "sp up did not exit within 30s of stop request; forcing Stopped transition"
            );
            let _ = event_tx.send(SupervisorEvent::UpDaemonExited { profile });
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        if !up_pid_alive(up_pid, started_at) {
            info!(
                profile = profile.as_str(),
                up_pid, "sp up exited (kill(0) → ESRCH)"
            );
            let _ = event_tx.send(SupervisorEvent::UpDaemonExited { profile });
            return;
        }
    }
}

fn fallback_stop_profile_from_metadata(
    profile: &ContainerName,
    up_logs: &mut HashMap<ContainerName, SharedLevelLogRings>,
) {
    info!(
        profile = profile.as_str(),
        "executing metadata-based container kill fallback"
    );
    let ns_meta = state_paths::profile_ns_meta(profile.as_str());
    let Ok(ns_alive) = read_ns_alive(&ns_meta) else {
        push_up_log(
            up_logs,
            profile,
            diag::LogEntry {
                ts: diag::Timestamp::now(),
                level: "WARN".to_string(),
                target: "supervisor".to_string(),
                message: "No ns metadata available for container kill fallback".to_string(),
                fields: Vec::new(),
            },
        );
        return;
    };

    let mut killed_any = false;
    for (label, pid) in [("up", ns_alive.up_pid), ("keeper", ns_alive.child_pid)] {
        if let Some(pid) = pid.filter(|&p| pid_exists(p)) {
            info!(
                profile = profile.as_str(),
                label, pid, "sending SIGKILL in container kill fallback"
            );
            let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
            push_up_log(
                up_logs,
                profile,
                diag::LogEntry {
                    ts: diag::Timestamp::now(),
                    level: "INFO".to_string(),
                    target: "supervisor".to_string(),
                    message: format!(
                        "Container kill fallback sent SIGKILL to {} pid {}",
                        label, pid
                    ),
                    fields: Vec::new(),
                },
            );
            killed_any = true;
        }
    }

    if !killed_any {
        push_up_log(
            up_logs,
            profile,
            diag::LogEntry {
                ts: diag::Timestamp::now(),
                level: "INFO".to_string(),
                target: "supervisor".to_string(),
                message: "Container kill fallback found no live up/keeper pid".to_string(),
                fields: Vec::new(),
            },
        );
    }
}

fn plain_log_entry(level: &str, target: &str, message: impl Into<String>) -> LogEntry {
    LogEntry {
        ts: diag::Timestamp::now(),
        level: level.to_string(),
        target: target.to_string(),
        message: message.into(),
        fields: Vec::new(),
    }
}

fn push_up_log(
    up_logs: &mut HashMap<ContainerName, SharedLevelLogRings>,
    profile: &ContainerName,
    entry: LogEntry,
) {
    push_profile_log(up_logs, profile, LogSource::Up, entry);
}

fn push_global_log(logs: &SharedLevelLogRings, src: LogSource, entry: LogEntry) {
    let mut guard = logs.write().unwrap_or_else(|e| e.into_inner());
    guard.push_entry(src, entry);
}

fn replace_global_logs_for_source<I>(logs: &SharedLevelLogRings, src: LogSource, entries: I)
where
    I: IntoIterator<Item = LogEntry>,
{
    let mut guard = logs.write().unwrap_or_else(|e| e.into_inner());
    guard.replace_source(src, entries);
}

fn push_profile_log(
    up_logs: &mut HashMap<ContainerName, SharedLevelLogRings>,
    profile: &ContainerName,
    src: LogSource,
    entry: LogEntry,
) {
    let logs = up_logs
        .entry(profile.clone())
        .or_insert_with(|| Arc::new(RwLock::new(LevelLogView::default())))
        .clone();
    let mut guard = logs.write().unwrap_or_else(|e| e.into_inner());
    guard.push_entry(src, entry);
}

fn replace_profile_logs_for_source<I>(
    up_logs: &mut HashMap<ContainerName, SharedLevelLogRings>,
    profile: &ContainerName,
    src: LogSource,
    entries: I,
) where
    I: IntoIterator<Item = LogEntry>,
{
    let logs = up_logs
        .entry(profile.clone())
        .or_insert_with(|| Arc::new(RwLock::new(LevelLogView::default())))
        .clone();
    let mut profile_logs = logs.write().unwrap_or_else(|e| e.into_inner());
    profile_logs.replace_source(src, entries);
}

fn log_level_rank(level: &str) -> u8 {
    match level.trim().to_ascii_uppercase().as_str() {
        "TRACE" => 0,
        "DEBUG" => 1,
        "WARN" => 3,
        "ERROR" => 4,
        _ => 2,
    }
}

fn load_template_from_disk(profile: &ContainerName) -> Result<TemplateConfig, String> {
    let path = state_paths::profile_config(profile.as_str());
    TemplateConfig::load(&path).map_err(|e| format!("invalid JSON: {e}"))
}
