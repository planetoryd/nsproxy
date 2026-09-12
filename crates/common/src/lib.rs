#![feature(associated_type_defaults)]
#![feature(decl_macro)]

use std::borrow::Borrow;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::future::Future;
use std::hash::Hash;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::{LazyLock, RwLock};
use std::{borrow::Cow, os::fd::AsRawFd, path::PathBuf};

use anyhow::Result;
use anyhow::{ensure, Context};
use derive_new::new;
use fs4::fs_std::FileExt;
use fully_pub::fully_pub as public;
use indexmap::{Equivalent, IndexMap};
use libc::stat;
use nix::errno::Errno;
use nix::{libc::pid_t, unistd::getpid};
use owo_colors::OwoColorize;
use serde::{de::Visitor, Deserialize, Serialize};

pub mod crdt;
pub mod routing;
pub mod rpc;
pub mod stats;

pub const UID_HINT_VAR: &str = "NSPROXY_UID";

/// Persistent profile storage root
pub const PERSIST_ROOT: &str = "/nsp3";

/// Helper functions for consistent path handling
pub mod state_paths {
    use super::*;

    static PERSIST_ROOT_STATE: LazyLock<RwLock<PathBuf>> =
        LazyLock::new(|| RwLock::new(PathBuf::from(PERSIST_ROOT)));

    /// Current persistent root for profile state.
    pub fn persist_root() -> PathBuf {
        PERSIST_ROOT_STATE
            .read()
            .expect("persist root lock poisoned")
            .clone()
    }

    /// Override persistent root for the current process.
    pub fn set_persist_root(root: impl Into<PathBuf>) {
        *PERSIST_ROOT_STATE
            .write()
            .expect("persist root lock poisoned") = root.into();
    }

    /// Root directory for persistent profile configuration.
    pub fn config_root() -> PathBuf {
        persist_root().join("config")
    }

    /// Root directory for container rootfs trees used by pivot_root.
    pub fn rootfs_root() -> PathBuf {
        persist_root().join("rootfs")
    }

    /// Get persistent config directory for a named profile.
    pub fn profile_dir(name: &str) -> PathBuf {
        config_root().join(name)
    }

    /// Get rootfs directory for a named profile.
    pub fn profile_rootfs_dir(name: &str) -> PathBuf {
        rootfs_root().join(name)
    }

    /// Get profile.json path for a named profile
    pub fn profile_config(name: &str) -> PathBuf {
        profile_dir(name).join("profile.json")
    }

    /// Get hot.json path for a named profile
    pub fn hot_config(name: &str) -> PathBuf {
        profile_dir(name).join("hot.json")
    }

    /// Get sandbox status snapshot path for a named profile.
    pub fn sandbox_status(name: &str) -> PathBuf {
        profile_dir(name).join("sandbox_status.json")
    }

    /// Runtime veth reconciliation results for a named profile.
    pub fn veth_status(name: &str) -> PathBuf {
        profile_dir(name).join("veth_status.json")
    }

    /// Get namespace bind mount path inside profile instance dir
    /// Returns /nsp3/config/{name}/net
    pub fn profile_netns_bind(name: &str) -> PathBuf {
        profile_dir(name).join("net")
    }

    /// Get a persistent namespace bind mount path for the basis namespace.
    pub fn basis_ns_bind(namespace: &str) -> PathBuf {
        profile_dir("basis").join(namespace)
    }

    /// Get namespace metadata JSON path inside profile instance dir
    /// Returns /nsp3/config/{name}/ns_alive.json
    pub fn profile_ns_meta(name: &str) -> PathBuf {
        profile_dir(name).join("ns_alive.json")
    }

    /// Get metadata JSON path from bind mount path
    pub fn metadata_for_bind(bind_path: &Path) -> PathBuf {
        bind_path.with_extension("json")
    }

    /// Get uplink root directory for a specific kind (e.g., "clash", "geph")
    /// Returns /nsp3/uplink/{kind}
    pub fn uplink_dir(kind: &str) -> PathBuf {
        persist_root().join("uplink").join(kind)
    }

    /// Get uplink root directory
    /// Returns /nsp3/uplink
    pub fn uplink_root() -> PathBuf {
        persist_root().join("uplink")
    }

    /// Get uplink profile directory for a specific kind and profile name
    /// Returns /nsp3/uplink/{kind}/{profile}
    pub fn uplink_profile_dir(kind: &str, profile: &str) -> PathBuf {
        uplink_dir(kind).join(profile)
    }

    /// Global wrapped binaries config path
    /// Returns /nsp3/wrapped_binaries.json
    pub fn wrapped_binaries_config() -> PathBuf {
        persist_root().join("wrapped_binaries.json")
    }

    /// Personal constants config path.
    /// Returns /nsp3/constants.json
    pub fn constants_config() -> PathBuf {
        persist_root().join("constants.json")
    }

    /// Centralized Clash state path
    /// Returns /nsp3/uplink/clash.json
    pub fn uplink_clash_state() -> PathBuf {
        uplink_root().join("clash.json")
    }

    /// Persistent remote proxy list state path
    /// Returns /nsp3/uplink/remote.json
    pub fn uplink_remote_state() -> PathBuf {
        uplink_root().join("remote.json")
    }

    /// Persistent uplink link-stats state path
    /// Returns /nsp3/uplink/stats.json
    pub fn uplink_stats_state() -> PathBuf {
        uplink_root().join("stats.json")
    }

    /// Pivot-root staging directory for a named profile.
    /// Returns /tmp/nsproxy_{name}
    pub fn pivot_root_mem(name: &str) -> PathBuf {
        PathBuf::from(format!("/tmp/nsproxy_{}", name))
    }

    /// This is the default pattern, because many docker images use / for state store
    pub fn pivot_root(name: &str) -> PathBuf {
        profile_rootfs_dir(name)
    }

    /// Global namespace registry path.
    /// Returns /nsp3/namespaces.json
    pub fn namespaces_registry() -> PathBuf {
        persist_root().join("namespaces.json")
    }

    /// Root directory for per-process diagnostic logs.
    /// Returns /nsp3/logs
    pub fn logs_root() -> PathBuf {
        persist_root().join("logs")
    }

    /// Per-process diagnostic log path.
    /// Returns /nsp3/logs/{process_label}-{pid}.jsonl
    pub fn process_log_file(process_label: &str, pid: u32) -> PathBuf {
        let safe_label: String = process_label
            .chars()
            .map(|ch| match ch {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => ch,
                _ => '_',
            })
            .collect();
        logs_root().join(format!("{}-{}.jsonl", safe_label, pid))
    }

    /// Append-only log of nsproxy process invocations for the current boot.
    pub fn process_log() -> PathBuf {
        persist_root().join("nsproxy-process-log.jsonl")
    }

    /// Boot ID associated with [`process_log`].
    pub fn process_log_boot() -> PathBuf {
        persist_root().join("nsproxy-process-log.boot")
    }
}

pub fn current_boot_time_secs() -> Result<u64> {
    let content = std::fs::read_to_string("/proc/stat")?;
    let line = content
        .lines()
        .find(|line| line.starts_with("btime "))
        .ok_or_else(|| anyhow::anyhow!("missing btime entry in /proc/stat"))?;
    let value = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("malformed btime entry in /proc/stat"))?;
    Ok(value.parse()?)
}

/// Returns the kernel boot ID from `/proc/sys/kernel/random/boot_id`.
/// This is a UUID that changes on every boot, suitable for cache/state invalidation.
pub fn current_boot_id() -> Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_string())
}

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Eq, Debug)]
pub struct NsAlive {
    #[serde(default)]
    pub boot_time_secs: Option<u64>,
    #[serde(default)]
    pub profile_name: Option<String>,
    pub browser_profile: Option<String>,
    pub bind_mount: PathBuf,
    /// keeper process within netns
    pub child_pid: Option<u32>,
    #[serde(default)]
    pub serve_pid: Option<u32>,
    /// sp up daemon, socket server
    #[serde(default)]
    pub up_pid: Option<u32>,
    /// Uniquely identifies a rootfs created at runtime
    #[serde(default)]
    pub rootfs: Option<UniqueFile>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ProfileNamespaces {
    pub mnt: ExactNS,
    pub net: ExactNS,
    pub pid: ExactNS,
}

impl Inode for ProfileNamespaces {
    fn ino_eq(&self, other: &Self) -> bool {
        self.mnt.ino_eq(&other.mnt)
            && self.net.ino_eq(&other.net)
            && self.pid.ino_eq(&other.pid)
    }
}

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Eq, Debug)]
pub struct NamespacesRegistry {
    #[serde(default)]
    pub profiles: HashMap<String, ProfileNamespaces>,
    /// Namespace set recorded as the basis host/UI namespace.
    #[serde(default, alias = "default_ns")]
    pub basis_ns: Option<ProfileNamespaces>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct NamespaceRegistryInit {
    pub current: ProfileNamespaces,
    pub basis_ns: ProfileNamespaces,
    pub initialized: bool,
}

impl NamespacesRegistry {
    /// Record the current process namespaces as the basis if none exists.
    pub fn initialize_basis(
        current: ProfileNamespaces,
        force: bool,
    ) -> Result<NamespaceRegistryInit> {
        let mut initialized = false;
        let basis_ns = Self::update_locked_recover(|registry| {
            if force || registry.basis_ns.is_none() {
                registry.basis_ns = Some(current.clone());
                initialized = true;
            }
            Ok(registry
                .basis_ns
                .clone()
                .expect("basis namespace was set"))
        })?;

        Ok(NamespaceRegistryInit {
            current,
            basis_ns,
            initialized,
        })
    }

    pub fn load_locked() -> Result<Self> {
        let path = state_paths::namespaces_registry();
        let lock = Self::open_lock_file()?;
        lock.lock_shared()
            .context("failed to acquire shared namespaces registry lock")?;
        let registry = Self::read_or_default(&path)?;
        Ok(registry)
    }

    pub fn update_locked<T>(update: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let path = state_paths::namespaces_registry();
        let lock = Self::open_lock_file()?;
        lock.lock_exclusive()
            .context("failed to acquire exclusive namespaces registry lock")?;

        let mut registry = Self::read_or_default(&path)?;
        let result = update(&mut registry)?;
        Self::write_atomic(&path, &registry)?;
        Ok(result)
    }

    fn update_locked_recover<T>(update: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let path = state_paths::namespaces_registry();
        let lock = Self::open_lock_file()?;
        lock.lock_exclusive()
            .context("failed to acquire exclusive namespaces registry lock")?;

        let mut registry = match Self::read_or_default(&path) {
            Ok(registry) => registry,
            Err(error) => {
                tracing::warn!(
                    path = ?path,
                    %error,
                    "incompatible namespaces registry; replacing it"
                );
                Self::default()
            }
        };
        let result = update(&mut registry)?;
        Self::write_atomic(&path, &registry)?;
        Ok(result)
    }

    fn open_lock_file() -> Result<std::fs::File> {
        let path = state_paths::namespaces_registry();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("failed to create namespaces state dir")?;
        }

        let lock_path = path.with_extension("json.lock");
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .context("failed to open namespaces registry lock file")
    }

    fn read_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read namespaces registry from {:?}", path))?;
        serde_json::from_str(&content).context("failed to parse namespaces registry json")
    }

    fn write_atomic(path: &Path, registry: &Self) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("failed to create namespaces state dir")?;
        }

        let tmp = path.with_extension("tmp");
        let content = serde_json::to_string_pretty(registry)
            .context("failed to serialize namespaces registry")?;
        let mut file = std::fs::File::create(&tmp)
            .with_context(|| format!("failed to create temp namespaces file {:?}", tmp))?;
        use std::io::Write as _;
        file.write_all(content.as_bytes())
            .context("failed to write temp namespaces file")?;
        file.sync_all()
            .context("failed to sync temp namespaces file")?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("failed to replace namespaces registry {:?}", path))?;
        Ok(())
    }
}

/// Represents an NS anchored to a process, or a file
/// `Inode::ino_eq` compares namespace identity; `Eq` also compares the source.
#[public]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct ExactNS {
    unique: UniqueFile,
    source: NSSource,
}

pub trait Inode {
    fn ino_eq(&self, other: &Self) -> bool;
}

impl Inode for ExactNS {
    fn ino_eq(&self, other: &Self) -> bool {
        self.unique.ino_eq(&other.unique)
    }
}

impl Display for ExactNS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("File {} ", self.unique.yellow()))?;
        match self.source {
            NSSource::Pid(ref p) => f.write_fmt(format_args!("from pid {}", p.bright_purple())),
            NSSource::Path(ref p) => f.write_fmt(format_args!("at {:?}", p.yellow())),
            NSSource::Unavail(b) => f.write_fmt(format_args!("{}", "Unavailable".magenta())),
        }
    }
}

/// We don't care about the means.
/// We want to uniquely identify a file so we don't get into a wrong NS.
/// IIRC ino and dev uniquely identifies a file
#[public]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord, new)]
struct UniqueFile {
    ino: u64,
    dev: u64,
}

impl Inode for UniqueFile {
    fn ino_eq(&self, other: &Self) -> bool {
        self == other
    }
}

impl From<stat> for UniqueFile {
    fn from(value: stat) -> Self {
        Self {
            ino: value.st_ino,
            dev: value.st_dev,
        }
    }
}

impl Serialize for UniqueFile {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self { ino, dev } = self;
        serializer.serialize_str(&format!("{dev}_{ino}"))
    }
}

impl core::fmt::Display for UniqueFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { ino, dev } = self;
        f.write_fmt(format_args!("{dev}_{ino}"))
    }
}

impl<'de> Deserialize<'de> for UniqueFile {
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(UFVisitor)
    }
}

impl FromStr for UniqueFile {
    type Err = serde::de::value::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        UFVisitor.visit_str(s)
    }
}

struct UFVisitor;

impl<'de> Visitor<'de> for UFVisitor {
    type Value = UniqueFile;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("string representation of UniqueFile")
    }
    fn visit_str<E>(self, v: &str) -> std::prelude::v1::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let mut sp = v.split("_");
        Ok(UniqueFile {
            dev: sp
                .next()
                .ok_or(serde::de::Error::missing_field("dev"))?
                .parse()
                .map_err(serde::de::Error::custom)?,
            ino: sp
                .next()
                .ok_or(serde::de::Error::missing_field("ino"))?
                .parse()
                .map_err(serde::de::Error::custom)?,
        })
    }
}

/// Pid literal
#[derive(Clone, Copy, Debug)]
pub enum PidPath {
    Selfproc,
    N(i32),
}

#[public]
impl PidPath {
    fn to_str(&self) -> Cow<'static, str> {
        match self {
            PidPath::N(n) => n.to_string().into(),
            PidPath::Selfproc => "self".into(),
        }
    }
    /// Convert it to pid number
    fn to_n(&self) -> Self {
        match self {
            PidPath::Selfproc => Self::N(getpid().as_raw()),
            k => *k,
        }
    }
}

pub trait NSFrom<S>: Sized {
    fn from_source(source: S) -> Result<Self>;
}

impl NSFrom<PathBuf> for ExactNS {
    fn from_source(path: PathBuf) -> Result<Self> {
        tracing::info!("stating exact NS at {:?}", &path);
        let stat = nix::sys::stat::stat(&path)?;
        Ok(Self {
            unique: stat.into(),
            source: NSSource::Path(path),
        })
    }
}

impl NSFrom<(PidPath, &str)> for ExactNS {
    fn from_source(source: (PidPath, &str)) -> Result<Self> {
        let path = PathBuf::from(format!(
            "/proc/{}/ns/{}",
            source.0.to_n().to_str(),
            source.1
        ));
        NSFrom::from_source(path)
    }
}

impl NSFrom<pid_t> for ExactNS {
    fn from_source(source: pid_t) -> Result<Self> {
        Ok(Self {
            unique: pidfd_uf(source)?.into(),
            source: NSSource::Pid(source),
        })
    }
}

impl UniqueFile {
    pub fn validate(&self, fst: &stat) -> Result<(), ValidationErr> {
        if fst.st_ino == self.ino && fst.st_dev == self.dev {
            Ok(())
        } else {
            Err(ValidationErr::InoMismatch)
        }
    }
}

use thiserror::Error;

#[derive(Error, Debug)]
#[error("{:?}", self)]
pub enum ValidationErr {
    InoMismatch,
    FileNonExist,
    FileNonExistProc,
    ProcessGone,
    Permission,
}

#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum NSSource {
    Pid(pid_t),
    Path(PathBuf),
    /// Ex. running as an unprivileged process, the root NS can't be stated.
    /// And we don't keep ephemeral proc fs paths either
    /// Treated as path when validating
    /// True for IOCTL-able
    /// False for not (usually root ns)
    Unavail(bool),
}

#[derive(Default)]
#[public]
struct VaCache {
    pid: IndexMap<NSedPid, stat>,
    mnt: IndexMap<NSedPath, stat>,
}

#[test]
fn getbyref() {
    let va = VaCache::default();
    let uq = UniqueFile { ino: 0, dev: 0 };
    va.pid.get(&(0, &uq));
    let pa = PathBuf::new();
    va.mnt.get(&(&pa, &uq));
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct NSedPid(pid_t, UniqueFile);

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct NSedPath(PathBuf, UniqueFile);

pub type NPid<'k> = (pid_t, &'k UniqueFile);
impl Equivalent<NSedPid> for NPid<'_> {
    fn equivalent(&self, key: &NSedPid) -> bool {
        self.0 == key.0 && self.1 == &key.1
    }
}

impl<'a> From<&'a NPid<'a>> for NSedPid {
    fn from(value: &'a NPid) -> Self {
        Self(value.0.to_owned(), value.1.to_owned())
    }
}

pub type NMnt<'k> = (&'k PathBuf, &'k UniqueFile); // Namespaced mount

impl Equivalent<NSedPath> for NMnt<'_> {
    fn equivalent(&self, key: &NSedPath) -> bool {
        self.0 == &key.0 && self.1 == &key.1
    }
}

impl<'a> From<&'a NMnt<'_>> for NSedPath {
    fn from(value: &'a NMnt) -> Self {
        Self(value.0.to_owned(), value.1.to_owned())
    }
}

pub trait CachedMap {
    type K;
    type V;
    fn cached_get<'e, E: Equivalent<Self::K> + Hash + PartialEq>(
        &mut self,
        key: &'e E,
        init: impl FnOnce(&E) -> Result<Self::V>,
    ) -> Result<&Self::V>
    where
        &'e E: Into<Self::K>;
}

impl<K: Hash + Eq, V> CachedMap for IndexMap<K, V> {
    type K = K;
    type V = V;
    fn cached_get<'e, E: Equivalent<Self::K> + Hash + PartialEq>(
        &mut self,
        key: &'e E,
        init: impl FnOnce(&E) -> Result<Self::V>,
    ) -> Result<&Self::V>
    where
        &'e E: Into<Self::K>,
    {
        if !self.contains_key(key) {
            self.insert(key.into(), init(key)?);
        }
        Ok(self.get(key).unwrap())
    }
}

pub fn cached_fstat<'m>(ca: &'m mut VaCache, cp: NPid) -> Result<&'m stat> {
    ca.pid.cached_get(&cp, |k| pidfd_uf(k.0))
}

/// Stat by a pid
pub fn pidfd_uf(k: pid_t) -> Result<stat> {
    match unsafe { pidfd::PidFd::open(k, 0) } {
        Ok(f) => {
            let fd = f.as_raw_fd();
            let st = nix::sys::stat::fstat(fd)?;
            Ok(st)
        }
        Err(eno) => {
            // WARN This should be "no such process", but who knows
            if eno.raw_os_error() == Some(3) {
                return Err(ValidationErr::ProcessGone.into());
            } else {
                return Err(eno.into());
            }
        }
    }
}

pub fn cached_stat<'k>(ca: &'k mut VaCache, path: NMnt) -> Result<&'k stat> {
    ca.mnt.cached_get(&path, |k| {
        let st = nix::sys::stat::stat::<Path>(k.0.as_path());
        if let Err(ref e) = st {
            match e {
                Errno::ENOENT => Err(if k.0.starts_with("/proc/") {
                    ValidationErr::FileNonExistProc.into()
                } else {
                    ValidationErr::FileNonExist.into()
                }),
                Errno::EPERM | Errno::EACCES => Err(ValidationErr::Permission.into()),
                _ => Err(st.unwrap_err().into()),
            }
        } else {
            Ok(st.unwrap())
        }
    })
}

pub use anyhow::Ok as aok;

pub fn log_err<T, E, F>(op: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E>,
    E: Display,
{
    let result = op();
    if let Err(ref err) = result {
        tracing::error!("{err}");
    }
    result
}

#[track_caller]
pub fn trace_spawn_result<F, T, E>(
    task_name: &'static str,
    future: F,
) -> impl Future<Output = ()> + Send
where
    F: Future<Output = std::result::Result<T, E>> + Send,
    E: Display,
{
    let location = std::panic::Location::caller();
    async move {
        if let Err(error) = future.await {
            tracing::error!(
                task = task_name,
                file = location.file(),
                line = location.line(),
                error = %error,
                "spawned task failed"
            );
        }
    }
}

#[test]
fn test_f() {
    let rx = nix::sys::stat::stat("./nonexist");
    let _ = dbg!(rx);
    let rx = unsafe { pidfd::PidFd::open(65532, 0) };
    let ox = rx.err().unwrap();
    let _ = dbg!(ox.raw_os_error());
}

#[test]
fn initialize_basis_replaces_incompatible_registry() {
    let previous_root = state_paths::persist_root();
    let root = std::env::temp_dir().join(format!(
        "nsproxy-common-namespace-registry-{}",
        getpid()
    ));
    let _ = std::fs::remove_dir_all(&root);
    state_paths::set_persist_root(&root);

    let path = state_paths::namespaces_registry();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "{\"basis_ns\": invalid}").unwrap();

    let current = ProfileNamespaces {
        mnt: ExactNS::from_source((PidPath::Selfproc, "mnt")).unwrap(),
        net: ExactNS::from_source((PidPath::Selfproc, "net")).unwrap(),
        pid: ExactNS::from_source((PidPath::Selfproc, "pid")).unwrap(),
    };
    let init = NamespacesRegistry::initialize_basis(current, false).unwrap();

    assert!(init.initialized);
    let registry = NamespacesRegistry::load_locked().unwrap();
    assert_eq!(registry.basis_ns, Some(init.current));

    let _ = std::fs::remove_dir_all(root);
    state_paths::set_persist_root(previous_root);
}

pub macro forever() {
    ::std::future::pending::<()>()
}

#[derive(Debug, Clone)]
pub enum DNSHost {
    Tier1(SocketAddr),
    Tier2Domain {
        domain: String,
        /// Must be Some, unless this is passed to proxies capable of DNS resolution
        socket: Option<SocketAddr>,
    },
    Tier2IP(SocketAddr),
}

/// DNS domain normalization: ensures trailing dot per RFC 1034/1035
pub fn normalize_domain(domain: &mut String) {
    let trimmed = domain.trim().to_string();
    if !trimmed.is_empty() && !trimmed.ends_with('.') {
        *domain = format!("{}.", trimmed);
    } else {
        *domain = trimmed;
    }
}
