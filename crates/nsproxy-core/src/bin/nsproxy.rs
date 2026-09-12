#![feature(ip_as_octets)]

use anyhow::ensure;
use capctl::prctl;
/// This binary will at most spawn 2 processes (including itself)
/// It's intended to be minimal, which can be used later in higher order composition such as in GUI
use clap::{
    CommandFactory, Parser, Subcommand, ValueEnum,
    builder::{TypedValueParser, ValueParser, ValueParserFactory},
};
use clap_complete::{generate, shells::Fish};
use futures::stream::{FuturesUnordered, TryStreamExt};
use futures::{
    AsyncWriteExt, SinkExt, StreamExt,
    channel::{
        mpsc::{self, unbounded},
        oneshot,
    },
    future::join_all,
};
use reqwest::redirect::Policy;
use socks5_impl::protocol::WireAddress;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as TokioWriteExt},
    time::sleep,
};

use futures_lite::future::block_on;
use fs4::fs_std::FileExt;
use hardware_address::MacAddr;
use ipnetwork::{IpNetwork, Ipv4Network};
use libc::KERN_HOTPLUG;
use nix::{
    mount::{MsFlags, mount as nix_mount},
    pty::openpty,
    sched::{CloneFlags, unshare},
    unistd::{
        ForkResult, Gid, Pid, Uid, chdir, chown, dup2, execve, fork, getresgid, getresuid, pipe,
        setgroups, setpgid, setresgid, setresuid, setsid,
    },
};
use notify::{Event, EventKind, RecommendedWatcher, Watcher, event::ModifyKind};
use nsproxy_common::{
    ExactNS, Inode, NSFrom, NSSource, NamespacesRegistry, PidPath, ProfileNamespaces, UniqueFile,
    forever,
};
use nsproxy_core::{
    BasisCommand, Cli, DaemonCliRequest, HotConfig, MainCommand, NetlinkOps, NsproxyConfig, Paths,
    PathsBinds, SandboxMode, TemplateConfig, TunMaker,
    cmd_common::{
        apply_ns_env, check_proxy_mode, enter_ns, enter_ns_sandboxed, read_ns_alive,
        read_ns_alive_opt, report_clone3_err, update_ns_alive,
    },
    env::{
        ENV_DBUS_SESSION_BUS_ADDRESS, ENV_DBUS_SYSTEM_BUS_ADDRESS, ENV_NS, args_deduce_mount,
        name_to_mount_path,
    },
    hot_reload::{VethIps, sync_links, watch_hot},
    sandbox::{
        apply_chmod, apply_mounts, assert_mount_ns_matches, collect_sandbox_status,
        read_sandbox_status, write_sandbox_status,
    },
    shell::{ShellPrefs, ShellArgs},
    state_paths,
    sys::{
        Clone3Result, NSEnter, check_capsys, check_selfns, enable_ping_all, mount_bind,
        mount_bind_ro_explicit, mount_bind_root, mount_bind_rw_explicit, mount_ns,
        mount_nsswitch_conf, mount_resolv_conf, mount_tmpfs, pivot_root_into,
        replace_mount_resolv_conf, rm_mount, umount_detach_targets,
    },
    tokio_netlink_conn,
    utils::ToExactNs,
};
use nsproxy_core::{
    cmd_uplink::{cmd_uplink, load_saved_uplink_hub},
    env::{ENV_CONTAINER, ENV_PROFILE},
    *,
};
use owo_colors::OwoColorize;
use passfd::FdPassingExt;
use pidfd::PidFd;
use rtnetlink::packet_route::{
    AddressFamily,
    link::{LinkAttribute, LinkExtentMask, LinkFlags, LinkHeader},
};
use rtnetlink::{Handle, LinkMessageBuilder, LinkUnspec, LinkVeth};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque, hash_map::Entry},
    convert::Infallible,
    ffi::OsStr,
    fs::{self, Permissions},
    future::{pending, ready},
    io::{ErrorKind, Read, Write},
    mem::ManuallyDrop,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
        unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::{Component, Path, PathBuf},
    pin::Pin,
    process::{Command, Stdio, exit},
    str::FromStr,
    sync::Mutex,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{select, sync};
use tracing::{error, info, level_filters::LevelFilter, warn};
use tracing_subscriber::{Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use tun2socks5::{
    ArgMode, IArgs, VirtDNSChange, aok, diag,
    dns::VirtDNSHandle,
    flume,
    ipstack::stream::{IpStackStream, IpStackTcpStream},
    tun_rs::AsyncDevice,
};
use uzers::os::unix::UserExt;

use nsproxy_core::HotRoute;

#[derive(Debug, Clone)]
enum VethNamespaceTarget {
    Pid(u32),
    Fd(Arc<fs::File>),
}

#[derive(Debug, Clone)]
struct VethEndpoint {
    arg: NsArg,
    label: String,
    target: VethNamespaceTarget,
    source: NSSource,
}

#[derive(Debug, Serialize, Deserialize)]
enum NetnsChildResult<T> {
    Ok(T),
    Err(String),
}
use nsproxy_core::internal_dns::run_dns_ipv4_only;

const PTY_SCROLLBACK_CAP: usize = 256 * 1024;
const PTY_BROADCAST_CAP: usize = 128;

struct PtyScrollbackState {
    cap: usize,
    ring: VecDeque<u8>,
}

impl PtyScrollbackState {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            ring: VecDeque::with_capacity(cap),
        }
    }
}

struct RawLogRingState {
    cap: usize,
    next_seq: u64,
    ring: VecDeque<diag::RawLog>,
}

impl RawLogRingState {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            next_seq: 0,
            ring: VecDeque::with_capacity(cap),
        }
    }
}

fn profile_bus_socket(profile: &str) -> PathBuf {
    state_paths::profile_dir(profile)
        .join("bus")
        .join("session.sock")
}

fn profile_bus_address(profile: &str) -> String {
    format!("unix:path={}", profile_bus_socket(profile).display())
}

fn profile_system_bus_socket(profile: &str) -> PathBuf {
    state_paths::profile_dir(profile)
        .join("bus")
        .join("system.sock")
}

fn profile_system_bus_address(profile: &str) -> String {
    format!("unix:path={}", profile_system_bus_socket(profile).display())
}

fn session_bus_ready(socket_path: &Path) -> bool {
    if !fs::symlink_metadata(socket_path).is_ok_and(|metadata| metadata.file_type().is_socket()) {
        return false;
    }

    let address = format!("unix:path={}", socket_path.display());
    let mut child = match Command::new("dbus-send")
        .arg(format!("--bus={address}"))
        .args([
            "--dest=org.freedesktop.DBus",
            "--type=method_call",
            "--print-reply",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.ListNames",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            warn!(%err, "cannot run dbus-send to check private session bus health");
            return false;
        }
    };

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                warn!(socket = %socket_path.display(), "private session bus health check timed out");
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            Err(err) => {
                warn!(%err, socket = %socket_path.display(), "private session bus health check failed");
                return false;
            }
        }
    }
}

fn dbus_mode_for_profile(ns_alive: &nsproxy_core::NsAlive) -> nsproxy_core::DbusMode {
    ns_alive
        .profile_name
        .as_ref()
        .and_then(|profile| TemplateConfig::load(&state_paths::profile_config(profile)).ok())
        .map(|template| template.dbus)
        .unwrap_or_default()
}

fn maybe_session_bus_address(ns_alive: &nsproxy_core::NsAlive) -> Option<String> {
    let profile = ns_alive.profile_name.as_deref()?;
    match dbus_mode_for_profile(ns_alive) {
        nsproxy_core::DbusMode::Block => None,
        nsproxy_core::DbusMode::Pass => std::env::var(ENV_DBUS_SESSION_BUS_ADDRESS).ok(),
        nsproxy_core::DbusMode::Proxy => None,
        nsproxy_core::DbusMode::Container => Some(profile_bus_address(profile)),
    }
}

fn maybe_system_bus_address(ns_alive: &nsproxy_core::NsAlive) -> Option<String> {
    let profile = ns_alive.profile_name.as_deref()?;
    match dbus_mode_for_profile(ns_alive) {
        nsproxy_core::DbusMode::Block => None,
        nsproxy_core::DbusMode::Pass => std::env::var(ENV_DBUS_SYSTEM_BUS_ADDRESS).ok(),
        nsproxy_core::DbusMode::Proxy => None,
        nsproxy_core::DbusMode::Container => Some(profile_system_bus_address(profile)),
    }
}

/// Apply the correct D-Bus environment to `shell_prefs` based on the profile's DbusMode.
/// Must be called AFTER `shell_prefs.adjust()`:
/// - Block: strip DBUS_SESSION_BUS_ADDRESS (adjust() captured it from parent env)
/// - Pass:  do nothing (already inherited from parent env via adjust())
/// - Container: replace with the private per-profile dbus-daemon socket address
fn apply_dbus_env(shell_prefs: &mut ShellPrefs, ns_alive: &nsproxy_core::NsAlive) {
    match dbus_mode_for_profile(ns_alive) {
        nsproxy_core::DbusMode::Block => shell_prefs.strip_dbus_env(),
        nsproxy_core::DbusMode::Pass => {}
        // Retain the legacy config value without preserving the old incomplete
        // proxy implementation or exposing the host bus by accident.
        nsproxy_core::DbusMode::Proxy => shell_prefs.strip_dbus_env(),
        nsproxy_core::DbusMode::Container => {
            if let Some(profile) = ns_alive.profile_name.as_deref() {
                shell_prefs.set_dbus_session_bus_env(&profile_bus_address(profile));
                shell_prefs.set_dbus_system_bus_env(&profile_system_bus_address(profile));
            }
        }
    }
}

/// Run one self-contained session bus for a container.
///
/// Unlike `dbus-broker-launch`, `dbus-daemon` handles traditional D-Bus service
/// activation itself, without requiring a host or nested systemd user manager.
/// The daemon is run in the foreground so the `sp dbus` task group owns its
/// lifetime and the UI can report it just like `sp serve`.
fn run_container_dbus_daemon(socket_path: &Path, system: bool) -> Result<()> {
    let address = format!("unix:path={}", socket_path.display());
    // `sp` is setuid-root, but the daemon must use the profile owner's real
    // credentials. Otherwise it inherits a mixed real/user and effective/root
    // identity, which can leave a socket that accepts connections but cannot
    // complete D-Bus authentication.
    let uid = getresuid()?.real.as_raw();
    let gid = getresgid()?.real.as_raw();
    let runtime_dir = socket_path
        .parent()
        .ok_or_else(|| anyhow!("private session-bus socket has no parent directory"))?;
    fs::create_dir_all(runtime_dir)?;
    chown(
        runtime_dir,
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
    )?;
    fs::set_permissions(runtime_dir, Permissions::from_mode(0o700))?;

    let mut command = Command::new("dbus-daemon");
    let dbus_args = if system {
        ["--system", "--nofork", "--nopidfile"]
    } else {
        ["--session", "--nofork", "--nopidfile"]
    };
    command
        .args(dbus_args)
        .arg(format!("--address={address}"))
        .uid(uid)
        .gid(gid)
        // Activated services receive DBUS_STARTER_ADDRESS from the daemon.
        // Do not preserve the host bus addresses in their inherited env.
        .env_remove(ENV_DBUS_SESSION_BUS_ADDRESS);
    command.env_remove(ENV_DBUS_SYSTEM_BUS_ADDRESS);

    let status = command.status()?;
    let _ = fs::remove_file(socket_path);
    ensure!(status.success(), "dbus-daemon exited with {status}");
    Ok(())
}

fn build_spawn_env_pairs(
    ns_alive: &nsproxy_core::NsAlive,
    dbus_session_address: Option<&str>,
    dbus_system_address: Option<&str>,
) -> Vec<(String, String)> {
    let container_val = ns_alive
        .profile_name
        .clone()
        .unwrap_or_else(|| "UNSPEC".to_string());
    let profile_val = ns_alive
        .browser_profile
        .clone()
        .unwrap_or_else(|| "UNSPEC".to_string());
    let ns_val = ns_alive.bind_mount.to_string_lossy().to_string();

    unsafe {
        std::env::set_var(ENV_CONTAINER, &container_val);
        std::env::set_var(ENV_PROFILE, &profile_val);
        std::env::set_var(ENV_NS, &ns_val);
    }

    let mut env_pairs: Vec<(String, String)> = std::env::vars().collect();
    env_pairs.retain(|(k, _)| {
        k != ENV_CONTAINER
            && k != ENV_PROFILE
            && k != ENV_NS
            && k != ENV_DBUS_SESSION_BUS_ADDRESS
            && k != ENV_DBUS_SYSTEM_BUS_ADDRESS
    });
    env_pairs.push((ENV_CONTAINER.to_string(), container_val));
    env_pairs.push((ENV_PROFILE.to_string(), profile_val));
    env_pairs.push((ENV_NS.to_string(), ns_val));
    if let Some(address) = dbus_session_address {
        unsafe {
            std::env::set_var(ENV_DBUS_SESSION_BUS_ADDRESS, address);
        }
        env_pairs.push((
            ENV_DBUS_SESSION_BUS_ADDRESS.to_string(),
            address.to_string(),
        ));
    }
    if let Some(address) = dbus_system_address {
        unsafe {
            std::env::set_var(ENV_DBUS_SYSTEM_BUS_ADDRESS, address);
        }
        env_pairs.push((ENV_DBUS_SYSTEM_BUS_ADDRESS.to_string(), address.to_string()));
    }
    env_pairs
}

fn build_spawn_env_cstrings(
    ns_alive: &nsproxy_core::NsAlive,
    dbus_session_address: Option<&str>,
    dbus_system_address: Option<&str>,
) -> Result<Vec<std::ffi::CString>> {
    build_spawn_env_pairs(ns_alive, dbus_session_address, dbus_system_address)
        .into_iter()
        .map(|(k, v)| std::ffi::CString::new(format!("{}={}", k, v)))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

/// Outcome of checking a recorded basis-namespace entry against the namespaces
/// we currently observe.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BasisValidity {
    /// No basis entry is recorded at all.
    Empty,
    /// Entry is recorded but one or more namespace identities no longer match.
    Invalid(String),
    /// Entry is recorded and still matches the current namespaces.
    Valid,
}

/// Compare a recorded basis entry against the namespaces we currently observe.
/// `Inode::ino_eq` compares namespace identity only (dev/ino), not the source.
fn validate_recorded_basis(
    recorded: &ProfileNamespaces,
    current: &ProfileNamespaces,
) -> BasisValidity {
    if recorded.ino_eq(current) {
        return BasisValidity::Valid;
    }
    let mut drifted = Vec::new();
    if !recorded.mnt.ino_eq(&current.mnt) {
        drifted.push("mnt");
    }
    if !recorded.net.ino_eq(&current.net) {
        drifted.push("net");
    }
    if !recorded.pid.ino_eq(&current.pid) {
        drifted.push("pid");
    }
    BasisValidity::Invalid(drifted.join(", "))
}

fn initialize_basis_namespace(
    force: bool,
) -> anyhow::Result<nsproxy_common::NamespaceRegistryInit> {
    let current = ProfileNamespaces {
        // Mount namespaces are recorded via a /proc path source since they are
        // not bind-mounted to a stable file path like net/pid.
        mnt: ExactNS::from_source((PidPath::N(1), "mnt"))?,
        net: ExactNS::from_source((PidPath::Selfproc, "net"))?,
        pid: ExactNS::from_source((PidPath::Selfproc, "pid"))?,
    };
    // Always check the recorded entry, regardless of --force.
    let validity = match NamespacesRegistry::load_locked()
        .ok()
        .and_then(|registry| registry.basis_ns)
    {
        Some(recorded) => validate_recorded_basis(&recorded, &current),
        None => BasisValidity::Empty,
    };
    match &validity {
        BasisValidity::Empty => println!(
            "basis namespace empty: nothing recorded, recording current namespace"
        ),
        BasisValidity::Invalid(drifted) => println!(
            "basis namespace invalid: {} identity no longer matches current, updating record",
            drifted
        ),
        BasisValidity::Valid => println!("basis namespace valid: recorded identity matches current"),
    }
    let replace = force || matches!(validity, BasisValidity::Empty | BasisValidity::Invalid(_));
    let basis = if replace {
        let mut mounted = current;
        for (name, namespace) in [("net", "net"), ("pid", "pid")] {
            let source = PathBuf::from(format!("/proc/self/ns/{namespace}"));
            let target = state_paths::basis_ns_bind(name);
            mount_ns(&source, &target)?;
            let exact = ExactNS::from_source(target)?;
            match name {
                "net" => mounted.net = exact,
                "pid" => mounted.pid = exact,
                _ => unreachable!(),
            }
        }
        mounted
    } else {
        current
    };
    Ok(NamespacesRegistry::initialize_basis(basis, replace)?)
}

fn should_log_process(cli: &Cli) -> bool {
    matches!(
        &cli.cmd,
        MainCommand::Enter { .. }
            | MainCommand::Socks5 { .. }
            | MainCommand::Up { cmd: None, .. }
            | MainCommand::Serve { .. }
            | MainCommand::Dbus { .. }
            | MainCommand::Sudo { .. }
            | MainCommand::Basis {
                cmd: BasisCommand::Enter { .. }
            }
            | MainCommand::Daemon { cmd: None }
    )
}

fn log_process_invocation(cli: &Cli) -> Result<()> {
    if !should_log_process(cli) {
        return Ok(());
    }

    let log_path = state_paths::process_log();
    let boot_path = state_paths::process_log_boot();
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let lock_path = boot_path.with_extension("lock");
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    lock.lock_exclusive()?;

    let boot_id = nsproxy_common::current_boot_id()?;
    let previous_boot = fs::read_to_string(&boot_path).ok();
    if previous_boot.as_deref() != Some(boot_id.as_str()) {
        fs::File::create(&log_path)?;
        fs::write(&boot_path, &boot_id)?;
    }

    let netns = ExactNS::from_source((PidPath::Selfproc, "net"))?.unique;
    let entry = serde_json::json!({
        "type": "process_start",
        "pid": std::process::id(),
        "nsid": netns,
        "args": serde_json::to_value(cli)?,
    });
    let mut log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    serde_json::to_writer(&mut log, &entry)?;
    log.write_all(b"\n")?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    // Ignore SIGPIPE so logging to a closed pipe does not kill the daemon.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }

    // Fast path: `sp <fd_num>` — read a bincode-encoded `Cli` directly from the fd.
    // This lets callers (e.g. the GUI) pass structured args without string conversion.
    let mut cli = {
        let raw_args: Vec<String> = std::env::args().collect();
        if raw_args.len() == 2 {
            if let Ok(fd) = raw_args[1].parse::<i32>() {
                nsproxy_core::decode_cli_from_fd(fd)?
            } else {
                Cli::parse()
            }
        } else {
            Cli::parse()
        }
    };
    if let Some(root) = cli.root.clone() {
        state_paths::set_persist_root(root.clone());
        info!("Using state root: {:?}", root);
    }
    diag::set_protocol_version(nsproxy_core::build_identity());
    // DEBUG is annoying because its filled with TCP retransmission logs
    let (layer, reload_handle) = tracing_subscriber::reload::Layer::new(
        fmt::Layer::new()
            .without_time()
            .with_filter(LevelFilter::INFO),
    );
    // https://docs.rs/tracing-subscriber/latest/tracing_subscriber/layer/trait.Layer.html
    tracing_subscriber::registry()
        .with(layer)
        .with(diag::DiagTracingLayer)
        .init();

    log_process_invocation(&cli)?;

    let pid = nix::unistd::Pid::this();

    use rlimit as rl;
    let (soft, hard) = rl::Resource::NOFILE.get()?;
    if !matches!(&cli.cmd, MainCommand::Id { .. }) {
        info!(
            "open file limits, soft={}, hard={}. trying to raise soft limit to max",
            soft, hard
        );
    }
    rl::Resource::NOFILE.set(hard, hard)?;

    match cli.cmd {
        MainCommand::Socks5 { port } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                use socks5_impl::protocol::*;
                use socks5_impl::server::*;
                warn!("starting socks server on 0.0.0.0:{}", port);
                let addr = format!("0.0.0.0:{}", port);
                let server = Server::bind(addr.parse()?, Arc::new(auth::NoAuth)).await?;
                loop {
                    let (conn, _) = server.accept().await?;
                    tokio::spawn(async {
                        if let Err(err) = handle_socks5_connection(conn).await {
                            warn!("socks5 connection error: {}", err);
                        }
                    });
                }

                aok!()
            })?;
        }
        MainCommand::Rm { file } => {
            rm_mount(&file)?;
        }
        MainCommand::Id { pid } => {
            // Keep this command output clean and human-focused.
            let _ = reload_handle.modify(|k| *k.filter_mut() = LevelFilter::WARN);

            let env_value = |key: &str| std::env::var(key).ok().filter(|v| !v.is_empty());
            let fmt_env = |v: Option<String>| v.unwrap_or_else(|| "-".to_string());

            let container = env_value(ENV_CONTAINER);
            let browser = env_value(ENV_PROFILE);
            let netns = env_value(ENV_NS);

            let target_pid = pid;
            let target_ns = if let Some(pid) = target_pid {
                Some(ProfileNamespaces {
                    mnt: ExactNS::from_source((PidPath::N(pid as i32), "mnt"))?,
                    net: ExactNS::from_source((PidPath::N(pid as i32), "net"))?,
                    pid: ExactNS::from_source((PidPath::N(pid as i32), "pid"))?,
                })
            } else {
                None
            };

            let self_ns = ProfileNamespaces {
                mnt: ExactNS::from_source((PidPath::Selfproc, "mnt"))?,
                net: ExactNS::from_source((PidPath::Selfproc, "net"))?,
                pid: ExactNS::from_source((PidPath::Selfproc, "pid"))?,
            };

            let print_divider = |widths: &[usize]| {
                print!("+");
                for &w in widths {
                    print!("{}+", "-".repeat(w + 2));
                }
                println!();
            };

            let status_width = "MISSING".len();

            println!("{}", "NSPROXY ID".bold().bright_cyan());
            println!(
                "{} {}={}  {}={}  {}={}",
                "env".bold().bright_black(),
                "container".bright_blue(),
                fmt_env(container.clone()).bright_white(),
                "browser".bright_blue(),
                fmt_env(browser).bright_white(),
                "netns".bright_blue(),
                fmt_env(netns).bright_white()
            );

            let self_rows = [
                ("mnt", self_ns.mnt.unique.to_string()),
                ("net", self_ns.net.unique.to_string()),
                ("pid", self_ns.pid.unique.to_string()),
            ];
            let self_kind_w = self_rows
                .iter()
                .map(|(k, _)| k.len())
                .max()
                .unwrap_or(4)
                .max("kind".len());
            let self_ns_w = self_rows
                .iter()
                .map(|(_, v)| v.len())
                .max()
                .unwrap_or(4)
                .max("self".len());

            println!();
            println!("{}", "self".bold().bright_magenta());
            let self_widths = [self_kind_w, self_ns_w];
            print_divider(&self_widths);
            println!(
                "| {:<kind_w$} | {:<ns_w$} |",
                "kind".bold(),
                "self".bold(),
                kind_w = self_kind_w,
                ns_w = self_ns_w
            );
            print_divider(&self_widths);
            for (kind, val) in &self_rows {
                println!(
                    "| {:<kind_w$} | {:<ns_w$} |",
                    kind,
                    val,
                    kind_w = self_kind_w,
                    ns_w = self_ns_w
                );
            }
            print_divider(&self_widths);

            if let Some(container_name) = container.as_deref().filter(|c| *c != "UNSPEC") {
                println!();
                println!(
                    "{} {}",
                    "claim".bold().bright_magenta(),
                    format!("profile={}", container_name).bright_white()
                );
                let registry = NamespacesRegistry::load_locked()?;
                let mut claim_rows: Vec<(String, String, String, bool, bool)> = Vec::new();
                if let Some(declared) = registry.profiles.get(container_name) {
                    for (label, declared_ns, self_actual) in [
                        ("mnt", &declared.mnt, &self_ns.mnt),
                        ("net", &declared.net, &self_ns.net),
                        ("pid", &declared.pid, &self_ns.pid),
                    ] {
                        claim_rows.push((
                            label.to_string(),
                            declared_ns.unique.to_string(),
                            self_actual.unique.to_string(),
                            declared_ns.unique == self_actual.unique,
                            false,
                        ));
                    }
                } else {
                    claim_rows.push((
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        false,
                        true,
                    ));
                }

                let claim_kind_w = claim_rows
                    .iter()
                    .map(|r| r.0.len())
                    .max()
                    .unwrap_or(4)
                    .max("kind".len());
                let claim_declared_w = claim_rows
                    .iter()
                    .map(|r| r.1.len())
                    .max()
                    .unwrap_or(8)
                    .max("declared".len());
                let claim_self_w = claim_rows
                    .iter()
                    .map(|r| r.2.len())
                    .max()
                    .unwrap_or(4)
                    .max("self".len());
                let claim_widths = [claim_kind_w, claim_declared_w, claim_self_w, status_width];

                print_divider(&claim_widths);
                println!(
                    "| {:<kind_w$} | {:<decl_w$} | {:<self_w$} | {:<status_w$} |",
                    "kind".bold(),
                    "declared".bold(),
                    "self".bold(),
                    "status".bold(),
                    kind_w = claim_kind_w,
                    decl_w = claim_declared_w,
                    self_w = claim_self_w,
                    status_w = status_width
                );
                print_divider(&claim_widths);
                for (kind, declared_val, self_val, ok, missing) in claim_rows {
                    let status_plain = if missing {
                        "MISSING"
                    } else if ok {
                        "OK"
                    } else {
                        "DIFF"
                    };
                    let status_padded = format!("{:<width$}", status_plain, width = status_width);
                    let status_colored = if missing {
                        format!("{}", status_padded.yellow().bold())
                    } else if ok {
                        format!("{}", status_padded.green().bold())
                    } else {
                        format!("{}", status_padded.red().bold())
                    };
                    println!(
                        "| {:<kind_w$} | {:<decl_w$} | {:<self_w$} | {} |",
                        kind,
                        declared_val,
                        self_val,
                        status_colored,
                        kind_w = claim_kind_w,
                        decl_w = claim_declared_w,
                        self_w = claim_self_w
                    );
                }
                print_divider(&claim_widths);
            }

            if let Some(proc) = target_ns {
                let target_pid =
                    target_pid.expect("pid must exist when proc namespaces were built");
                println!();
                println!(
                    "{} {}",
                    "pid".bold().bright_magenta(),
                    format!("{} vs self", target_pid).bright_white()
                );
                let mut pid_rows: Vec<(String, String, String, bool)> = Vec::new();
                for (label, theirs, ours) in [
                    ("mnt", &proc.mnt, &self_ns.mnt),
                    ("net", &proc.net, &self_ns.net),
                    ("pid", &proc.pid, &self_ns.pid),
                ] {
                    pid_rows.push((
                        label.to_string(),
                        theirs.unique.to_string(),
                        ours.unique.to_string(),
                        theirs.unique == ours.unique,
                    ));
                }

                let pid_kind_w = pid_rows
                    .iter()
                    .map(|r| r.0.len())
                    .max()
                    .unwrap_or(4)
                    .max("kind".len());
                let pid_target_w = pid_rows
                    .iter()
                    .map(|r| r.1.len())
                    .max()
                    .unwrap_or(6)
                    .max("target".len());
                let pid_self_w = pid_rows
                    .iter()
                    .map(|r| r.2.len())
                    .max()
                    .unwrap_or(4)
                    .max("self".len());
                let pid_widths = [pid_kind_w, pid_target_w, pid_self_w, status_width];

                print_divider(&pid_widths);
                println!(
                    "| {:<kind_w$} | {:<target_w$} | {:<self_w$} | {:<status_w$} |",
                    "kind".bold(),
                    "target".bold(),
                    "self".bold(),
                    "status".bold(),
                    kind_w = pid_kind_w,
                    target_w = pid_target_w,
                    self_w = pid_self_w,
                    status_w = status_width
                );
                print_divider(&pid_widths);
                for (kind, target_val, self_val, ok) in pid_rows {
                    let status_plain = if ok { "OK" } else { "DIFF" };
                    let status_padded = format!("{:<width$}", status_plain, width = status_width);
                    let status_colored = if ok {
                        format!("{}", status_padded.green().bold())
                    } else {
                        format!("{}", status_padded.red().bold())
                    };
                    println!(
                        "| {:<kind_w$} | {:<target_w$} | {:<self_w$} | {} |",
                        kind,
                        target_val,
                        self_val,
                        status_colored,
                        kind_w = pid_kind_w,
                        target_w = pid_target_w,
                        self_w = pid_self_w
                    );
                }
                print_divider(&pid_widths);
            }

            let mount_ns = (
                std::fs::metadata("/proc/self/ns/mnt"),
                std::fs::metadata("/proc/1/ns/mnt"),
            );
            println!();
            match mount_ns {
                (Ok(self_mnt), Ok(init_mnt)) => {
                    let isolated =
                        self_mnt.dev() != init_mnt.dev() || self_mnt.ino() != init_mnt.ino();
                    println!(
                        "{} {} {}",
                        "mount_ns".bold().bright_blue(),
                        if isolated {
                            "isolated".green().bold().to_string()
                        } else {
                            "host-shared".red().bold().to_string()
                        },
                        format!("(self_ino={} init_ino={})", self_mnt.ino(), init_mnt.ino())
                            .bright_black(),
                    );
                }
                (Err(e), _) | (_, Err(e)) => {
                    println!(
                        "{} {} {}",
                        "mount_ns".bold().bright_blue(),
                        "unknown".yellow().bold(),
                        format!("({})", e).bright_black()
                    );
                }
            }
            println!();
        }
        MainCommand::Ps { target, kill } => {
            let _ = reload_handle.modify(|k| *k.filter_mut() = LevelFilter::WARN);
            cmd_ps(&target, kill)?;
        }
        MainCommand::Sudo { sargs } => {
            let mut shell_prefs = ShellPrefs::default();
            shell_prefs.take_args(sargs);
            shell_prefs.uid = shell_prefs.uid.or(Some(0));
            shell_prefs.adjust();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;

            rt.block_on(async {
                let rx = shell_prefs.spawn()?;
                rx.wait_for_child().await?;

                aok!()
            })?;
        }
        /// We are just putting state in proc now, basically. Seems cleaner
        MainCommand::Enter { eargs, target } => {
            let mut shell_prefs = ShellPrefs::default();
            shell_prefs.take_enter_args(eargs);
            shell_prefs.adjust();

            if target.eq_ignore_ascii_case("basis") {
                let registry = NamespacesRegistry::load_locked()?;
                let basis = registry.basis_ns.ok_or_else(|| {
                    anyhow!("basis namespace is not recorded; run 'sp init' first")
                })?;
                basis.net.enter(CloneFlags::CLONE_NEWNET)?;
                if let NSSource::Path(path) = &basis.net.source {
                    shell_prefs.set_ns_env(Some(&path.to_string_lossy()));
                }
            } else {
                // Resolve the bind mount path: profile name resolves to /nsp3/{name}/net,
                // otherwise treat as an explicit path if it starts with /, ./, or ~/
                let (resolved_path, nsdata) = {
                    let t = &target;
                    if t.starts_with('/')
                        || t.starts_with("./")
                        || t.starts_with("~/")
                        || t == "~"
                    {
                        let vars = PathExpansionState::without_instance();
                        let p = vars.expand(Path::new(t));
                        (p.clone(), state_paths::metadata_for_bind(&p))
                    } else {
                        let p = state_paths::profile_netns_bind(t);
                        let m = state_paths::profile_ns_meta(t);
                        info!("Resolved profile name {:?} to {:?}", t, &p);
                        (p, m)
                    }
                };

                let ns_alive = read_ns_alive(&nsdata)?;
                let profile = ns_alive.profile_name.as_deref().unwrap_or(target.as_str());
                let sandbox_status = read_sandbox_status(profile).ok_or_else(|| {
                    anyhow!(
                        "no valid sandbox status for '{}' — run 'sp sandbox {}' first",
                        profile,
                        profile
                    )
                })?;
                enter_ns_sandboxed(&ns_alive, &sandbox_status, &resolved_path)?;
                apply_ns_env(&mut shell_prefs, &ns_alive);
                apply_dbus_env(&mut shell_prefs, &ns_alive);
            }

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;

            rt.block_on(async {
                let rx = shell_prefs.spawn()?;
                rx.wait_for_child().await?;

                aok!()
            })?;
        }
        MainCommand::Install { dir: dstdir } => {
            if !dstdir.exists() {
                bail!(
                    "target directory {:?} does not exist. you have to create it manually",
                    &dstdir
                )
            }
            let dstdir_abs = dstdir.canonicalize()?;
            let selfprog = std::env::current_exe()?;
            let mut sproxyf = selfprog.clone();
            let overwrite = |src: &Path, path: &Path| {
                warn!("installing {:?} to {:?}", src, path);
                if path.exists() {
                    std::fs::remove_file(path)?;
                }
                std::fs::copy(src, path)?;
                aok!()
            };
            let selfprogdst = dstdir.join(selfprog.file_name().unwrap());
            overwrite(&selfprog, &selfprogdst)?;
            let ui_src = selfprog
                .parent()
                .ok_or_else(|| anyhow!("installed executable has no parent directory"))?
                .join("nsproxy-ui");
            let ui_dst = dstdir.join("nsproxy-ui");
            overwrite(&ui_src, &ui_dst)?;
            sproxyf.set_file_name("sproxy");

            let fd = dstdir.join(sproxyf.file_name().unwrap());
            overwrite(&sproxyf, &fd)?;
            let f = std::fs::File::open(&fd)?;
            let perms = Permissions::from_mode(0o6755);
            f.set_permissions(perms)?;
            let meta = f.metadata()?;
            warn!(
                "{fd:?}, uid={:?}, gid={}, suid={}",
                meta.uid(),
                meta.gid(),
                meta.permissions().mode() & 0o4000 != 0
            );
            let short_path = dstdir_abs.join("sp");
            let fd_abs = fd.canonicalize()?;
            warn!("Installing symlink {:?} -> {:?}", &short_path, &fd_abs);
            symlink(&fd_abs, &short_path);
            let short_path_unpriv = dstdir_abs.join("nsp");
            let selfprogdst_abs = selfprogdst.canonicalize()?;
            warn!(
                "Installing symlink {:?} -> {:?}",
                &short_path_unpriv, &selfprogdst_abs
            );
            symlink(&selfprogdst_abs, &short_path_unpriv);

            sproxyf.set_file_name("nswrap");
            let fd = dstdir.join(sproxyf.file_name().unwrap());
            overwrite(&sproxyf, &fd)?;
        }
        MainCommand::Completions { fish } => {
            if fish {
                if let Some(home) = std::env::var_os("HOME") {
                    let dir = PathBuf::from(home)
                        .join(".config")
                        .join("fish")
                        .join("completions");
                    std::fs::create_dir_all(&dir)?;

                    for bin_name in ["sp", "nsp", "nsproxy"] {
                        let mut cmd = Cli::command();
                        let mut buf = Vec::new();
                        generate(Fish, &mut cmd, bin_name, &mut buf);
                        let path = dir.join(format!("{}.fish", bin_name));
                        info!(
                            "Installing fish completion for '{}' at {:?}",
                            bin_name, path
                        );
                        std::fs::write(&path, &buf)?;
                    }
                } else {
                    warn!("HOME is not set; skipping fish completion install");
                }
            } else {
                warn!("No completion target specified; use --fish");
            }
        }
        MainCommand::Clean { veth } => {
            if veth {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;

                rt.block_on(async {
                    let cmd = tokio_netlink_conn()?;
                    info!("trying to remove v_out if it exists");
                    let default_v = cmd.fetch_link_by_name("v_out".to_owned()).await?;
                    cmd.link().del(default_v.header.index).execute().await?;
                    warn!("v_out removed");
                    aok!(())
                })?;
            }
        }
        MainCommand::Gen { save_to } => {
            let conf = HotConfig::default();
            let json = serde_json::to_string_pretty(&conf)?;

            std::fs::write(&save_to, json)?;
        }
        MainCommand::Init { force } => {
            let init = initialize_basis_namespace(force)?;
            if init.initialized {
                println!("basis namespace recorded");
            } else {
                println!("basis namespace already recorded");
            }
        }
        MainCommand::Netlink => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;

            rt.block_on(async {
                let nl = tokio_netlink_conn()?;
                let addrs = nl.fetch_all_ip_addrs().await?;
                for a in addrs {
                    println!("{}", a);
                }
                Ok::<(), anyhow::Error>(())
            })?;
        }
        MainCommand::Curl { url, proxy } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;

            rt.block_on(async {
                let client = if let Some(proxy_addr) = proxy {
                    let proxy_url = format!("socks5h://{}", proxy_addr);
                    info!("using proxy: {}", proxy_url);
                    reqwest::Client::builder()
                        .proxy(reqwest::Proxy::all(proxy_url)?)
                        .build()?
                } else {
                    reqwest::Client::builder()
                        .redirect(Policy::default())
                        .build()?
                };

                info!("requesting: {}", url);
                match client.get(url).send().await {
                    Ok(response) => {
                        println!("Status: {}", response.status());
                        match response.text().await {
                            Ok(body) => println!("{}", body),
                            Err(e) => warn!("failed to read response body: {}", e),
                        }
                    }
                    Err(e) => warn!("request failed: {:?}", e),
                }
                Ok::<(), anyhow::Error>(())
            })?;
        }
        MainCommand::Forward { src, dst } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;

            if dst == src {
                bail!("src==dst dead loop");
            }

            rt.block_on(async {
                let list = format!("0.0.0.0:{}", src);
                let listener = tokio::net::TcpListener::bind(&list).await?;
                info!("tcp forward listening on {}", &list);

                loop {
                    let (mut client, _) = listener.accept().await?;
                    let dst_addr = format!("127.0.0.1:{}", dst);

                    tokio::spawn(async move {
                        match tokio::net::TcpStream::connect(&dst_addr).await {
                            Ok(mut server) => {
                                info!("forwarded connection to {}", dst_addr);
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

                aok!()
            })?;
        }
        MainCommand::Template {
            path,
            name,
            reset,
            update,
        } => {
            if reset && update {
                bail!("Cannot use --reset and --update together");
            }

            info!("Profile Creation");
            info!("Creating profile instance with isolated state directory");
            info!("Each profile can only be instantiated once (e.g., for VS Code isolation)");
            info!("");

            // Derive name from config file stem if not provided
            let clean_name = if let Some(ref name) = name {
                // Sanitize provided name: extract filename, remove .json extension
                let name_path = PathBuf::from(name);
                name_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(name)
                    .to_string()
            } else {
                // Derive from config path
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| anyhow!("cannot derive profile name from path: {:?}", path))?
                    .to_string()
            };

            info!("Profile name: {}", clean_name);
            info!("Template config: {:?}", path);

            // Create target config directory at /nsp3/config/{clean_name}
            let profile_config_dir = state_paths::profile_dir(&clean_name);
            let rootfs_dir = state_paths::profile_rootfs_dir(&clean_name);
            info!("Target config directory: {:?}", profile_config_dir);

            let profile_path = profile_config_dir.join("profile.json");
            let hot_path = profile_config_dir.join("hot.json");

            if update {
                // Update mode: check that profile exists
                if !profile_path.exists() {
                    bail!(
                        "profile does not exist at {:?}. Use without --update to create.",
                        profile_path
                    );
                }

                info!("Update mode - updating existing profile...");

                // Load the new template
                info!("Loading new template from {:?}...", path);
                let mut profile = TemplateConfig::load(&path)?;
                info!("Template loaded successfully");

                // Expand @ placeholders
                info!("Expanding @ placeholders to: {:?}", profile_config_dir);
                profile.expand_placeholders(&profile_config_dir);

                // Wellness checks
                info!("Running wellness checks...");

                // Check if mount sources exist
                let mut missing_sources = Vec::new();
                let mut existing_sources = Vec::new();
                for m in &profile.mounts {
                    if !m.source.exists() {
                        missing_sources.push(&m.source);
                    } else {
                        existing_sources.push(&m.source);
                    }
                }

                if !missing_sources.is_empty() {
                    warn!("Missing mount sources:");
                    for src in &missing_sources {
                        warn!("  ✗ {:?}", src);
                    }
                    bail!("Some mount sources do not exist. Create them manually or use --reset.");
                }

                info!("All mount sources available:");
                for src in &existing_sources {
                    info!("  ✓ {:?}", src);
                }

                // Check hot config
                if hot_path.exists() {
                    info!("✓ Hot config exists: {:?}", hot_path);
                } else {
                    warn!("Hot config does not exist at {:?}", hot_path);
                }

                // Check cwd if specified
                if let Some(ref cwd) = profile.sargs.cwd {
                    if cwd.exists() {
                        info!("✓ Working directory exists: {:?}", cwd);
                    } else {
                        warn!("Working directory does not exist: {:?}", cwd);
                    }
                }

                // Update profile config (overwrite profile.json, keep hot.json)
                info!("Updating profile configuration...");
                let mut new_profile = profile.clone();
                new_profile.hot = hot_path;

                let profile_json = serde_json::to_string_pretty(&new_profile)?;
                std::fs::write(&profile_path, profile_json)?;

                info!("");
                info!("✓ Profile updated successfully");
                info!("Config: {:?}", profile_path);
                info!("Hot config: {:?} (unchanged)", new_profile.hot);
                info!("");
                info!("Note: Existing directories and files were not modified");
            } else {
                // Create mode (original logic)

                // If reset flag is set, remove the entire directory first
                if reset && (profile_config_dir.exists() || rootfs_dir.exists()) {
                    // TODO: this profile reset path should reuse `sp down`
                    warn!("Reset flag enabled - removing existing profile state");

                    // Remove namespace bind mount if it exists
                    let ns_bind = state_paths::profile_netns_bind(&clean_name);
                    if ns_bind.exists() {
                        warn!("Removing namespace bind mount at {:?}", &ns_bind);
                        if let Err(e) = rm_mount(&ns_bind) {
                            warn!("Failed to unmount {:?}: {:?}", &ns_bind, e);
                        }
                    }
                    // Remove sidecar metadata JSON
                    let ns_meta = state_paths::profile_ns_meta(&clean_name);
                    if ns_meta.exists() {
                        std::fs::remove_file(&ns_meta)?;
                    }

                    if profile_config_dir.exists() {
                        std::fs::remove_dir_all(&profile_config_dir)?;
                        info!("Removed existing config directory");
                    }
                }

                info!("Creating profile directory structure...");
                std::fs::create_dir_all(&profile_config_dir)?;

                if profile_path.exists() && !reset {
                    bail!(
                        "profile config already exists: {:?}. Use --reset to recreate from scratch or --update to update config.",
                        profile_path
                    );
                }

                // Load the profile template from provided path
                info!("Loading profile template from {:?}...", path);
                let mut profile = TemplateConfig::load(&path)?;
                info!("Template loaded successfully");

                // Expand @ placeholders for directory creation
                info!("Expanding @ placeholders to: {:?}", profile_config_dir);
                profile.expand_placeholders(&profile_config_dir);

                // Create all referenced directories
                if let Some(ref cwd) = profile.sargs.cwd {
                    if !cwd.exists() {
                        info!("Creating working directory: {:?}", cwd);
                        std::fs::create_dir_all(cwd)?;
                        warn!("Created cwd: {:?}", cwd);
                    }
                }

                create_profile_mount_sources(&profile)?;

                // Copy hot config if it exists, otherwise create from hot_init or default
                info!("Setting up hot config...");
                if profile.hot.exists() && profile.hot != hot_path {
                    info!("Copying hot config from {:?}", profile.hot);
                    std::fs::copy(&profile.hot, &hot_path)?;
                    warn!("Copied hot config: {:?} -> {:?}", profile.hot, hot_path);
                } else if !hot_path.exists() {
                    info!("Creating hot config from profile.hot_init");
                    let hot = profile.hot_init.clone().unwrap_or_default();
                    hot.save(&hot_path)?;
                    warn!("Created hot config: {:?}", hot_path);
                }

                // Update profile to point to new hot config location
                info!("Writing profile configuration...");
                let mut new_profile = profile.clone();
                new_profile.hot = hot_path;

                let profile_json = serde_json::to_string_pretty(&new_profile)?;
                std::fs::write(&profile_path, profile_json)?;

                info!("");
                info!("✓ Profile created successfully");
                info!("Location: {:?}", profile_config_dir);
                info!("Config: {:?}", profile_path);
                info!("Hot config: {:?}", new_profile.hot);
            }
        }
        MainCommand::Clone { name, from } => {
            let clean_name = {
                let name_path = PathBuf::from(&name);
                name_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&name)
                    .to_string()
            };

            if clean_name.contains('/') {
                bail!("new profile name must not contain '/'");
            }
            if from.contains('/') {
                bail!("source profile name must not contain '/'");
            }
            if clean_name == from {
                bail!("new profile name must differ from source profile name");
            }

            let source_profile_path = state_paths::profile_config(&from);
            if !source_profile_path.exists() {
                bail!("source profile does not exist at {:?}", source_profile_path);
            }

            let target_dir = state_paths::profile_dir(&clean_name);
            if target_dir.exists() {
                bail!("target profile directory already exists: {:?}", target_dir);
            }

            let target_profile_path = state_paths::profile_config(&clean_name);
            let target_hot_path = state_paths::hot_config(&clean_name);
            let source_hot_path = state_paths::hot_config(&from);

            info!("Cloning profile '{}' -> '{}'", from, clean_name);
            std::fs::create_dir_all(&target_dir)?;

            let mut profile = TemplateConfig::load(&source_profile_path)?;
            let hot = load_hot_config_from_disk_or_default(&source_hot_path);

            hot.save(&target_hot_path)?;
            profile.hot = PathBuf::from("@/hot.json");
            profile.hot_init = Some(hot);

            let profile_json = serde_json::to_string_pretty(&profile)?;
            std::fs::write(&target_profile_path, profile_json)?;

            info!("✓ Profile cloned successfully");
            info!("Source: {:?}", source_profile_path);
            info!("Config: {:?}", target_profile_path);
            info!("Hot config: {:?}", target_hot_path);
        }
        MainCommand::Up {
            profile,
            cmd,
            simulate_protocol_no_upgrade,
            simulate_conn_close,
            simulate_slow_shutdown,
        } => {
            // Show build identity and human-readable build time early for diagnostics.
            let build_hash = nsproxy_core::build_tree_hash();
            let build_epoch = nsproxy_core::build_epoch_secs();
            let human_time = chrono::NaiveDateTime::from_timestamp_opt(build_epoch as i64, 0)
                .map(|dt: chrono::NaiveDateTime| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "unknown".to_string());
            warn!(
                profile = profile.as_str(),
                "sp up starting: build_hash={} build_time={} (epoch={})",
                build_hash,
                human_time,
                build_epoch
            );
            let profile_path = state_paths::profile_config(&profile);
            if !profile_path.exists() {
                bail!(
                    "profile config does not exist: {:?}. Use 'profile' subcommand to create it.",
                    profile_path
                );
            }
            let profile_conf = TemplateConfig::load(&profile_path)?;

            // If a CLI-specified daemon request was provided, translate and
            // send it to the already-running `up` daemon for this profile.
            if let Some(cli_req) = cmd {
                // Translate CLI request into `diag::DaemonRequest`.
                let req = match cli_req {
                    CliDaemonRequest::GetProcessList => diag::DaemonRequest::GetProcessList,
                    CliDaemonRequest::Ping => diag::DaemonRequest::Ping,
                    CliDaemonRequest::EnsureDbus => diag::DaemonRequest::EnsureDbus,
                    CliDaemonRequest::Kill { task_pgid } => diag::DaemonRequest::Kill { task_pgid },
                    CliDaemonRequest::Stop => diag::DaemonRequest::Stop,
                    CliDaemonRequest::Spawn { args } => {
                        let dra = diag::SpawnArgs {
                            uid: args.uid,
                            gid: args.gid,
                            exec: args.exec,
                            cwd: args.cwd,
                            gids: args.gids,
                            args: args.args,
                            ringbuf_size: None,
                            application: None,
                            ns: args.ns,
                        };
                        diag::DaemonRequest::Spawn { args: dra }
                    }
                    CliDaemonRequest::SpawnCli { cli_json, ns } => {
                        // Parse provided JSON into `Cli` and bincode-serialize it.
                        let cli_struct: Cli = serde_json::from_str(&cli_json)
                            .map_err(|e| anyhow!("failed to parse cli JSON: {}", e))?;
                        let b = bincode::serialize(&cli_struct)?;
                        diag::DaemonRequest::SpawnCli { cli_bincode: b, ns }
                    }
                };

                // Send over the profile's up.sock and print a single response if any.
                let sock_path = diag::up_sock_path(&profile);
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                rt.block_on(async {
                    let mut stream = diag::connect_up_daemon(&sock_path).await?;
                    stream.send_unstable_request(&req).await?;
                    if let Some(evt) = stream.next_event().await? {
                        println!("{:?}", evt);
                    }
                    Ok::<(), anyhow::Error>(())
                })?;
                return Ok(());
            }

            let bind_mount = state_paths::profile_netns_bind(&profile);
            if let Some(parent) = bind_mount.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let ns_meta = state_paths::profile_ns_meta(&profile);
            let mut upkeeper_pid: Option<u32> = None;
            let mut existing_up_daemon_pid: Option<u32> = None;
            if ns_meta.exists() {
                info!("Reading NS metadata from {:?}", &ns_meta);
                warn!(
                    profile = profile.as_str(),
                    ns_meta = %ns_meta.display(),
                    "up preflight: ns metadata present; evaluating existing daemon state"
                );
                if let Some(ns_alive) = read_ns_alive_opt(&ns_meta) {
                    warn!(
                        profile = profile.as_str(),
                        up_pid = ?ns_alive.up_pid,
                        child_pid = ?ns_alive.child_pid,
                        "up preflight: loaded NsAlive metadata"
                    );
                    let alive_child = ns_alive.child_pid.filter(|pid| pid_is_alive(*pid));

                    warn!(
                        profile = profile.as_str(),
                        alive_child = ?alive_child,
                        "up preflight: probed live child pid"
                    );

                    if let Some(target_pid) = alive_child {
                        upkeeper_pid = Some(target_pid);
                        existing_up_daemon_pid = ns_alive.up_pid.filter(|pid| pid_is_alive(*pid));
                        warn!(
                            profile = profile.as_str(),
                            target_pid,
                            "up preflight: existing namespace detected; will use clone3 no-newns replacement path"
                        );
                    }
                }
            }

            let clone = if upkeeper_pid.is_some() {
                warn!(
                    profile = profile.as_str(),
                    target_pid = ?upkeeper_pid,
                    "up startup: using clone3 without new namespaces; child will enter existing namespaces"
                );
                nsproxy_core::sys::clone3::<false>(false, false)
            } else {
                // Fresh profile start: create new mount/net namespaces.
                nsproxy_core::sys::clone3::<true>(true, true)
            };
            match clone {
                Ok(clone) => match clone {
                    Clone3Result::IsChild { mut tx } => {
                        if let Some(target_pid) = upkeeper_pid {
                            warn!(
                                profile = profile.as_str(),
                                target_pid, "up child: entering existing namespaces"
                            );
                            enter_all_profile_namespaces_of_pid(target_pid)?;
                        }

                        // Signal to parent that child namespace context is ready to inspect.
                        tx.write(&[1])?;

                        let mut buf = [0; 1];
                        enable_ping_all()?;
                        tx.read(&mut buf)?; // wait for bind mount

                        if upkeeper_pid.is_none() {
                            // always done when there is new mount namespace
                            mount_bind_root()?;
                            // mounting DNS related things is also basic to either overlay or pivot sandbox
                            mount_resolv_conf("100.68.0.2")?;
                            mount_nsswitch_conf()?;
                        } else {
                            warn!(
                                profile = profile.as_str(),
                                "up child: reusing existing namespace mounts; skip fresh namespace bootstrap mounts"
                            );
                        }

                        loop {
                            std::thread::park();
                        }
                    }
                    Clone3Result::Parent {
                        child_pid, mut tx, ..
                    } => {
                        let mut ready = [0; 1];
                        tx.read(&mut ready)?;

                        let parent_mnt = ExactNS::from_source((PidPath::Selfproc, "mnt"))?;
                        let parent_net = ExactNS::from_source((PidPath::Selfproc, "net"))?;
                        let parent_pid = ExactNS::from_source((PidPath::Selfproc, "pid"))?;
                        let child_mnt = ExactNS::from_source((PidPath::N(child_pid), "mnt"))?;
                        let child_net = ExactNS::from_source((PidPath::N(child_pid), "net"))?;
                        let child_pid_ns = ExactNS::from_source((PidPath::N(child_pid), "pid"))?;
                        info!(
                            "ns indicator parent[mnt={},net={},pid={}] child[mnt={},net={},pid={}]",
                            parent_mnt.unique,
                            parent_net.unique,
                            parent_pid.unique,
                            child_mnt.unique,
                            child_net.unique,
                            child_pid_ns.unique,
                        );

                        if let Some(parent) = bind_mount.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        let path = format!("/proc/{}/ns/net", child_pid);
                        let path = PathBuf::from(path);
                        mount_ns(&path, &bind_mount)?;
                        let bind_net = ExactNS::from_source(bind_mount.clone())?;
                        info!(
                            "up ns indicator bind_mount[mnt_path={:?},net={}]",
                            bind_mount, bind_net.unique
                        );

                        NamespacesRegistry::update_locked(|registry| {
                            registry.profiles.insert(
                                profile.clone(),
                                ProfileNamespaces {
                                    mnt: child_mnt.clone(),
                                    net: child_net.clone(),
                                    pid: child_pid_ns.clone(),
                                },
                            );
                            Ok(())
                        })?;

                        info!("Updating NS metadata at {:?}", &ns_meta);
                        let up_pid = std::process::id();
                        update_ns_alive(&ns_meta, |ns_alive| {
                            ns_alive.profile_name = Some(profile.clone());
                            ns_alive.browser_profile = profile_conf.browser_profile.clone();
                            ns_alive.bind_mount = bind_mount.clone();
                            ns_alive.child_pid = Some(child_pid as u32);
                            ns_alive.up_pid = Some(up_pid);
                            if upkeeper_pid.is_none() {
                                ns_alive.rootfs = None;
                            }
                        })?;
                        warn!("Auxiliary data written to {:?}", &ns_meta);

                        if let Some(old_up_pid) =
                            existing_up_daemon_pid.filter(|pid| pid_is_alive(*pid))
                        {
                            warn!(
                                profile = profile.as_str(),
                                old_up_pid,
                                "up replacement: new child keeper is ready; requesting graceful shutdown of old up daemon"
                            );
                            let sock_path = diag::up_sock_path(&profile);
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()?;
                            rt.block_on(async {
                                let mut stream = diag::connect_up_daemon_stable(&sock_path).await?;
                                stream.send_stable_request(&diag::StableRequest::GracefulShutdown).await?;
                                match tokio::time::timeout(Duration::from_secs(5), stream.next_event()).await {
                                    Ok(Ok(Some(diag::UpWireEvent::Stable(diag::StableEvent::ShuttingDown))))
                                    | Ok(Ok(Some(diag::UpWireEvent::Unstable(diag::DaemonEvent::Stopping))))
                                    | Ok(Ok(None)) => Ok::<(), anyhow::Error>(()),
                                    Ok(Ok(Some(diag::UpWireEvent::Stable(diag::StableEvent::Error { msg })))) => {
                                        bail!("old up daemon returned error on graceful shutdown: {}", msg)
                                    }
                                    Ok(Ok(Some(diag::UpWireEvent::Unstable(diag::DaemonEvent::Error { msg })))) => {
                                        bail!("old up daemon returned error on graceful shutdown: {}", msg)
                                    }
                                    Ok(Ok(Some(other))) => {
                                        bail!("unexpected response from old up daemon: {:?}", other)
                                    }
                                    Ok(Err(e)) => Err(e.into()),
                                    Err(_) => bail!(
                                        "timed out waiting for graceful-shutdown acknowledgement from old up daemon"
                                    ),
                                }
                            })?;
                            warn!(
                                profile = profile.as_str(),
                                old_up_pid, "up replacement: old up daemon shutdown acknowledged"
                            );
                        }

                        tx.write(&[0])?;

                        if profile_conf.sandbox_mode == SandboxMode::Pivot {
                            let sandbox_status_path = state_paths::sandbox_status(&profile);
                            // read_sandbox_status purges stale (previous-boot) state automatically.
                            let prior_state = nsproxy_core::sandbox::read_sandbox_status_for_mnt(
                                profile.as_str(),
                                &child_mnt.unique,
                            )
                            .map(|s| s.detected_state);
                            match prior_state {
                                Some(nsproxy_core::sandbox::SandboxState::Pivoted) => {
                                    warn!(
                                        profile = profile.as_str(),
                                        sandbox_status = %sandbox_status_path.display(),
                                        "sandbox already pivoted (prior run applied pivot_root); \
                                         processes spawned into this container see the sandbox rootfs, not the host."
                                    );
                                }
                                Some(nsproxy_core::sandbox::SandboxState::NoPivot) => {
                                    warn!(
                                        profile = profile.as_str(),
                                        sandbox_status = %sandbox_status_path.display(),
                                        "UNPIVOTED: sandbox_status.json records NoPivot. \
                                         Any process spawned into this container before 'sp sandbox' applies \
                                         pivot_root will operate on the HOST filesystem and may overwrite host files."
                                    );
                                }
                                None => {
                                    warn!(
                                        profile = profile.as_str(),
                                        sandbox_status = %sandbox_status_path.display(),
                                        "UNPIVOTED: no sandbox_status.json found; 'sp sandbox' has never run. \
                                         Any process spawned into this container before 'sp sandbox' applies \
                                         pivot_root will operate on the HOST filesystem and may overwrite host files."
                                    );
                                }
                            }
                        } else if profile_conf.sandbox_mode == SandboxMode::Overlay {
                            // Overlay containers do not go through `sp sandbox`, so
                            // sandbox_status.json is never written by that path.  Write it
                            // here during `sp up` so that the daemon can spawn processes
                            // (sp serve, sp dbus, PTYs, etc.) which all require the file.
                            let sandbox_status = collect_sandbox_status(
                                SandboxMode::Overlay,
                                nsproxy_core::sandbox::SandboxState::NoPivot,
                                &[],
                                None,
                            )?;
                            write_sandbox_status(&profile, &sandbox_status)?;
                            info!(
                                profile = profile.as_str(),
                                "wrote sandbox_status.json for overlay container"
                            );
                        }

                        reconcile_configured_veths(&profile);

                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?;
                        rt.block_on(run_up_daemon(
                            &profile,
                            ns_meta,
                            child_pid as u32,
                            cli.control_socket.clone(),
                            simulate_protocol_no_upgrade,
                            simulate_conn_close,
                            simulate_slow_shutdown,
                        ))?;
                        exit_with_warn(
                            0,
                            "up replacement child exiting after run_up_daemon returned",
                        );
                    }
                },
                Err(er) => report_clone3_err(&er)?,
            }
        }
        MainCommand::Down { profile, rm } => {
            let ns_meta = state_paths::profile_ns_meta(&profile);
            let bind_mount = state_paths::profile_netns_bind(&profile);
            let profile_dir = state_paths::profile_dir(&profile);
            let sandbox_root = configured_sandbox_root(&profile);
            let mut sandbox_mounts_removed = sandbox_root.as_ref().map_or(true, |r| !r.exists());

            // Kill the keeper process if we know its PID.
            if ns_meta.exists() {
                if let Ok(content) = std::fs::read_to_string(&ns_meta) {
                    if let Ok(ns_alive) = serde_json::from_str::<nsproxy_core::NsAlive>(&content) {
                        if rm {
                            if let Some(ref root) = sandbox_root {
                                match cleanup_sandbox_mounts(&ns_alive, root) {
                                    Ok(()) => {
                                        sandbox_mounts_removed = true;
                                    }
                                    Err(err) => {
                                        warn!(
                                            "failed to detach sandbox-owned mounts for {:?}: {}",
                                            profile, err
                                        );
                                    }
                                }
                            }
                        }
                        if ns_alive.up_pid.filter(|pid| pid_is_alive(*pid)).is_some() {
                            request_graceful_up_shutdown(&profile);
                        }
                        if let Some(pid) = ns_alive.child_pid {
                            let proc_path = PathBuf::from("/proc").join(pid.to_string());
                            if proc_path.exists() {
                                warn!("killing keeper process pid={}", pid);
                                if !kill_and_wait_for_exit(pid, Duration::from_secs(5)) {
                                    warn!("keeper pid {} did not exit within 5 seconds", pid);
                                }
                            } else {
                                info!("keeper process pid={} is already gone", pid);
                            }
                        }
                    }
                }
                std::fs::remove_file(&ns_meta)?;
                info!("removed NS metadata {:?}", ns_meta);
            } else {
                warn!("no NS metadata found at {:?}", ns_meta);
            }

            NamespacesRegistry::update_locked(|registry| {
                registry.profiles.remove(&profile);
                Ok(())
            })?;

            if rm {
                // Unmount and remove the bind-mount file.
                let mut bind_mount_removed = !bind_mount.exists();
                if bind_mount.exists() {
                    if let Err(e) = rm_mount(&bind_mount) {
                        warn!("failed to remove bind mount {:?}: {:?}", bind_mount, e);
                    } else {
                        info!("removed bind mount {:?}", bind_mount);
                        bind_mount_removed = true;
                    }
                } else {
                    warn!(
                        "bind mount {:?} does not exist, nothing to unmount",
                        bind_mount
                    );
                }

                if bind_mount_removed && sandbox_mounts_removed {
                    if let Some(ref sandbox_root) = sandbox_root {
                        if sandbox_root.exists() {
                            std::fs::remove_dir_all(sandbox_root)?;
                            info!("removed profile rootfs directory {:?}", sandbox_root);
                        } else {
                            warn!("profile rootfs directory {:?} does not exist", sandbox_root);
                        }
                    }
                    if profile_dir.exists() {
                        std::fs::remove_dir_all(&profile_dir)?;
                        info!("removed profile config directory {:?}", profile_dir);
                    } else {
                        warn!("profile config directory {:?} does not exist", profile_dir);
                    }
                } else {
                    warn!(
                        "skipping profile state removal for config {:?} and rootfs {:?} because mount cleanup failed (bind_mount_removed={}, sandbox_mounts_removed={})",
                        profile_dir, sandbox_root, bind_mount_removed, sandbox_mounts_removed
                    );
                }
            }

            warn!("profile '{}' is down", profile);
        }
        MainCommand::Serve {
            profile,
            tun_name,
            simple,
            no_default,
            log,
            clash,
            no_dns_capture,
            internal_dns_server,
        } => cmd_serve(
            profile,
            tun_name,
            simple,
            no_default,
            log,
            clash,
            no_dns_capture,
            cli.control_socket.clone(),
            &mut |level| {
                reload_handle.modify(|k| *k.filter_mut() = level)?;
                Ok(())
            },
            internal_dns_server,
        )?,
        MainCommand::Dbus { profile } => {
            let profile_path = state_paths::profile_config(&profile);
            if !profile_path.exists() {
                bail!(
                    "profile config does not exist: {:?}. Use 'profile' subcommand to create it.",
                    profile_path
                );
            }

            let profile_conf = TemplateConfig::load(&profile_path)?;
            ensure!(
                profile_conf.dbus == nsproxy_core::DbusMode::Container,
                "profile '{}' dbus mode is not 'container' in TemplateConfig",
                profile
            );

            let ns_meta = state_paths::profile_ns_meta(&profile);
            let ns_alive = read_ns_alive(&ns_meta)?;
            let bind_mount = state_paths::profile_netns_bind(&profile);

            // Load registry *before* entering ns so path access is still on host.
            let registry = NamespacesRegistry::load_locked()?;
            let profile_namespaces = registry.profiles.get(&profile).ok_or_else(|| {
                anyhow!("profile namespace registry entry missing for {}", profile)
            })?;

            let sandbox_status = read_sandbox_status(&profile).ok_or_else(|| {
                anyhow!(
                    "no valid sandbox status for '{}' — run 'sp sandbox {}' first",
                    profile,
                    profile
                )
            })?;
            enter_ns_sandboxed(&ns_alive, &sandbox_status, &bind_mount)?;

            // Refuse to run if we are not in the expected mount namespace.
            // This prevents any fs ops from touching the host tree.
            assert_mount_ns_matches(&profile_namespaces.mnt)?;

            let session_socket = profile_bus_socket(&profile);
            let system_socket = profile_system_bus_socket(&profile);

            let session_ready = session_bus_ready(&session_socket);
            let system_ready = session_bus_ready(&system_socket);

            // Idempotent: if both healthy buses are already listening, nothing to do.
            if session_ready && system_ready {
                info!(
                    session = %session_socket.display(),
                    system = %system_socket.display(),
                    "private session and system dbus buses already running"
                );
                return Ok(());
            }

            if !session_ready && session_socket.exists() {
                fs::remove_file(&session_socket)?;
            }
            if !system_ready && system_socket.exists() {
                fs::remove_file(&system_socket)?;
            }

            let mut joins = Vec::new();
            if !session_ready {
                let socket_path = session_socket.clone();
                joins.push(std::thread::spawn(move || {
                    info!("starting private dbus-daemon session bus");
                    run_container_dbus_daemon(&socket_path, false)
                }));
            }
            if !system_ready {
                let socket_path = system_socket.clone();
                joins.push(std::thread::spawn(move || {
                    info!("starting private dbus-daemon system bus");
                    run_container_dbus_daemon(&socket_path, true)
                }));
            }

            for join in joins {
                join.join()
                    .map_err(|_| anyhow!("dbus daemon thread panicked"))??;
            }
        }
        MainCommand::Veth { src, dst, veth_name, src_ip4, dst_ip4, prefix_len, log } => {
            if let Some(log) = log {
                reload_handle.modify(|k| *k.filter_mut() = log)?;
            }
            create_veth_pair(src, dst, veth_name, src_ip4, dst_ip4, prefix_len)?;
        }
        MainCommand::Basis { cmd } => match cmd {
            BasisCommand::Mount {} => {
                let source = PathBuf::from("/proc/self/ns/net");
                let bind_mount = state_paths::profile_netns_bind("basis");
                if let Some(parent) = bind_mount.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                mount_ns(&source, &bind_mount)?;
                info!("Basis netns mounted at {:?}", bind_mount);
            }
            BasisCommand::Enter { sargs } => {
                let mut shell_prefs = ShellPrefs::default();
                shell_prefs.take_args(sargs);
                shell_prefs.adjust();

                let registry = NamespacesRegistry::load_locked()?;
                let basis = registry.basis_ns.ok_or_else(|| {
                    anyhow!("basis namespace is not recorded; run 'sp init' first")
                })?;
                basis.net.enter(CloneFlags::CLONE_NEWNET)?;
                if let NSSource::Path(path) = &basis.net.source {
                    shell_prefs.set_ns_env(Some(&path.to_string_lossy()));
                }

                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;

                rt.block_on(async {
                    let rx = shell_prefs.spawn()?;
                    rx.wait_for_child().await?;

                    aok!()
                })?;
            }
        },
        MainCommand::StateTree => {
            let tree = nsproxy_core::state_blueprint::global_state_tree();
            println!("{}", tree.render_tree());
        }
        MainCommand::Version => {
            println!("hash={}", nsproxy_core::build_tree_hash());
            println!("epoch={}", nsproxy_core::build_epoch_secs());
        }
        MainCommand::Uplink { kind } => cmd_uplink(kind)?,
        MainCommand::Sandbox { profile } => {
            // Pivot-root sandbox: enter an existing namespace,
            check_capsys()?;

            let profile_path = state_paths::profile_config(&profile);
            if !profile_path.exists() {
                bail!(
                    "profile config does not exist: {:?}. Use 'profile' subcommand to create it.",
                    profile_path
                );
            }
            let mut profile_conf = TemplateConfig::load(&profile_path)?;
            let instance_root = state_paths::profile_dir(&profile);
            profile_conf.expand_placeholders(&instance_root);

            // The UI's older create path wrote profile.json without the CLI
            // profile-create initialization step. Reconcile the declared source
            // tree here too, before entering the profile mount namespace.
            create_profile_mount_sources(&profile_conf)?;

            let ns_meta = state_paths::profile_ns_meta(&profile);
            let ns_alive = read_ns_alive(&ns_meta)?;
            let bind_mount = state_paths::profile_netns_bind(&profile);
            let registry = NamespacesRegistry::load_locked()?;
            let profile_namespaces = registry.profiles.get(&profile).ok_or_else(|| {
                anyhow!("profile namespace registry entry missing for {}", profile)
            })?;

            // Enter the existing mount namespace.
            enter_ns(&ns_alive, &bind_mount)?;

            // Rigorous safety check: refuse to proceed unless we are in the
            // exact mount namespace recorded for this profile.
            nsproxy_core::sandbox::assert_mount_ns_matches(&profile_namespaces.mnt)?;

            // Check if a previous sandbox is already in place (restart case).
            let sandbox_state = nsproxy_core::sandbox::detect_sandbox_state(ns_alive.rootfs)?;

            // Determine before consuming sandbox_state whether a pivot root will be/was applied.
            // Hot mounts applied after a pivot must resolve source paths through /pivot (the old root).
            let is_pivot_mode = profile_conf.sandbox_mode == SandboxMode::Pivot;

            match sandbox_state {
                nsproxy_core::sandbox::SandboxState::Pivoted => {
                    info!("sandbox already applied, skipping pivot");
                }
                nsproxy_core::sandbox::SandboxState::NoPivot => {
                    if is_pivot_mode {
                        // Build and pivot into the sandbox root.
                        nsproxy_core::sandbox::apply_pivot(&profile_conf, &profile)?;
                        let rootfs = nsproxy_core::sandbox::current_rootfs_id()?;
                        update_ns_alive(&ns_meta, |ns_alive| {
                            ns_alive.rootfs = Some(rootfs);
                        })?;
                    }
                }
            }

            let mut status_mounts = profile_conf.mounts.clone();

            // Resolve the hot config path (already expanded).
            let hot_path = profile_conf.hot.clone();

            // After a pivot the process root is the new tmpfs root; the old host
            // filesystem is accessible at /pivot.  Source paths in hot mounts are
            // host paths, so we must chroot them to /pivot when in pivot mode.
            let hot_vars = {
                let base = nsproxy_core::PathExpansionState::for_instance(&instance_root);
                if is_pivot_mode {
                    base.with_src_chroot(std::path::Path::new("/pivot"))
                } else {
                    base
                }
            };
            if hot_path.exists() {
                let fc = std::fs::read_to_string(&hot_path)?;
                if let Ok(mut hot) = serde_json::from_str::<HotConfig>(&fc) {
                    hot.process_and_save(&hot_path)?;
                    hot.expand_with(&hot_vars);
                    if let Ok(mounts) = hot.merged_mounts() {
                        if !mounts.is_empty() {
                            nsproxy_core::sandbox::apply_mounts(&hot_vars, &mounts)?;
                            status_mounts.extend(mounts);
                        }
                    }
                }
            }

            let sandbox_state = nsproxy_core::sandbox::detect_sandbox_state(
                read_ns_alive_opt(&ns_meta).and_then(|ns_alive| ns_alive.rootfs),
            )?;
            let sandbox_status = collect_sandbox_status(
                profile_conf.sandbox_mode.clone(),
                sandbox_state,
                &status_mounts,
                None,
            )?;
            write_sandbox_status(&profile, &sandbox_status)?;
        }
        MainCommand::Daemon { cmd } => {
            check_capsys()?;

            if let Some(cmd) = cmd {
                let request = match cmd {
                    DaemonCliRequest::Ping => diag::RootDaemonRequest {
                        op_id: 0,
                        op: diag::RootDaemonOp::Ping,
                    },
                    DaemonCliRequest::Stop => diag::RootDaemonRequest {
                        op_id: 0,
                        op: diag::RootDaemonOp::Stop,
                    },
                    DaemonCliRequest::CreateDirAll { path } => diag::RootDaemonRequest {
                        op_id: 0,
                        op: diag::RootDaemonOp::CreateDirAll { path },
                    },
                    DaemonCliRequest::ReadFile { path } => diag::RootDaemonRequest {
                        op_id: 0,
                        op: diag::RootDaemonOp::ReadFile { path },
                    },
                    DaemonCliRequest::WriteFile {
                        path,
                        content,
                        create_parent,
                    } => diag::RootDaemonRequest {
                        op_id: 0,
                        op: diag::RootDaemonOp::WriteFile {
                            path,
                            content,
                            create_parent,
                        },
                    },
                    DaemonCliRequest::CreateProfile {
                        name,
                        profile_content,
                        hot_content,
                    } => diag::RootDaemonRequest {
                        op_id: 0,
                        op: diag::RootDaemonOp::CreateProfile {
                            name,
                            profile_content,
                            hot_content,
                        },
                    },
                };
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                rt.block_on(async {
                    let mut stream =
                        diag::connect_root_daemon(&diag::root_daemon_sock_path()).await?;
                    stream.send_request(&request).await?;
                    match stream.next_event().await? {
                        Some(evt) => {
                            println!("{:?}", evt);
                            Ok::<(), anyhow::Error>(())
                        }
                        None => bail!("root daemon closed connection without a response"),
                    }
                })?;
            } else {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                rt.block_on(run_root_daemon(cli.control_socket.clone()))?;
            }
        }
        _ => unimplemented!(),
    }

    Ok(())
}

fn exit_with_warn(code: i32, reason: &'static str) -> ! {
    warn!(exit_code = code, reason, "intentional process exit");
    std::process::exit(code);
}

fn load_hot_config_from_disk_or_default(path: &Path) -> HotConfig {
    match std::fs::read_to_string(path) {
        Ok(fc) => match serde_json::from_str::<HotConfig>(&fc) {
            Ok(mut conf) => {
                if let Err(err) = conf.process_and_save(path) {
                    warn!(?path, %err, "failed to persist normalized hot config");
                }
                conf
            }
            Err(e) => {
                warn!(
                    "failed to parse hot config {:?} at startup: {}, using default",
                    path, e
                );
                HotConfig::default()
            }
        },
        Err(e) => {
            warn!(
                "failed to read hot config {:?} at startup: {}, using default",
                path, e
            );
            HotConfig::default()
        }
    }
}

fn create_veth_pair(
    src: NsArg,
    dst: NsArg,
    veth_name: Option<String>,
    src_ip4: Option<Ipv4Addr>,
    dst_ip4: Option<Ipv4Addr>,
    prefix_len: u8,
) -> Result<()> {
    warn!("make veth {:?} -> {:?}", src, dst);
    let src_endpoint = resolve_veth_endpoint(&src)?;
    let dst_endpoint = resolve_veth_endpoint(&dst)?;
    let vname = veth_name
        .unwrap_or_else(|| format!("{}_{}", src_endpoint.label, dst_endpoint.label));
    let v_src = veth_interface_name(&vname, "src");
    let v_dst = veth_interface_name(&vname, "dst");
    let veth_net: Ipv4Network = "100.64.0.0/10".parse()?;
    if prefix_len == 0 || prefix_len >= 32 {
        bail!("veth prefix length must be between 1 and 31");
    }
    if src_ip4.is_some() != dst_ip4.is_some() {
        bail!("src_ip4 and dst_ip4 must be supplied together");
    }
    let host_bits = 32 - prefix_len;

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        let nl = tokio_netlink_conn()?;
        remove_link_if_exists_in_namespace(src_endpoint.source.clone(), &v_src).await?;
        remove_link_if_exists_in_namespace(dst_endpoint.source.clone(), &v_dst).await?;
        nl.remove_link_if_exists(&v_src).await?;
        nl.remove_link_if_exists(&v_dst).await?;

        let mut used = fetch_ipv4_in_namespace(NSSource::Pid(std::process::id() as i32)).await?;
        if !veth_endpoint_is_current(&src_endpoint) {
            used.extend(fetch_ipv4_in_namespace(src_endpoint.source.clone()).await?);
        }
        if !veth_endpoint_is_current(&dst_endpoint) && dst_endpoint.source != src_endpoint.source {
            used.extend(fetch_ipv4_in_namespace(dst_endpoint.source.clone()).await?);
        }

        let (src_addr, dst_addr) = match (src_ip4, dst_ip4) {
            (Some(src_addr), Some(dst_addr)) => {
                if used.contains(&src_addr) || used.contains(&dst_addr) {
                    bail!("requested veth address is already occupied");
                }
                (src_addr, dst_addr)
            }
            (None, None) => {
                let subnet = find_vacant_ipv4_subnet(used, veth_net, host_bits)
                    .ok_or_else(|| anyhow!("cannot find any vacant ip"))?;
                (veth_addr_for(subnet, host_bits, true), veth_addr_for(subnet, host_bits, false))
            }
            _ => unreachable!(),
        };

        nl.add_veth(&v_src, &v_dst).await?;
        if !veth_endpoint_is_current(&src_endpoint) {
            let src_link = nl.fetch_link_by_name(v_src.clone()).await?;
            let mut msg: LinkMessageBuilder<LinkVeth> =
                LinkMessageBuilder::default().index(src_link.header.index);
            msg = match &src_endpoint.target {
                VethNamespaceTarget::Pid(pid) => msg.setns_by_pid(*pid),
                VethNamespaceTarget::Fd(fd) => msg.setns_by_fd(fd.as_raw_fd()),
            };
            nl.link().set(msg.build()).execute().await?;
        }
        if !veth_endpoint_is_current(&dst_endpoint) {
            let dst_link = nl.fetch_link_by_name(v_dst.clone()).await?;
            let mut msg: LinkMessageBuilder<LinkVeth> =
                LinkMessageBuilder::default().index(dst_link.header.index);
            msg = match &dst_endpoint.target {
                VethNamespaceTarget::Pid(pid) => msg.setns_by_pid(*pid),
                VethNamespaceTarget::Fd(fd) => msg.setns_by_fd(fd.as_raw_fd()),
            };
            nl.link().set(msg.build()).execute().await?;
        }
        configure_veth_endpoint(src_endpoint.source, v_src, src_addr, prefix_len).await?;
        configure_veth_endpoint(dst_endpoint.source, v_dst, dst_addr, prefix_len).await?;
        Ok(())
    })
}

fn reconcile_configured_veths(profile: &str) {
    let hot = load_hot_config_from_disk_or_default(&state_paths::hot_config(profile));
    let mut snapshot = VethStatusSnapshot::default();
    let basis_source = match NamespacesRegistry::load_locked()
        .ok()
        .and_then(|registry| registry.basis_ns)
        .map(|namespaces| namespaces.net.source)
    {
        Some(source) => source,
        None => {
            let detail = "basis namespace is not recorded; run 'sp init' first".to_string();
            for spec in hot.veth {
                snapshot.entries.push(VethStatus {
                    spec,
                    success: false,
                    detail: detail.clone(),
                    updated_at_secs: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                });
            }
            if let Ok(content) = serde_json::to_string_pretty(&snapshot) {
                if let Err(err) = std::fs::write(state_paths::veth_status(profile), content) {
                    warn!(profile, %err, "failed to persist veth status");
                }
            }
            return;
        }
    };
    for spec in hot.veth {
        let result = run_in_netns_clone3_source(
            basis_source.clone(),
            || {
                create_veth_pair(
                    spec.src.parse().map_err(|e: String| anyhow!(e))?,
                    spec.dst.parse().map_err(|e: String| anyhow!(e))?,
                    spec.veth_name.clone(),
                    spec.src_ip4,
                    spec.dst_ip4,
                    spec.prefix_len,
                )
            },
        );
        snapshot.entries.push(VethStatus {
            spec,
            success: result.is_ok(),
            detail: result.map(|_| "veth ready".to_string()).unwrap_or_else(|e| e.to_string()),
            updated_at_secs: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        });
    }
    if let Ok(content) = serde_json::to_string_pretty(&snapshot) {
        if let Err(err) = std::fs::write(state_paths::veth_status(profile), content) {
            warn!(profile, %err, "failed to persist veth status");
        }
    }
}

fn load_hot_config_with_serve_dns_overrides(
    path: &Path,
    no_dns_capture: Option<bool>,
    internal_dns_server: Option<bool>,
) -> HotConfig {
    let mut hot = load_hot_config_from_disk_or_default(path);
    if let Some(no_dns_capture) = no_dns_capture {
        hot.set_dns_capture_enabled(!no_dns_capture);
    }
    if let Some(internal_dns_server) = internal_dns_server {
        hot.resolv_conf_dns = if internal_dns_server {
            nsproxy_core::INTERNAL_RESOLV_CONF_DNS.to_string()
        } else {
            nsproxy_core::CAPTURED_RESOLV_CONF_DNS.to_string()
        };
    }
    hot
}

#[derive(Debug)]
struct NamespaceProcess {
    pid: u32,
    command: String,
}

fn resolve_ps_netns(target: &str) -> Result<UniqueFile> {
    if let Ok(pid) = target.parse::<u32>() {
        return Ok(ExactNS::from_source((PidPath::N(pid as i32), "net"))?.unique);
    }

    let registry = NamespacesRegistry::load_locked()?;
    if let Some(profile) = registry.profiles.get(target) {
        return Ok(profile.net.unique);
    }

    let path = if target.starts_with('/') || target.starts_with("./") || target.starts_with("~/") {
        PathExpansionState::without_instance().expand(Path::new(target))
    } else {
        bail!(
            "unknown container {:?}; expected a container name, mount path, or PID",
            target
        );
    };
    let mount_ns = ExactNS::from_source(path)?;
    registry
        .profiles
        .values()
        .find(|profile| profile.mnt.unique == mount_ns.unique)
        .map(|profile| profile.net.unique)
        .ok_or_else(|| anyhow!("no registered container matches mount namespace {:?}", target))
}

fn scan_processes_in_netns(netns: UniqueFile) -> Vec<NamespaceProcess> {
    let mut processes = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return processes;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|name| name.parse::<u32>().ok()) else {
            continue;
        };
        let ns_path = entry.path().join("ns/net");
        let Ok(metadata) = std::fs::metadata(ns_path) else {
            continue;
        };
        if UniqueFile::new(metadata.ino(), metadata.dev()) != netns {
            continue;
        }

        let command = std::fs::read(entry.path().join("cmdline"))
            .ok()
            .filter(|cmdline| !cmdline.is_empty())
            .map(|cmdline| {
                String::from_utf8_lossy(&cmdline)
                    .replace('\0', " ")
                    .trim()
                    .to_string()
            })
            .filter(|command| !command.is_empty())
            .or_else(|| std::fs::read_to_string(entry.path().join("comm")).ok())
            .unwrap_or_else(|| "<unknown>".to_string());
        processes.push(NamespaceProcess { pid, command });
    }

    processes.sort_by_key(|process| process.pid);
    processes
}

fn cmd_ps(target: &str, kill: bool) -> Result<()> {
    let netns = resolve_ps_netns(target)?;
    let processes = scan_processes_in_netns(netns);
    println!("netns {}: {} process(es)", netns, processes.len());

    if kill {
        let self_pid = std::process::id();
        for process in processes {
            if process.pid == self_pid {
                warn!(pid = process.pid, "skipping current process during namespace kill");
                continue;
            }
            match nix::sys::signal::kill(
                Pid::from_raw(process.pid as i32),
                nix::sys::signal::Signal::SIGKILL,
            ) {
                Ok(()) => println!("killed {:>6} {}", process.pid, process.command),
                Err(nix::errno::Errno::ESRCH) => {
                    warn!(pid = process.pid, "process exited during namespace scan")
                }
                Err(error) => {
                    warn!(pid = process.pid, %error, "failed to kill process");
                }
            }
        }
    } else {
        for process in processes {
            println!("{:>6} {}", process.pid, process.command);
        }
    }
    Ok(())
}

fn apply_hot_route_to_uplink(uplink: &mut nsproxy_core::uplink::UplinkHub, route: &HotRoute) {
    match route {
        HotRoute::None => uplink.set_routing(nsproxy_core::uplink::no_routing()),
        HotRoute::SimpleProxy { proxy_id } => {
            uplink.set_routing(nsproxy_core::uplink::simple_routing(proxy_id.clone()));
        }
    }
}

async fn serve_worker_runtime(
    tx: UnixStream,
    tun_dev_index: u32,
    no_default: bool,
    hot_conf: PathBuf,
    write_resolv_conf_directly: bool,
) -> Result<()> {
    use tokio::io::AsyncReadExt;
    use tokio_send_fd::SendFd;
    warn!("serve child runtime initialized");
    tx.set_nonblocking(true)?;
    let mut tx = tokio::net::UnixStream::from_std(tx)?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let nl = tokio_netlink_conn()?;
    nl.up_lo().await?;

    let txqueuelen = 500_000u32;
    warn!(
        "setting TUN txqueuelen to {} for high throughput",
        txqueuelen
    );
    nl.link()
        .set(
            LinkMessageBuilder::<LinkUnspec>::default()
                .index(tun_dev_index)
                .append_extra_attribute(LinkAttribute::TxQueueLen(txqueuelen))
                .build(),
        )
        .execute()
        .await?;

    if !no_default {
        warn!("adding TUN as default route");
        if let Err(e) = nl.ip_add_default_route(tun_dev_index).await {
            // EEXIST (17) means the route is already present from a previous run — ignore.
            let is_exists =
                e.to_string().contains("File exists") || format!("{e:?}").contains("17");
            if is_exists {
                warn!("default route already exists, skipping");
            } else {
                return Err(e.into());
            }
        }
    }

    warn!("start internal DNS server");
    let mut dns_shutdown_rx = shutdown_rx.clone();
    tokio::spawn(nsproxy_common::trace_spawn_result(
        "serve child dns supervisor",
        async move {
            loop {
                let mut dns_run_shutdown_rx = dns_shutdown_rx.clone();
                nsproxy_common::trace_spawn_result(
                    "internal DNS server",
                    async move {
                        tokio::select! {
                            rx = run_dns_ipv4_only() => { warn!("{:?}", rx); }
                            changed = dns_run_shutdown_rx.changed() => {
                                match changed {
                                    Ok(()) if *dns_run_shutdown_rx.borrow() => {
                                        warn!("internal DNS server stopped after control socket closed");
                                    }
                                    Ok(()) => {}
                                    Err(_) => {
                                        warn!("internal DNS server stopped because shutdown watcher closed");
                                    }
                                }
                            }
                        }
                        aok!()
                    },
                )
                .await;
                if *dns_shutdown_rx.borrow() {
                    warn!("serve child dns supervisor exiting after shutdown signal");
                    break;
                }
            }
            aok!()
        },
    ));

    tokio::spawn(nsproxy_common::trace_spawn_result(
        "serve child hot reload watcher",
        async move {
            let mut read = [0u8; 1];
            let mut len_buf = [0u8; 4];
            loop {
                warn!("in-ns wait for config");
                if tx.read_exact(&mut read[..]).await.is_err() {
                    warn!("in-ns config watcher exits due to EOF");
                    let _ = shutdown_tx.send(true);
                    break;
                }
                warn!("in-ns reload config");
                if read[0] != 1 {
                    warn!("in-ns unknown config command {}", read[0]);
                    continue;
                }
                tx.read_exact(&mut len_buf).await?;
                let payload_len = u32::from_le_bytes(len_buf) as usize;
                let mut payload = vec![0u8; payload_len];
                tx.read_exact(&mut payload).await?;
                if let Ok(request) = serde_json::from_slice::<
                    nsproxy_core::hot_reload::ChildHotReloadRequest,
                >(&payload)
                {
                    let mut newconf = request.config;
                    newconf.process();
                    replace_mount_resolv_conf(
                        &newconf.resolv_conf_dns,
                        write_resolv_conf_directly,
                    )?;
                    if let Err(err) = newconf.merged_mounts() {
                        warn!("failed to merge hot mounts during sandbox handoff: {}", err);
                    } else {
                        warn!(
                            "skipping live sandbox mount reconcile in serve child; waiting for dedicated sp sandbox run"
                        );
                    }
                    tx.write(&[0, 0, 0, 0]).await?;
                    for in_port in request.requested_local_ports {
                        match std::net::TcpListener::bind(format!("127.0.0.1:{}", in_port)) {
                            Ok(bind) => {
                                let raw = bind.as_raw_fd();
                                tx.write(&in_port.to_le_bytes()).await?;
                                tx.send_fd(raw).await?;
                            }
                            Err(err) => {
                                warn!(
                                    "failed to bind refreshed local forward listener on 127.0.0.1:{}: {}",
                                    in_port, err
                                );
                            }
                        }
                    }
                    tx.write(&[0, 0, 0, 0]).await?;
                    let _ = sync_links(None, &newconf.devs).await;
                }
                // TODO: DNS
            }
            drop(hot_conf); // kept alive until watcher exits
            aok!()
        },
    ));

    let mut shutdown_rx = shutdown_rx;
    match shutdown_rx.changed().await {
        Ok(()) if *shutdown_rx.borrow() => {
            warn!("serve child main task exiting after shutdown signal")
        }
        Ok(()) => warn!("serve child main task woke without shutdown flag"),
        Err(_) => warn!("serve child main task exiting because shutdown watcher closed"),
    }
    aok!()
}

fn cmd_serve(
    profile: String,
    tun_name: Option<String>,
    simple: Option<nsproxy_common::routing::ProxyNym>,
    no_default: bool,
    log: Option<LevelFilter>,
    _clash: Option<String>,
    no_dns_capture: Option<bool>,
    control_socket: Option<PathBuf>,
    set_log: &mut dyn FnMut(LevelFilter) -> Result<()>,
    internal_dns_server: Option<bool>,
) -> Result<()> {
    let ns_meta = state_paths::profile_ns_meta(&profile);
    let ns_alive = read_ns_alive(&ns_meta)?;
    let registry = NamespacesRegistry::load_locked()?;
    let profile_namespaces = registry.profiles.get(&profile).cloned().ok_or_else(|| {
        anyhow!(
            "no persisted namespace metadata found for profile {}",
            profile
        )
    })?;
    let profile_path = state_paths::profile_config(&profile);
    let profile_conf = TemplateConfig::load(&profile_path)?;
    let write_resolv_conf_directly = ns_alive.rootfs.is_some();

    let child_pid = ns_alive
        .child_pid
        .ok_or_else(|| anyhow!("ns_alive has no child_pid"))?;

    let hot_conf = state_paths::hot_config(&profile);
    if !hot_conf.exists() {
        bail!("hot config does not exist: {:?}", hot_conf);
    }

    let diag_path = diag::diag_sock_path(&profile);
    if diag_path.exists() {
        let expected_netns = profile_namespaces.net.unique;
        let probe_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;
        let probe = probe_runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(1), async {
                let (mut stream, identity) = diag::connect_with_identity(&diag_path).await?;
                info!(
                    peer_pid = identity.self_pid,
                    peer_netns = %identity.netns,
                    expected_netns = %expected_netns,
                    "probed existing TUN diagnostic socket"
                );
                if identity.netns == expected_netns {
                    return Ok::<bool, anyhow::Error>(true);
                }

                warn!(
                    expected = %expected_netns,
                    actual = %identity.netns,
                    peer_pid = identity.self_pid,
                    "diag socket belongs to a different network namespace; requesting shutdown"
                );
                stream
                    .send_cmd(&diag::ControlCommand::Shutdown)
                    .await
                    .context("request shutdown from existing TUN")?;
                Ok(false)
            })
            .await
        });
        match probe {
            Ok(Ok(true)) => {
                bail!(
                    "tun appears to be running (diag socket handshake succeeded): {:?}",
                    diag_path
                );
            }
            Ok(Ok(false)) => {
                warn!("existing TUN shutdown requested, proceeding with startup");
            }
            Ok(Err(e)) => {
                warn!(
                    "diag socket handshake failed ({}), proceeding with startup: {:?}",
                    e, diag_path
                );
            }
            Err(_) => {
                warn!(
                    "diag socket handshake timed out, proceeding with startup: {:?}",
                    diag_path
                );
            }
        }
    }
    let mtu = 1500;
    let tun_name = tun_name.unwrap_or_else(|| "tun2".to_owned());
    let child_process_label = format!("serve-{}-child", profile);
    let (child_log_parent, child_log_child) = UnixStream::pair()?;

    let clone = nsproxy_core::sys::clone3::<false>(false, false);
    match clone {
        Ok(clone) => match clone {
            Clone3Result::IsChild { mut tx } => {
                drop(child_log_parent);
                if false {
                    let _file_log_path = match diag::enable_process_log_file(&child_process_label) {
                        Ok(path) => {
                            warn!(path = %path.display(), "serve child file-backed log available (disabled)");
                            Some(path)
                        }
                        Err(err) => {
                            warn!(%err, "serve child failed to enable file-backed log");
                            None
                        }
                    };
                }
                warn!(
                    profile,
                    tun_name, child_pid, "serve child bootstrap starting"
                );
                diag::install_child_log_forward(child_log_child);
                let hot_conf = hot_conf.clone();
                let write_resolv_conf_directly = write_resolv_conf_directly;
                let expected_mnt = profile_namespaces.mnt.clone();
                let ns_source = NSSource::Pid(child_pid as i32);
                warn!(child_pid, "serve child entering target mount namespace");
                ns_source.enter(CloneFlags::CLONE_NEWNS)?;
                warn!(child_pid, "serve child entering target network namespace");
                ns_source.enter(CloneFlags::CLONE_NEWNET)?;
                warn!(child_pid, "serve child validating mount namespace identity");
                nsproxy_core::sandbox::assert_mount_ns_matches(&expected_mnt)?;

                let initial_hot = load_hot_config_with_serve_dns_overrides(
                    &hot_conf,
                    no_dns_capture,
                    internal_dns_server,
                );
                warn!("serve child applying resolv.conf override");
                replace_mount_resolv_conf(
                    &initial_hot.resolv_conf_dns,
                    write_resolv_conf_directly,
                )?;

                let mut tun = TunMaker::default();
                tun.name = tun_name.clone();
                tun.mtu = mtu;
                warn!(tun_name, mtu, "serve child creating TUN device");
                let mut tun_state = tun.make()?;
                tun_state.sync_basic()?;
                let dev = Arc::into_inner(tun_state.fd.unwrap()).unwrap();
                let raw = dev.as_raw_fd();

                warn!(fd = raw, "serve child sending TUN fd to parent");
                tx.send_fd(raw)?;
                drop(dev);

                // Supervisor loop: fork a worker grandchild for the async runtime.
                // If the worker is killed or crashes, the supervisor forks a fresh one.
                // The parent (great-grandparent) already has the TUN fd and is unaffected.
                let mut restart_count: u32 = 0;
                loop {
                    if restart_count > 0 {
                        let backoff_secs = restart_count.min(10) as u64;
                        warn!(
                            restart_count,
                            backoff_secs, "serve supervisor: restarting worker after abnormal exit"
                        );
                        std::thread::sleep(Duration::from_secs(backoff_secs));
                    }
                    restart_count += 1;
                    match unsafe { fork()? } {
                        ForkResult::Child => {
                            // Worker grandchild: all paths end in exit_with_warn (-> !)
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .expect("serve worker: failed to build tokio runtime");
                            let result = rt.block_on(serve_worker_runtime(
                                tx,
                                tun_state.dev_index,
                                no_default,
                                hot_conf,
                                write_resolv_conf_directly,
                            ));
                            match result {
                                Ok(()) => exit_with_warn(0, "serve worker exited cleanly"),
                                Err(ref e) => {
                                    warn!(%e, "serve worker exited with error");
                                    exit_with_warn(1, "serve worker exited with error");
                                }
                            }
                        } // ForkResult::Child
                        ForkResult::Parent { child } => {
                            // Supervisor: wait for the worker, restart if it crashed.
                            warn!(
                                worker_pid = child.as_raw(),
                                restart_count, "serve supervisor: worker forked"
                            );
                            match nix::sys::wait::waitpid(child, None) {
                                Ok(nix::sys::wait::WaitStatus::Exited(_, 0)) => {
                                    warn!("serve supervisor: worker exited cleanly; stopping");
                                    break;
                                }
                                Ok(status) => {
                                    warn!(
                                        ?status,
                                        restart_count,
                                        "serve supervisor: worker exited abnormally; restarting"
                                    );
                                }
                                Err(e) => {
                                    warn!(%e, "serve supervisor: waitpid failed; stopping");
                                    break;
                                }
                            }
                        } // ForkResult::Parent
                    } // match fork
                } // supervisor loop
            } // IsChild
            Clone3Result::Parent {
                child_pid,
                child_pidfd,
                mut tx,
            } => {
                drop(child_log_child);
                let hot_conf = hot_conf.clone();
                info!("recved fd");
                let dev = tx.recv_fd()?;
                let dev = Arc::new(unsafe { AsyncDevice::from_fd(dev) }?);

                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()?;
                if let Some(log) = log {
                    set_log(log)?;
                }

                // Record this process's PID as the serve process
                let serve_pid = std::process::id();
                update_ns_alive(&ns_meta, |ns_alive| {
                    ns_alive.serve_pid = Some(serve_pid);
                })?;
                info!("recorded serve_pid={} to {:?}", serve_pid, &ns_meta);

                rt.spawn(nsproxy_common::trace_spawn_result(
                    "serve child pidfd watcher",
                    async move {
                        let fd = unsafe { PidFd::from_raw_fd(child_pidfd) };
                        let _ = fd.into_future().await?;
                        warn!("tun helper exited");
                        aok!()
                    },
                ));

                rt.block_on(async move {
                    use tokio::io::AsyncWriteExt;

                    tx.set_nonblocking(true)?;
                    let mut tx = tokio::net::UnixStream::from_std(tx)?;
                    child_log_parent.set_nonblocking(true)?;
                    let mut child_log_stream = tokio::net::UnixStream::from_std(child_log_parent)?;

                    let (mut vdns_sx, vdns_rx) = mpsc::channel(1);
                    let (st_sx, acceptor) = flume::unbounded();
                    let (hot_reload_tx, hot_reload_rx) = tokio::sync::mpsc::channel(8);

                    let mut initial_hot = load_hot_config_with_serve_dns_overrides(
                        &hot_conf,
                        no_dns_capture,
                        internal_dns_server,
                    );
                    if no_dns_capture.is_some() || internal_dns_server.is_some() {
                        initial_hot.save(&hot_conf)?;
                    }

                    let (hot_tx, hot_rx) = tokio::sync::watch::channel(initial_hot.clone());
                    let shared_hot = Arc::new(hot_rx);
                    let live_hot = Arc::new(tokio::sync::RwLock::new(initial_hot.clone()));

                    let mut hub = load_saved_uplink_hub()?;
                    let router_conf = nsproxy_core::uplink::router::RouterConfig {
                        mtu,
                        packet_info: false,
                        udp_timeout: Duration::from_secs(20),
                        diag_sock: Some(diag_path.clone()),
                    };

                    if let Some(nym) = simple {
                        let proxy_id = hub.nym_map.get(&nym).cloned().ok_or_else(|| {
                            anyhow!("Simple route proxy not found for nym {}", nym)
                        })?;
                        initial_hot.route = HotRoute::SimpleProxy { proxy_id };
                        initial_hot.save(&hot_conf)?;
                        let _ = hot_tx.send(initial_hot.clone());
                    }

                    apply_hot_route_to_uplink(&mut hub, &initial_hot.route);

                    let mut router = nsproxy_core::uplink::router::Router::new(
                        dev,
                        router_conf,
                        hub,
                        Some(st_sx),
                        shared_hot,
                    )?;

                    let selected_proxy = match &initial_hot.route {
                        HotRoute::None => None,
                        HotRoute::SimpleProxy { proxy_id } => Some(proxy_id.clone()),
                    };

                    router.init_diag(&diag_path).await?;

                    let diag_srv = router.diag_handle();
                    tokio::spawn(nsproxy_common::trace_spawn_result(
                        "serve child log relay",
                        async move {
                        loop {
                            match read_bincode_frame_async::<diag::LogEntry, _>(&mut child_log_stream)
                                .await
                            {
                                Ok(Some(entry)) => diag_srv.emit_forwarded_log(entry),
                                Ok(None) => {
                                    warn!("serve child log relay exiting after EOF");
                                    break;
                                }
                                Err(err) => {
                                    warn!("serve child log relay failed: {}", err);
                                    break;
                                }
                            }
                        }
                        aok!()
                    },
                    ));

                    // If the UI passed a control socket, connect to it now (after the diag
                    // server is ready) and register the reversed connection as a diag client.
                    if let Some(ref ctrl_path) = control_socket {
                        match connect_and_greet_serve(ctrl_path, &profile).await {
                            Ok(stream) => {
                                info!("sp serve: connected to UI control socket as reversed diag client");
                                router.diag_handle().add_reversed_client(stream);
                            }
                            Err(e) => warn!("sp serve: failed to connect to control socket {:?}: {}", ctrl_path, e),
                        }
                    }

                    // Forward tracing logs to this profile's diag socket for the lifetime
                    // of this serve task and all explicitly-scoped spawned children.
                    let diag_srv_scope = router.diag_handle();
                    // Also register as the process-global sink so that tasks spawned without
                    // an explicit scope (e.g. router-internal tokio::spawn) forward logs here.
                    diag_srv_scope.install_as_global();
                    let scope_for_cmd = diag_srv_scope.clone();
                    let scope_for_watch = diag_srv_scope.clone();
                    diag_srv_scope.scope(async move {

                    // Drive the control-command loop emitted by diag clients.
                    if let Some(mut cmd_rx) = router.take_cmd_rx() {
                        let uplink_cmd = router.uplink.clone();
                        let hot_conf_cmd = hot_conf.clone();
                        let hot_tx = hot_tx.clone();
                        let reload_tx = hot_reload_tx.clone();
                        let diag_srv = router.diag_handle();
                        let dns_handle = router.dns_handle();
                        let live_hot_cmd = live_hot.clone();
                        tokio::spawn(nsproxy_common::trace_spawn_result(
                            "serve parent diag command loop",
                            scope_for_cmd.scope(async move {
                            while let Some(cmd) = cmd_rx.recv().await {
                                match cmd {
                                    diag::ControlCommand::Shutdown => {
                                        warn!("serve shutdown requested via diag socket");
                                        std::process::exit(0);
                                    }
                                    diag::ControlCommand::ReloadUplink => {
                                        if let Ok(hub) = nsproxy_core::cmd_uplink::load_saved_uplink_hub() {
                                            let mut hub = hub;
                                            let current_hot = live_hot_cmd.read().await.clone();
                                            apply_hot_route_to_uplink(&mut hub, &current_hot.route);
                                            let mut u = uplink_cmd.write().await;
                                            *u = hub;
                                            info!("uplink reloaded via diag cmd");
                                        }
                                    }
                                    diag::ControlCommand::ReloadHotConfig => {
                                        match tokio::fs::read_to_string(&hot_conf_cmd).await {
                                            Ok(fc) => match serde_json::from_str::<HotConfig>(&fc) {
                                                Ok(cfg) => {
                                                    let mut cfg = cfg;
                                                    if let Err(err) = cfg.process_and_save(&hot_conf_cmd) {
                                                        warn!(%err, "failed to persist normalized hot config");
                                                    }
                                                    let _ = reload_tx.send(nsproxy_core::hot_reload::HotReloadTrigger::ApplyConfig {
                                                        source: "direct",
                                                        persist_backup: false,
                                                        config: Arc::new(cfg),
                                                    }).await;
                                                }
                                                Err(e) => {
                                                    diag_srv.emit(diag::DiagEvent::HotConfigReloaded {
                                                        ts: diag::Timestamp::now(),
                                                        ok: false,
                                                        changed: false,
                                                        source: "direct".to_string(),
                                                        error: Some(e.to_string()),
                                                    });
                                                    warn!("hot config parse error: {e}");
                                                }
                                            },
                                            Err(e) => {
                                                diag_srv.emit(diag::DiagEvent::HotConfigReloaded {
                                                    ts: diag::Timestamp::now(),
                                                    ok: false,
                                                    changed: false,
                                                    source: "direct".to_string(),
                                                    error: Some(e.to_string()),
                                                });
                                                warn!("hot config read error: {e}");
                                            }
                                        }
                                    }
                                    diag::ControlCommand::SetSimpleRouting { proxy_id } => {
                                        let mut next_hot = live_hot_cmd.read().await.clone();
                                        next_hot.route = HotRoute::SimpleProxy {
                                            proxy_id: proxy_id.clone(),
                                        };
                                        let _ = reload_tx.send(nsproxy_core::hot_reload::HotReloadTrigger::ApplyConfig {
                                            source: "route",
                                            persist_backup: true,
                                            config: Arc::new(next_hot),
                                        }).await;
                                    }
                                    diag::ControlCommand::QueryDnsState => {
                                        let stats = dns_handle.stats();
                                        diag_srv.emit(diag::DiagEvent::DnsState {
                                            ts: diag::Timestamp::now(),
                                            state: diag::DnsState {
                                                aaaa_only: stats.aaaa_only,
                                                domain_count: stats.domain_count,
                                                ip4_count: stats.ip4_count,
                                                ip6_count: stats.ip6_count,
                                            },
                                        });
                                    }
                                    diag::ControlCommand::QueryRoutingState => {
                                        let current_hot = live_hot_cmd.read().await.clone();
                                        let selected_proxy = match &current_hot.route {
                                            HotRoute::None => None,
                                            HotRoute::SimpleProxy { proxy_id } => Some(proxy_id.clone()),
                                        };
                                        diag_srv.emit(diag::DiagEvent::RoutingState {
                                            ts: diag::Timestamp::now(),
                                            state: diag::RoutingState {
                                                selected_proxy,
                                            },
                                        });
                                    }
                                    diag::ControlCommand::QueryHotConfig => {
                                        let current_hot = live_hot_cmd.read().await.clone();
                                        match serde_json::to_string_pretty(&current_hot) {
                                            Ok(content) => {
                                                diag_srv.emit(diag::DiagEvent::HotConfigSnapshot {
                                                    ts: diag::Timestamp::now(),
                                                    ok: true,
                                                    content: Some(content),
                                                    error: None,
                                                });
                                            }
                                            Err(e) => {
                                                diag_srv.emit(diag::DiagEvent::HotConfigSnapshot {
                                                    ts: diag::Timestamp::now(),
                                                    ok: false,
                                                    content: None,
                                                    error: Some(e.to_string()),
                                                });
                                            }
                                        }
                                    }
                                    diag::ControlCommand::ApplyHotConfig { content } => {
                                        match serde_json::from_str::<HotConfig>(&content) {
                                            Ok(cfg) => {
                                                let mut cfg = cfg;
                                                match cfg.process_and_save(&hot_conf_cmd) {
                                                    Ok(()) => {
                                                        let saved_content = serde_json::to_string_pretty(&cfg)
                                                            .unwrap_or_else(|_| content.clone());
                                                        if let Err(err) = reload_tx.send(nsproxy_core::hot_reload::HotReloadTrigger::ApplyConfig {
                                                            source: "direct",
                                                            persist_backup: false,
                                                            config: Arc::new(cfg),
                                                        }).await {
                                                            diag_srv.emit(diag::DiagEvent::HotConfigSnapshot {
                                                                ts: diag::Timestamp::now(),
                                                                ok: false,
                                                                content: Some(saved_content),
                                                                error: Some(err.to_string()),
                                                            });
                                                            warn!("hot config reload enqueue error: {err}");
                                                        } else {
                                                            diag_srv.emit(diag::DiagEvent::HotConfigSnapshot {
                                                                ts: diag::Timestamp::now(),
                                                                ok: true,
                                                                content: Some(saved_content),
                                                                error: None,
                                                            });
                                                        }
                                                    }
                                                    Err(err) => {
                                                        diag_srv.emit(diag::DiagEvent::HotConfigSnapshot {
                                                            ts: diag::Timestamp::now(),
                                                            ok: false,
                                                            content: None,
                                                            error: Some(err.to_string()),
                                                        });
                                                    }
                                                }
                                            }
                                            Err(err) => {
                                                diag_srv.emit(diag::DiagEvent::HotConfigSnapshot {
                                                    ts: diag::Timestamp::now(),
                                                    ok: false,
                                                    content: None,
                                                    error: Some(err.to_string()),
                                                });
                                            }
                                        }
                                    }
                                    diag::ControlCommand::QueryUplinkStats => {
                                        let hub = uplink_cmd.read().await;
                                        diag_srv.emit(diag::DiagEvent::UplinkStatsSnapshot {
                                            ts: diag::Timestamp::now(),
                                            stats: hub.stats.clone(),
                                        });
                                    }
                                    diag::ControlCommand::ClearStats => {
                                        let mut hub = uplink_cmd.write().await;
                                        hub.clear_stats();

                                        if let Err(e) = hub.save_stats() {
                                            warn!("failed to save cleared stats: {}", e);
                                        } else {
                                            info!("uplink stats cleared via diag cmd");
                                        }

                                        diag_srv.emit(diag::DiagEvent::UplinkStatsSnapshot {
                                            ts: diag::Timestamp::now(),
                                            stats: hub.stats.clone(),
                                        });
                                    }
                                    diag::ControlCommand::QueryRecentLogs { limit } => {
                                        let entries = diag::query_recent_logs(limit);
                                        diag_srv.emit(diag::DiagEvent::RecentLogs(entries));
                                    }
                                    // Handled directly inside serve_client; should never reach here.
                                    diag::ControlCommand::QueryRecentDiagEvents { .. } => {}
                                    diag::ControlCommand::SetTrackConns { .. } => {}
                                    diag::ControlCommand::ResetConnsState => {}
                                    diag::ControlCommand::QueryConnsState => {}
                                }
                            }
                            warn!("serve parent diag command loop exiting after command channel closed");
                            aok!()
                        }),
                        ));
                    }

                    let uplink_route = router.uplink.clone();
                    let mut route_rx = hot_tx.subscribe();
                    tokio::spawn(nsproxy_common::trace_spawn_result(
                        "serve parent route watch",
                        scope_for_cmd.scope(async move {
                        loop {
                            let cfg = route_rx.borrow().clone();
                            {
                                let mut uplink = uplink_route.write().await;
                                apply_hot_route_to_uplink(&mut uplink, &cfg.route);
                            }
                            if route_rx.changed().await.is_err() {
                                warn!("serve parent route watch exiting after hot-config watch closed");
                                break;
                            }
                        }
                        aok!()
                    }),
                    ));

                    let _ = vdns_sx.send(Some(router.dns_handle())).await;

                    let diag_srv = router.diag_handle();
                    let hot_tx_spawn = hot_tx.clone();
                    let live_hot_spawn = live_hot.clone();
                    tokio::spawn(nsproxy_common::trace_spawn_result(
                        "serve parent hot watcher",
                        scope_for_watch.scope(async move {
                        watch_hot(
                            vdns_rx,
                            Some(hot_conf),
                            acceptor,
                            child_pid as u32,
                            tx,
                            None,
                            diag_srv,
                            hot_reload_rx,
                            live_hot_spawn,
                            hot_tx_spawn,
                        )
                        .await?;
                        warn!("serve parent hot watcher exited cleanly");
                        aok!()
                    }),
                    ));

                    router.run().await?;
                    warn!("router exited");
                    let _ = vdns_sx.send(None).await;

                    std::future::pending::<()>().await;
                    aok!()
                    }).await
                })?;
            }
        },
        Err(er) => report_clone3_err(&er)?,
    }

    Ok(())
}

use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwap;

/// Shared mutable state for the `sp up` daemon.
#[derive(Clone)]
struct UpDaemonState {
    process_list: diag::ProcessList,
    /// PID of the currently-tracked `sp serve` process (0 = none).
    /// The corresponding entry in `process_list.processes` carries the
    /// live `ProcessStatus`; this field is the look-up key.
    serve_pid: u32,
    personal_runtime_state: diag::personal::PersonalRuntimeState,
}

pub fn try_resolve_nsinput(nsi: NsInput) -> Result<Option<ExactNS>> {
    match nsi {
        NsInput::Path(p) => Ok(Some(NSFrom::from_source(p)?)),
        NsInput::Pid(p) => Ok(Some(NSFrom::from_source(p)?)),
        _ => Ok(None),
    }
}

async fn handle_socks5_connection<S>(
    conn: socks5_impl::server::IncomingConnection<S>,
) -> anyhow::Result<()>
where
    S: Send + Sync + 'static,
{
    use socks5_impl::protocol::*;
    use socks5_impl::server::*;
    use tokio::io;
    use tokio::net::TcpStream;

    let (conn, res) = conn.authenticate().await?;

    match conn.wait_request().await? {
        ClientConnection::UdpAssociate(associate, _) => {
            info!("UDP associate not supported");
            let mut conn = associate
                .reply(Reply::CommandNotSupported, WireAddress::unspecified())
                .await?;
            conn.shutdown().await?;
        }
        ClientConnection::Bind(bind, _) => {
            info!("Bind not supported");
            let mut conn = bind
                .reply(Reply::CommandNotSupported, WireAddress::unspecified())
                .await?;
            conn.shutdown().await?;
        }
        ClientConnection::Connect(connect, addr) => {
            info!("connect to {}", addr);
            let target = match &addr {
                WireAddress::DomainAddress(domain, port) => {
                    TcpStream::connect((domain.as_str(), *port)).await
                }
                WireAddress::SocketAddress(socket_addr) => TcpStream::connect(socket_addr).await,
            };

            match target {
                Ok(mut target_stream) => {
                    let mut conn = connect
                        .reply(Reply::Succeeded, WireAddress::unspecified())
                        .await?;
                    info!("established connection to {}", addr);
                    io::copy_bidirectional(&mut target_stream, &mut conn).await?;
                }
                Err(err) => {
                    warn!("failed to connect to {}: {}", addr, err);
                    let mut conn = connect
                        .reply(Reply::HostUnreachable, WireAddress::unspecified())
                        .await?;
                    conn.shutdown().await?;
                }
            }
        }
    }

    Ok(())
}

/// Accept loop for the `sp up` daemon socket.
///
/// Always accepts new connections and serves each in its own handler task.
/// The shared `UpDaemonState` is passed as `Arc<ArcSwap<…>>` so handlers can
/// do lock-free load/store updates without a mutex.
async fn run_up_daemon(
    profile: &str,
    ns_meta: PathBuf,
    keeper_pid: u32,
    control_socket: Option<PathBuf>,
    simulate_protocol_no_upgrade: bool,
    simulate_conn_close: bool,
    simulate_slow_shutdown: bool,
) -> Result<()> {
    enable_child_subreaper()?;

    let sock_path = diag::up_sock_path(profile);
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&sock_path);

    let listener = tokio::net::UnixListener::bind(&sock_path)?;
    std::fs::set_permissions(&sock_path, Permissions::from_mode(0o666))?;
    info!("up-daemon listening on {:?}", sock_path);

    // Initialise the global log broadcast so DiagTracingLayer can forward
    // tracing events from outside any serve scope to the connected UI client.
    diag::init_up_log_broadcast();

    let state: Arc<ArcSwap<UpDaemonState>> = Arc::new(ArcSwap::new(Arc::new(UpDaemonState {
        process_list: diag::ProcessList {
            processes: BTreeMap::new(),
        },
        serve_pid: 0,
        personal_runtime_state: diag::personal::PersonalRuntimeState::default(),
    })));

    // Shared per-process stdout/stderr ring buffer.
    let raw_logs: Arc<Mutex<BTreeMap<u32, RawLogRingState>>> =
        Arc::new(Mutex::new(BTreeMap::new()));
    // Shared PTY byte scrollback ring per process.
    let pty_scrollback: Arc<Mutex<BTreeMap<u32, PtyScrollbackState>>> =
        Arc::new(Mutex::new(BTreeMap::new()));
    // PTY master fd per task for input/resize control.
    let pty_masters: Arc<Mutex<BTreeMap<u32, OwnedFd>>> = Arc::new(Mutex::new(BTreeMap::new()));
    // PTY output broadcast channels keyed by task pgid.
    let pty_streams: Arc<Mutex<BTreeMap<u32, tokio::sync::broadcast::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(BTreeMap::new()));
    // Daemon-level broadcast for task-group exit notifications.
    let (exit_broadcast_tx, _) = tokio::sync::broadcast::channel::<u32>(64);
    let exit_broadcast_tx: Arc<tokio::sync::broadcast::Sender<u32>> = Arc::new(exit_broadcast_tx);
    {
        let state = state.clone();
        let exit_broadcast_tx = Arc::clone(&exit_broadcast_tx);
        tokio::spawn(nsproxy_common::trace_spawn_result(
            "up daemon sigchld watcher",
            async move {
                let mut sigchld =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())?;
                while sigchld.recv().await.is_some() {
                    let exited = reap_dead_task_groups_into_state(&state);
                    if !exited.is_empty() {
                        info!(count = exited.len(), task_pgids = ?exited, "sigchld reaped tasks");
                    }
                    for task_pgid in exited {
                        let _ = exit_broadcast_tx.send(task_pgid);
                    }
                }
                warn!("up daemon sigchld watcher exiting after signal stream closed");
                Ok::<(), anyhow::Error>(())
            },
        ));
    }

    // If the UI passed a control socket path, connect to it immediately and serve it
    // as a reversed-role client.  This is event-triggered: the UI doesn't need to
    // poll our socket; we initiate the connection and it receives DaemonEvent frames
    // just as if it had connected to us.
    if simulate_conn_close {
        warn!(
            profile,
            "up daemon mock mode active: simulate_conn_close=true, skipping reversed control-socket connection"
        );
    } else if let Some(ref ctrl_path) = control_socket {
        let ctrl_path = ctrl_path.clone();
        let profile_name = profile.to_string();
        let state2 = state.clone();
        let ns_meta2 = ns_meta.clone();
        let log_rx2 = diag::subscribe_up_logs()
            .expect("up log broadcast must be initialised before control socket connect");
        let raw_logs2 = raw_logs.clone();
        let pty_scrollback2 = pty_scrollback.clone();
        let pty_masters2 = pty_masters.clone();
        let pty_streams2 = pty_streams.clone();
        let exit_broadcast2 = Arc::clone(&exit_broadcast_tx);
        tokio::spawn(nsproxy_common::trace_spawn_result(
            "up daemon reversed client",
            async move {
                match connect_and_greet_up(&ctrl_path, &profile_name).await {
                    Ok(stream) => {
                        info!(
                            "up daemon: connected to UI control socket, serving reversed connection"
                        );
                        handle_up_client(
                            stream,
                            profile_name.clone(),
                            state2,
                            ns_meta2,
                            keeper_pid,
                            simulate_protocol_no_upgrade,
                            simulate_slow_shutdown,
                            log_rx2,
                            raw_logs2,
                            pty_scrollback2,
                            pty_masters2,
                            pty_streams2,
                            exit_broadcast2,
                        )
                        .await?;
                        warn!("up daemon reversed client handler exited cleanly");
                    }
                    Err(e) => warn!(
                        "up daemon: failed to connect to control socket {:?}: {}",
                        ctrl_path, e
                    ),
                }
                Ok::<(), anyhow::Error>(())
            },
        ));
    }

    // On startup, check if the sandbox is already applied and dbus should run.
    // This covers both fresh start and restart of an already-sandboxed container.
    {
        let template_path = state_paths::profile_config(profile);
        let dbus_enabled = TemplateConfig::load(&template_path)
            .map(|t| t.dbus == nsproxy_core::DbusMode::Container)
            .unwrap_or(false);
        let sandbox_ready = read_sandbox_status(profile).is_some_and(|s| {
            s.detected_state == nsproxy_core::sandbox::SandboxState::Pivoted
                || s.configured_mode == SandboxMode::Overlay
        });
        if dbus_enabled && sandbox_ready {
            info!(
                profile,
                "sp up startup: sandbox ready and dbus enabled, spawning sp dbus"
            );
            let template = TemplateConfig::load(&state_paths::profile_config(profile))?;
            if template.dbus == nsproxy_core::DbusMode::Container {
                let cli = Cli {
                    conf: None,
                    root: None,
                    no_wrap_check: false,
                    control_socket: None,
                    cmd: MainCommand::Dbus {
                        profile: profile.to_string(),
                    },
                };
                let cli_bytes = bincode::serialize(&cli)?;
                let ns_alive = read_ns_alive(&ns_meta)?;
                let sandbox_status = read_sandbox_status(&profile)
                    .ok_or_else(|| anyhow!("no valid sandbox status for '{}'", profile))?;
                if let Some((task_pgid, stdout_r, stderr_r)) = spawn_cli_process(
                    &cli,
                    &ns_alive,
                    &sandbox_status,
                    diag::NamespaceSpawn::Outside,
                )? {
                    let mut new = (*state.load_full()).clone();
                    new.process_list.processes.insert(
                        task_pgid,
                        diag::ProcessEntry {
                            meta: diag::SpawnedEntry::Cli(diag::SpawnCliType {
                                cli_bincode: cli_bytes,
                                kind: diag::SpawnCliKind::Dbus,
                            }),
                            spawned_at: SystemTime::now(),
                            task_pgid,
                            status: diag::ProcessStatus::Alive,
                        },
                    );
                    state.store(Arc::new(new));
                    spawn_pipe_reader(
                        task_pgid,
                        diag::RawLogKind::Stdout,
                        stdout_r,
                        raw_logs.clone(),
                        diag::RAW_LOG_RING_CAP,
                    );
                    spawn_pipe_reader(
                        task_pgid,
                        diag::RawLogKind::Stderr,
                        stderr_r,
                        raw_logs.clone(),
                        diag::RAW_LOG_RING_CAP,
                    );
                } else {
                    reap_dead_task_groups_into_state(&state);
                }
            }
        }
    }

    loop {
        let (mut stream, _addr) = listener.accept().await?;

        if simulate_conn_close {
            warn!(
                profile,
                "up daemon mock mode: simulate_conn_close=true, dropping accepted connection"
            );
            continue;
        }

        if let Err(e) = diag::handshake_server(&mut stream, diag::ProtocolChannel::Up).await {
            warn!("up daemon handshake failed: {}", e);
            continue;
        }

        let state = state.clone();
        let ns_meta = ns_meta.clone();
        // Subscribe to the log broadcast for this new connection.
        let log_rx = diag::subscribe_up_logs()
            .expect("up log broadcast must be initialised before accept loop");
        let raw_logs_conn = raw_logs.clone();
        let pty_scrollback_conn = pty_scrollback.clone();
        let pty_masters_conn = pty_masters.clone();
        let pty_streams_conn = pty_streams.clone();
        let exit_broadcast_conn = Arc::clone(&exit_broadcast_tx);
        let profile_name = profile.to_string();
        tokio::spawn(nsproxy_common::trace_spawn_result(
            "up daemon accepted client",
            async move {
                handle_up_client(
                    stream,
                    profile_name,
                    state,
                    ns_meta,
                    keeper_pid,
                    simulate_protocol_no_upgrade,
                    simulate_slow_shutdown,
                    log_rx,
                    raw_logs_conn,
                    pty_scrollback_conn,
                    pty_masters_conn,
                    pty_streams_conn,
                    exit_broadcast_conn,
                )
                .await?;
                warn!("up daemon client handler exited cleanly");
                Ok::<(), anyhow::Error>(())
            },
        ));
    }
}

/// Spawn a blocking thread that reads lines from `fd` and appends them to the per-process
/// raw log ring buffer.  The thread exits automatically when the write end of the pipe is
/// closed (i.e. when the process exits).
fn spawn_pipe_reader(
    pid: u32,
    kind: diag::RawLogKind,
    fd: std::os::unix::io::RawFd,
    raw_logs: Arc<Mutex<BTreeMap<u32, RawLogRingState>>>,
    raw_log_cap: usize,
) {
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        use std::os::unix::io::FromRawFd;
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let reader = BufReader::new(file);
        for line in reader.lines() {
            match line {
                Ok(content) => {
                    let entry = diag::RawLog {
                        ts: diag::Timestamp::now(),
                        kind,
                        content,
                    };
                    if let Ok(mut guard) = raw_logs.lock() {
                        let state = guard
                            .entry(pid)
                            .or_insert_with(|| RawLogRingState::new(raw_log_cap));
                        if state.cap == 0 {
                            state.ring.clear();
                            state.next_seq = state.next_seq.saturating_add(1);
                            continue;
                        }
                        if state.ring.len() >= state.cap {
                            state.ring.pop_front();
                        }
                        state.ring.push_back(entry);
                        state.next_seq = state.next_seq.saturating_add(1);
                    }
                }
                Err(_) => break,
            }
        }
    });
}

fn ringbuf_cap_from_args(args: &diag::SpawnArgs, default_cap: usize) -> usize {
    args.ringbuf_size
        .map(|size| size as usize)
        .unwrap_or(default_cap)
}

fn append_pty_scrollback(state: &mut PtyScrollbackState, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    if state.cap == 0 {
        state.ring.clear();
        return;
    }
    if data.len() >= state.cap {
        state.ring.clear();
        state
            .ring
            .extend(data[data.len().saturating_sub(state.cap)..].iter().copied());
        return;
    }
    let overflow = state
        .ring
        .len()
        .saturating_add(data.len())
        .saturating_sub(state.cap);
    for _ in 0..overflow {
        state.ring.pop_front();
    }
    state.ring.extend(data.iter().copied());
}

fn signal_pty_foreground_process_group(fd: std::os::fd::RawFd) -> anyhow::Result<()> {
    let Some(pgid) = pty_foreground_process_group(fd)? else {
        return Ok(());
    };

    let rc = unsafe { libc::killpg(pgid as libc::pid_t, libc::SIGWINCH) };
    if rc == 0 {
        Ok(())
    } else {
        let err = std::io::Error::last_os_error();
        if err.kind() == ErrorKind::NotFound {
            Ok(())
        } else {
            Err(anyhow::anyhow!(err))
        }
    }
}

fn pty_foreground_process_group(fd: std::os::fd::RawFd) -> anyhow::Result<Option<u32>> {
    let mut pgid: libc::pid_t = 0;
    let rc = unsafe { libc::ioctl(fd, libc::TIOCGPGRP, &mut pgid) };
    if rc != 0 {
        return Err(anyhow::anyhow!(std::io::Error::last_os_error()));
    }
    if pgid <= 0 {
        return Ok(None);
    }

    Ok(Some(pgid as u32))
}

/// Scan `chunk` for DA1 (`ESC [ c` / `ESC [ 0 c`) and DA2 (`ESC [ > c` / `ESC [ > 0 c`)
/// terminal-capability query sequences sent by the child process. For each found, write
/// the appropriate response directly back to `file` (the PTY master fd is bidirectional).
/// Returns the chunk with those sequences removed, or `None` if no changes were needed.
/// Responding here avoids the UI round-trip latency that causes the delayed response to
/// arrive after fish has already moved on and prints the escape bytes as literal text.
fn intercept_terminal_queries(file: &mut std::fs::File, chunk: &[u8]) -> Option<Vec<u8>> {
    let mut out: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < chunk.len() {
        if chunk[i] == 0x1b && chunk.get(i + 1) == Some(&b'[') {
            // DA1: ESC [ c
            if chunk.get(i + 2) == Some(&b'c') {
                let _ = file.write_all(b"\x1b[?6c");
                out.get_or_insert_with(|| chunk[..i].to_vec());
                i += 3;
                continue;
            }
            // DA1: ESC [ 0 c
            if chunk.get(i + 2) == Some(&b'0') && chunk.get(i + 3) == Some(&b'c') {
                let _ = file.write_all(b"\x1b[?6c");
                out.get_or_insert_with(|| chunk[..i].to_vec());
                i += 4;
                continue;
            }
            // DA2: ESC [ > c
            if chunk.get(i + 2) == Some(&b'>') && chunk.get(i + 3) == Some(&b'c') {
                let _ = file.write_all(b"\x1b[>0;10;1c");
                out.get_or_insert_with(|| chunk[..i].to_vec());
                i += 4;
                continue;
            }
            // DA2: ESC [ > 0 c
            if chunk.get(i + 2) == Some(&b'>')
                && chunk.get(i + 3) == Some(&b'0')
                && chunk.get(i + 4) == Some(&b'c')
            {
                let _ = file.write_all(b"\x1b[>0;10;1c");
                out.get_or_insert_with(|| chunk[..i].to_vec());
                i += 5;
                continue;
            }
        }
        if let Some(ref mut v) = out {
            v.push(chunk[i]);
        }
        i += 1;
    }
    out
}

fn spawn_pty_relay(
    pid: u32,
    relay_fd: OwnedFd,
    pty_scrollback: Arc<Mutex<BTreeMap<u32, PtyScrollbackState>>>,
    pty_streams: Arc<Mutex<BTreeMap<u32, tokio::sync::broadcast::Sender<Vec<u8>>>>>,
) {
    std::thread::spawn(move || {
        let mut file = std::fs::File::from(relay_fd);
        let mut buf = [0_u8; 4096];
        loop {
            let n = match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let chunk = &buf[..n];

            // Respond to DA1/DA2 terminal queries immediately and strip them
            // from the broadcast so the UI doesn't generate a second, delayed response.
            let filtered = intercept_terminal_queries(&mut file, chunk);
            let broadcast_chunk: &[u8] = filtered.as_deref().unwrap_or(chunk);
            if broadcast_chunk.is_empty() {
                continue;
            }

            {
                let mut guard = pty_scrollback.lock().unwrap_or_else(|e| e.into_inner());
                let state = guard
                    .entry(pid)
                    .or_insert_with(|| PtyScrollbackState::new(PTY_SCROLLBACK_CAP));
                append_pty_scrollback(state, broadcast_chunk);
            }

            let tx_opt = {
                let guard = pty_streams.lock().unwrap_or_else(|e| e.into_inner());
                guard.get(&pid).cloned()
            };
            if let Some(tx) = tx_opt {
                let _ = tx.send(broadcast_chunk.to_vec());
            }
        }
    });
}

/// Per-connection handler for the `sp up` daemon.
async fn handle_up_client(
    stream: tokio::net::UnixStream,
    profile: String,
    state: Arc<ArcSwap<UpDaemonState>>,
    ns_meta: PathBuf,
    keeper_pid: u32,
    simulate_protocol_no_upgrade: bool,
    simulate_slow_shutdown: bool,
    mut log_rx: tokio::sync::broadcast::Receiver<Arc<Vec<u8>>>,
    raw_logs: Arc<Mutex<BTreeMap<u32, RawLogRingState>>>,
    pty_scrollback: Arc<Mutex<BTreeMap<u32, PtyScrollbackState>>>,
    pty_masters: Arc<Mutex<BTreeMap<u32, OwnedFd>>>,
    pty_streams: Arc<Mutex<BTreeMap<u32, tokio::sync::broadcast::Sender<Vec<u8>>>>>,
    exit_broadcast_tx: Arc<tokio::sync::broadcast::Sender<u32>>,
) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;
    let (mut read_half, mut write_half) = stream.into_split();
    let mut exit_rx = exit_broadcast_tx.subscribe();
    let (pty_evt_tx, mut pty_evt_rx) = tokio::sync::mpsc::unbounded_channel::<diag::DaemonEvent>();
    let mut attached_pty_tasks: HashMap<u32, tokio::task::JoinHandle<()>> = HashMap::new();
    loop {
        tokio::select! {
            req_result = read_bincode_frame_async::<diag::UpWireRequest, _>(&mut read_half) => {
                let Some(req) = req_result? else {
                    break;
                };

                // Reap before dispatching so that GetProcessList returns the freshest task state.
                reap_dead_task_groups_into_state(&state);

                let req = match req {
                    diag::UpWireRequest::Stable(stable_req) => {
                        warn!(req = ?stable_req, "up daemon: received stable request");
                        match stable_req {
                            diag::StableRequest::Ping => {
                                warn!("up daemon stable step: responding to ping");
                                let stable_evt = diag::StableEvent::Pong;
                                let _ = write_up_stable_frame(&mut write_half, &stable_evt).await;
                            }
                            diag::StableRequest::GracefulShutdown => {
                                warn!("up daemon stable step: graceful shutdown requested");
                                if simulate_slow_shutdown {
                                    warn!("up daemon mock mode: simulate_slow_shutdown=true, delaying graceful shutdown acknowledgement by 6s");
                                    sleep(Duration::from_secs(6)).await;
                                }
                                let stable_evt = diag::StableEvent::ShuttingDown;
                                let _ = write_up_stable_frame(&mut write_half, &stable_evt).await;
                                warn!("up daemon stable step: shutdown acknowledgement sent; stopping daemon");

                                if perform_up_daemon_stop(&state, keeper_pid).await {
                                    exit_with_warn(0, "up daemon stable shutdown completed");
                                }
                            }
                            diag::StableRequest::Upgrade { build_tree_hash } => {
                                warn!(
                                    remote_hash = %build_tree_hash,
                                    local_hash = %nsproxy_core::build_tree_hash(),
                                    "up daemon stable step: protocol upgrade requested"
                                );
                                if simulate_protocol_no_upgrade {
                                    warn!("up daemon mock mode: simulate_protocol_no_upgrade=true, forcing upgrade rejection");
                                    let stable_evt = diag::StableEvent::UpgradeRejected {
                                        msg: "simulated no-upgrade mode".to_string(),
                                    };
                                    write_up_stable_frame(&mut write_half, &stable_evt).await?;
                                    continue;
                                }
                                let local_hash = nsproxy_core::build_tree_hash();
                                if build_tree_hash == local_hash {
                                    warn!("up daemon stable step: upgrade accepted");
                                } else {
                                    warn!("up daemon stable step: upgrade accepted with hash mismatch; client decides whether to continue");
                                }
                                let stable_evt = diag::StableEvent::UpgradeAccepted {
                                    build_tree_hash: local_hash.to_string(),
                                };
                                write_up_stable_frame(&mut write_half, &stable_evt).await?;
                            }
                        }
                        continue;
                    }
                    diag::UpWireRequest::Unstable(req) => req,
                };

                match req {
                    diag::DaemonRequest::GetProcessList => {
                        let s = state.load();
                        let evt = diag::DaemonEvent::ProcessListSnapshot(diag::ProcessListSnapshot {
                            procs: s.process_list.processes.clone(),
                            serve: s.serve_pid,
                        });
                        write_up_unstable_frame(&mut write_half, &evt).await?;
                    }
                    diag::DaemonRequest::Personal(diag::personal::PersonalDaemonRequest::GetState) => {
                        let s = state.load();
                        let evt = diag::DaemonEvent::Personal(diag::personal::PersonalDaemonEvent::State(
                            s.personal_runtime_state.clone(),
                        ));
                        write_up_unstable_frame(&mut write_half, &evt).await?;
                    }
                    diag::DaemonRequest::Personal(diag::personal::PersonalDaemonRequest::SetState(personal_runtime_state)) => {
                        let mut new = (*state.load_full()).clone();
                        new.personal_runtime_state = personal_runtime_state.clone();
                        state.store(Arc::new(new));
                        let evt = diag::DaemonEvent::Personal(diag::personal::PersonalDaemonEvent::State(
                            personal_runtime_state,
                        ));
                        write_up_unstable_frame(&mut write_half, &evt).await?;
                    }
                    diag::DaemonRequest::EnsureDbus => {
                        let dbus_running = {
                            let s = state.load();
                            s.process_list.processes.iter().any(|(task_pgid, entry)| {
                                matches!(
                                    &entry.meta,
                                    diag::SpawnedEntry::Cli(diag::SpawnCliType {
                                        kind: diag::SpawnCliKind::Dbus,
                                        ..
                                    })
                                ) && matches!(entry.status, diag::ProcessStatus::Alive | diag::ProcessStatus::Terminating)
                                    && task_process_alive(*task_pgid, entry)
                            })
                        };

                        if !dbus_running {
                            let template = TemplateConfig::load(&state_paths::profile_config(&profile))?;
                            if template.dbus == nsproxy_core::DbusMode::Container {
                                let cli = Cli {
                                    conf: None,
                                    root: None,
                                    no_wrap_check: false,
                                    control_socket: None,
                                    cmd: MainCommand::Dbus {
                                        profile: profile.clone(),
                                    },
                                };
                                let cli_bytes = bincode::serialize(&cli)?;
                                let ns_alive = read_ns_alive(&ns_meta)?;
                                let sandbox_status = read_sandbox_status(&profile)
                                    .ok_or_else(|| anyhow!("no valid sandbox status for '{}'", profile))?;
                                let (task_pgid, stdout_r, stderr_r) = match spawn_cli_process(
                                    &cli,
                                    &ns_alive,
                                    &sandbox_status,
                                    diag::NamespaceSpawn::Outside,
                                )? {
                                    Some((task_pgid, stdout_r, stderr_r)) => {
                                        (task_pgid, stdout_r, stderr_r)
                                    }
                                    None => {
                                        reap_dead_task_groups_into_state(&state);
                                        continue;
                                    }
                                };

                                let mut new = (*state.load_full()).clone();
                                new.process_list.processes.insert(
                                    task_pgid,
                                    diag::ProcessEntry {
                                        meta: diag::SpawnedEntry::Cli(diag::SpawnCliType {
                                            cli_bincode: cli_bytes,
                                            kind: diag::SpawnCliKind::Dbus,
                                        }),
                                        spawned_at: SystemTime::now(),
                                        task_pgid,
                                        status: diag::ProcessStatus::Alive,
                                    },
                                );
                                state.store(Arc::new(new));

                                spawn_pipe_reader(
                                    task_pgid,
                                    diag::RawLogKind::Stdout,
                                    stdout_r,
                                    raw_logs.clone(),
                                    diag::RAW_LOG_RING_CAP,
                                );
                                spawn_pipe_reader(
                                    task_pgid,
                                    diag::RawLogKind::Stderr,
                                    stderr_r,
                                    raw_logs.clone(),
                                    diag::RAW_LOG_RING_CAP,
                                );

                                let spawned = diag::DaemonEvent::Spawned { task_pgid };
                                write_up_unstable_frame(&mut write_half, &spawned).await?;
                            }
                        }

                        let s = state.load();
                        let snapshot = diag::DaemonEvent::ProcessListSnapshot(diag::ProcessListSnapshot {
                            procs: s.process_list.processes.clone(),
                            serve: s.serve_pid,
                        });
                        write_up_unstable_frame(&mut write_half, &snapshot).await?;
                    }
                    diag::DaemonRequest::Kill { task_pgid } => {
                        let (target, pty_foreground_pgid) = {
                            let s = state.load();
                            let entry = s.process_list.processes.get(&task_pgid);
                            let pty_foreground_pgid = entry
                                .filter(|entry| matches!(entry.meta, diag::SpawnedEntry::Pty(_)))
                                .and_then(|_| {
                                    let guard = pty_masters.lock().unwrap_or_else(|e| e.into_inner());
                                    guard.get(&task_pgid).and_then(|fd| {
                                        match pty_foreground_process_group(fd.as_raw_fd()) {
                                            Ok(pgid) => pgid,
                                            Err(err) => {
                                                warn!(task_pgid, %err, "failed to read PTY foreground process group during kill");
                                                None
                                            }
                                        }
                                    })
                                });
                            (task_signal_target(task_pgid, entry), pty_foreground_pgid)
                        };
                        info!(
                            task_pgid,
                            target = target.as_raw(),
                            pty_foreground_pgid,
                            "task kill requested"
                        );
                        let _ = nix::sys::signal::kill(
                            target,
                            nix::sys::signal::Signal::SIGTERM,
                        );
                        if let Some(foreground_pgid) = pty_foreground_pgid.filter(|pgid| *pgid != task_pgid) {
                            let _ = nix::sys::signal::kill(
                                Pid::from_raw(-(foreground_pgid as i32)),
                                nix::sys::signal::Signal::SIGTERM,
                            );
                        }
                        let mut new = (*state.load_full()).clone();
                        if let Some(entry) = new.process_list.processes.get_mut(&task_pgid) {
                            entry.status = diag::ProcessStatus::Terminating;
                        }
                        state.store(Arc::new(new));
                        let s = state.load();
                        let evt = diag::DaemonEvent::ProcessListSnapshot(diag::ProcessListSnapshot {
                            procs: s.process_list.processes.clone(),
                            serve: s.serve_pid,
                        });
                        write_up_unstable_frame(&mut write_half, &evt).await?;
                    }
                    diag::DaemonRequest::Spawn { args } => {
                        let raw_log_cap = ringbuf_cap_from_args(&args, diag::RAW_LOG_RING_CAP);
                        let ns_alive = read_ns_alive(&ns_meta)?;
                        let sandbox_status = read_sandbox_status(profile.as_str())
                            .ok_or_else(|| anyhow!("no valid sandbox status for '{}'", profile))?;
                        let (child, stdout_r, stderr_r) = spawn_daemon_process(&args, &ns_alive, &sandbox_status)?;;
                        let task_pgid = match child {
                            Clone3Result::Parent { child_pid, .. } => child_pid as u32,
                            _ => {
                                let evt = diag::DaemonEvent::Error {
                                    msg: "spawn daemon in child context".to_string(),
                                };
                                write_up_unstable_frame(&mut write_half, &evt).await?;
                                reap_dead_task_groups_into_state(&state);
                                continue;
                            }
                        };
                        let mut new = (*state.load_full()).clone();
                        new.process_list.processes.insert(
                            task_pgid,
                            diag::ProcessEntry {
                                meta: diag::SpawnedEntry::Args(args),
                                spawned_at: SystemTime::now(),
                                task_pgid,
                                status: diag::ProcessStatus::Alive,
                            },
                        );
                        state.store(Arc::new(new));

                        spawn_pipe_reader(
                            task_pgid,
                            diag::RawLogKind::Stdout,
                            stdout_r,
                            raw_logs.clone(),
                            raw_log_cap,
                        );
                        spawn_pipe_reader(
                            task_pgid,
                            diag::RawLogKind::Stderr,
                            stderr_r,
                            raw_logs.clone(),
                            raw_log_cap,
                        );

                        let spawned = diag::DaemonEvent::Spawned { task_pgid };
                        write_up_unstable_frame(&mut write_half, &spawned).await?;
                        let s = state.load();
                        let snapshot = diag::DaemonEvent::ProcessListSnapshot(diag::ProcessListSnapshot {
                            procs: s.process_list.processes.clone(),
                            serve: s.serve_pid,
                        });
                        write_up_unstable_frame(&mut write_half, &snapshot).await?;
                    }
                    diag::DaemonRequest::SpawnCli { cli_bincode, ns } => {
                        let cli = match bincode::deserialize::<Cli>(&cli_bincode) {
                            Ok(cli) => cli,
                            Err(err) => {
                                let evt = diag::DaemonEvent::Error {
                                    msg: format!("invalid cli payload: {err}"),
                                };
                                write_up_unstable_frame(&mut write_half, &evt).await?;
                                reap_dead_task_groups_into_state(&state);
                                continue;
                            }
                        };
                        let kind = match &cli.cmd {
                            MainCommand::Serve { .. } => diag::SpawnCliKind::Serve,
                            MainCommand::Dbus { .. } => diag::SpawnCliKind::Dbus,
                            _ => diag::SpawnCliKind::Other,
                        };
                        let is_serve = matches!(kind, diag::SpawnCliKind::Serve);
                        let ns_alive = read_ns_alive(&ns_meta)?;
                        let sandbox_status = read_sandbox_status(profile.as_str())
                            .ok_or_else(|| anyhow!("no valid sandbox status for '{}'", profile))?;
                        let (task_pgid, stdout_r, stderr_r) =
                            match spawn_cli_process(&cli, &ns_alive, &sandbox_status, ns)? {
                            Some((task_pgid, stdout_r, stderr_r)) => (task_pgid, stdout_r, stderr_r),
                            None => {
                                reap_dead_task_groups_into_state(&state);
                                continue;
                            }
                        };
                        let cli_bytes = bincode::serialize(&cli)?;
                        let mut new = (*state.load_full()).clone();
                        new.process_list.processes.insert(
                            task_pgid,
                            diag::ProcessEntry {
                                meta: diag::SpawnedEntry::Cli(diag::SpawnCliType {
                                    cli_bincode: cli_bytes,
                                    kind,
                                }),
                                spawned_at: SystemTime::now(),
                                task_pgid,
                                status: diag::ProcessStatus::Alive,
                            },
                        );
                        if is_serve {
                            new.serve_pid = task_pgid;
                        }
                        state.store(Arc::new(new));

                        spawn_pipe_reader(
                            task_pgid,
                            diag::RawLogKind::Stdout,
                            stdout_r,
                            raw_logs.clone(),
                            diag::RAW_LOG_RING_CAP,
                        );
                        spawn_pipe_reader(
                            task_pgid,
                            diag::RawLogKind::Stderr,
                            stderr_r,
                            raw_logs.clone(),
                            diag::RAW_LOG_RING_CAP,
                        );

                        let spawned = diag::DaemonEvent::Spawned { task_pgid };
                        write_up_unstable_frame(&mut write_half, &spawned).await?;
                        let s = state.load();
                        let snapshot = diag::DaemonEvent::ProcessListSnapshot(diag::ProcessListSnapshot {
                            procs: s.process_list.processes.clone(),
                            serve: s.serve_pid,
                        });
                        write_up_unstable_frame(&mut write_half, &snapshot).await?;
                    }
                    diag::DaemonRequest::SpawnPty { args } => {
                        let ns_alive = read_ns_alive(&ns_meta)?;
                        let pty_scrollback_cap = ringbuf_cap_from_args(&args, PTY_SCROLLBACK_CAP);
                        let sandbox_status = read_sandbox_status(profile.as_str())
                            .ok_or_else(|| anyhow!("no valid sandbox status for '{}'", profile))?;
                        let (task_pgid, master_fd) = spawn_pty_process(&args, &ns_alive, &sandbox_status)?;
                        let relay_raw = unsafe { libc::dup(master_fd.as_raw_fd()) };
                        if relay_raw < 0 {
                            let evt = diag::DaemonEvent::Error {
                                msg: format!("dup PTY master failed: {}", std::io::Error::last_os_error()),
                            };
                            write_up_unstable_frame(&mut write_half, &evt).await?;
                            reap_dead_task_groups_into_state(&state);
                            continue;
                        }
                        let relay_fd = unsafe { OwnedFd::from_raw_fd(relay_raw) };

                        {
                            let mut guard = pty_masters.lock().unwrap_or_else(|e| e.into_inner());
                            guard.insert(task_pgid, master_fd);
                        }
                        {
                            let mut guard = pty_scrollback.lock().unwrap_or_else(|e| e.into_inner());
                            guard
                                .entry(task_pgid)
                                .or_insert_with(|| PtyScrollbackState::new(pty_scrollback_cap));
                        }
                        {
                            let mut guard = pty_streams.lock().unwrap_or_else(|e| e.into_inner());
                            guard
                                .entry(task_pgid)
                                .or_insert_with(|| tokio::sync::broadcast::channel(PTY_BROADCAST_CAP).0);
                        }

                        spawn_pty_relay(task_pgid, relay_fd, pty_scrollback.clone(), pty_streams.clone());

                        let mut new = (*state.load_full()).clone();
                        new.process_list.processes.insert(
                            task_pgid,
                            diag::ProcessEntry {
                                meta: diag::SpawnedEntry::Pty(args),
                                spawned_at: SystemTime::now(),
                                task_pgid,
                                status: diag::ProcessStatus::Alive,
                            },
                        );
                        state.store(Arc::new(new));

                        let spawned = diag::DaemonEvent::Spawned { task_pgid };
                        write_up_unstable_frame(&mut write_half, &spawned).await?;
                        let s = state.load();
                        let snapshot = diag::DaemonEvent::ProcessListSnapshot(diag::ProcessListSnapshot {
                            procs: s.process_list.processes.clone(),
                            serve: s.serve_pid,
                        });
                        write_up_unstable_frame(&mut write_half, &snapshot).await?;
                    }
                    diag::DaemonRequest::AttachPty { task_pgid } => {
                        let scrollback = {
                            let guard = pty_scrollback.lock().unwrap_or_else(|e| e.into_inner());
                            guard
                                .get(&task_pgid)
                                .map(|state| state.ring.iter().copied().collect::<Vec<u8>>())
                                .unwrap_or_default()
                        };
                        let evt = diag::DaemonEvent::PtyScrollback {
                            task_pgid,
                            data: scrollback,
                        };
                        write_up_unstable_frame(&mut write_half, &evt).await?;

                        let tx_opt = {
                            let guard = pty_streams.lock().unwrap_or_else(|e| e.into_inner());
                            guard.get(&task_pgid).cloned()
                        };
                        if let Some(tx) = tx_opt {
                            if let Some(old) = attached_pty_tasks.remove(&task_pgid) {
                                old.abort();
                            }
                            let mut rx = tx.subscribe();
                            let pty_evt_tx2 = pty_evt_tx.clone();
                            let task = tokio::spawn(async move {
                                loop {
                                    match rx.recv().await {
                                        Ok(data) => {
                                            let _ = pty_evt_tx2.send(diag::DaemonEvent::PtyOutput { task_pgid, data });
                                        }
                                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                                    }
                                }
                            });
                            attached_pty_tasks.insert(task_pgid, task);
                        }
                    }
                    diag::DaemonRequest::DetachPty { task_pgid } => {
                        if let Some(task) = attached_pty_tasks.remove(&task_pgid) {
                            task.abort();
                        }
                    }
                    diag::DaemonRequest::PtyInput { task_pgid, data } => {
                        let write_result = {
                            let guard = pty_masters.lock().unwrap_or_else(|e| e.into_inner());
                            guard
                                .get(&task_pgid)
                                .ok_or_else(|| anyhow!("pty task pgid {} not found", task_pgid))
                                .and_then(|fd| nix::unistd::write(fd.as_raw_fd(), &data).map(|_| ()).map_err(|e| anyhow!(e)))
                        };
                        if let Err(e) = write_result {
                            let evt = diag::DaemonEvent::Error {
                                msg: format!("pty input failed for task pgid {}: {}", task_pgid, e),
                            };
                            write_up_unstable_frame(&mut write_half, &evt).await?;
                        }
                    }
                    diag::DaemonRequest::PtyResize { task_pgid, cols, rows } => {
                        let (resize_result, refresh_result) = {
                            let guard = pty_masters.lock().unwrap_or_else(|e| e.into_inner());
                            if let Some(fd) = guard.get(&task_pgid) {
                                let ws = libc::winsize {
                                    ws_row: rows.max(1),
                                    ws_col: cols.max(1),
                                    ws_xpixel: 0,
                                    ws_ypixel: 0,
                                };
                                let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
                                if rc == 0 {
                                    (Ok(()), signal_pty_foreground_process_group(fd.as_raw_fd()))
                                } else {
                                    (Err(anyhow!(std::io::Error::last_os_error())), Ok(()))
                                }
                            } else {
                                (Err(anyhow!("pty task pgid {} not found", task_pgid)), Ok(()))
                            }
                        };
                        if let Err(e) = resize_result {
                            let evt = diag::DaemonEvent::Error {
                                msg: format!("pty resize failed for task pgid {}: {}", task_pgid, e),
                            };
                            write_up_unstable_frame(&mut write_half, &evt).await?;
                        } else if let Err(e) = refresh_result {
                            warn!(%e, task_pgid, "pty refresh signal failed after resize");
                        }
                    }
                    diag::DaemonRequest::Stop => {
                        if simulate_slow_shutdown {
                            warn!("up daemon mock mode: simulate_slow_shutdown=true, delaying stop response by 6s");
                            sleep(Duration::from_secs(6)).await;
                        }
                        let evt = diag::DaemonEvent::Stopping;
                        let _ = write_up_unstable_frame(&mut write_half, &evt).await;

                        if perform_up_daemon_stop(&state, keeper_pid).await {
                            exit_with_warn(0, "up daemon stop request completed");
                        }
                    }
                    diag::DaemonRequest::Ping => {
                        let evt = diag::DaemonEvent::Pong;
                        let _ = write_up_unstable_frame(&mut write_half, &evt).await;
                    }
                    diag::DaemonRequest::QueryRecentLogs { limit } => {
                        let entries = diag::query_recent_logs(limit);
                        let evt = diag::DaemonEvent::RecentLogs(entries);
                        write_up_unstable_frame(&mut write_half, &evt).await?;
                    }
                    diag::DaemonRequest::QueryRawLogs {
                        task_pgid,
                        limit,
                        after_seq,
                    } => {
                        let (reset, start_seq, next_seq, logs) = {
                            let guard = raw_logs.lock().unwrap_or_else(|e| e.into_inner());
                            guard.get(&task_pgid)
                                .map(|state| {
                                    let first_seq = state
                                        .next_seq
                                        .saturating_sub(state.ring.len() as u64);
                                    let reset = after_seq.is_none_or(|seq| {
                                        seq < first_seq || seq > state.next_seq
                                    });
                                    let start_seq = if reset {
                                        state.next_seq.saturating_sub(limit as u64).max(first_seq)
                                    } else {
                                        after_seq.unwrap_or(first_seq)
                                    };
                                    let skip = start_seq.saturating_sub(first_seq) as usize;
                                    let logs = state
                                        .ring
                                        .iter()
                                        .skip(skip)
                                        .cloned()
                                        .collect::<Vec<_>>();
                                    (reset, start_seq, state.next_seq, logs)
                                })
                                .unwrap_or((after_seq.is_none(), 0, 0, Vec::new()))
                        };
                        let evt = diag::DaemonEvent::RawLogs {
                            task_pgid,
                            reset,
                            start_seq,
                            next_seq,
                            logs,
                        };
                        write_up_unstable_frame(&mut write_half, &evt).await?;
                    }
                }

                let exited_task_pgids = reap_dead_task_groups_into_state(&state);
                emit_task_exit_updates(
                    &mut write_half,
                    &state,
                    &mut attached_pty_tasks,
                    &pty_masters,
                    &pty_streams,
                    exited_task_pgids,
                ).await?;
            }

            exited_task_pgid = exit_rx.recv() => {
                match exited_task_pgid {
                    Ok(task_pgid) => {
                        emit_task_exit_updates(
                            &mut write_half,
                            &state,
                            &mut attached_pty_tasks,
                            &pty_masters,
                            &pty_streams,
                            std::iter::once(task_pgid),
                        ).await?;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("task-exit broadcast lagged by {}, sending full snapshot", n);
                        let s = state.load();
                        let snapshot = diag::DaemonEvent::ProcessListSnapshot(diag::ProcessListSnapshot {
                            procs: s.process_list.processes.clone(),
                            serve: s.serve_pid,
                        });
                        write_up_unstable_frame(&mut write_half, &snapshot).await?;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }

            pty_evt = pty_evt_rx.recv() => {
                if let Some(evt) = pty_evt {
                    write_up_unstable_frame(&mut write_half, &evt).await?;
                }
            }

            log_result = log_rx.recv() => {
                match log_result {
                    Ok(frame) => {
                        write_half.write_all(&frame).await?;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("up daemon log channel lagged, dropped {} log frames", n);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
    Ok(())
}

fn enable_child_subreaper() -> Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(anyhow!(
            "failed to enable child subreaper: {}",
            std::io::Error::last_os_error()
        ));
    }

    info!("child subreaper enabled");
    Ok(())
}

async fn write_up_stable_frame<W: tokio::io::AsyncWriteExt + Unpin>(
    stream: &mut W,
    evt: &diag::StableEvent,
) -> Result<()> {
    write_bincode_frame_async(stream, &diag::UpWireEvent::Stable(evt.clone())).await
}

async fn write_up_unstable_frame<W: tokio::io::AsyncWriteExt + Unpin>(
    stream: &mut W,
    evt: &diag::DaemonEvent,
) -> Result<()> {
    write_bincode_frame_async(stream, &diag::UpWireEvent::Unstable(evt.clone())).await
}

async fn emit_task_exit_updates<W: tokio::io::AsyncWriteExt + Unpin>(
    write_half: &mut W,
    state: &Arc<ArcSwap<UpDaemonState>>,
    attached_pty_tasks: &mut HashMap<u32, tokio::task::JoinHandle<()>>,
    pty_masters: &Arc<Mutex<BTreeMap<u32, OwnedFd>>>,
    pty_streams: &Arc<Mutex<BTreeMap<u32, tokio::sync::broadcast::Sender<Vec<u8>>>>>,
    exited_task_pgids: impl IntoIterator<Item = u32>,
) -> Result<()> {
    let mut emitted = false;
    let mut personal_changed = false;
    for task_pgid in exited_task_pgids {
        emitted = true;
        info!(task_pgid, "emitting task exit");
        if let Some(task) = attached_pty_tasks.remove(&task_pgid) {
            task.abort();
        }
        {
            let mut guard = pty_masters.lock().unwrap_or_else(|e| e.into_inner());
            guard.remove(&task_pgid);
        }
        {
            let mut guard = pty_streams.lock().unwrap_or_else(|e| e.into_inner());
            guard.remove(&task_pgid);
        }
        let exit_evt = diag::DaemonEvent::ProcessExit { task_pgid };
        write_up_unstable_frame(write_half, &exit_evt).await?;

        let mut new = (*state.load_full()).clone();
        if new.personal_runtime_state.llamacpp_task_pgid == Some(task_pgid) {
            new.personal_runtime_state.llamacpp_task_pgid = None;
            personal_changed = true;
        }
        if new.personal_runtime_state.cinny_task_pgid == Some(task_pgid) {
            new.personal_runtime_state.cinny_task_pgid = None;
            personal_changed = true;
        }
        state.store(Arc::new(new));
    }

    if personal_changed {
        let s = state.load();
        let evt = diag::DaemonEvent::Personal(diag::personal::PersonalDaemonEvent::State(
            s.personal_runtime_state.clone(),
        ));
        write_up_unstable_frame(write_half, &evt).await?;
    }

    if emitted {
        let s = state.load();
        let snapshot = diag::DaemonEvent::ProcessListSnapshot(diag::ProcessListSnapshot {
            procs: s.process_list.processes.clone(),
            serve: s.serve_pid,
        });
        write_up_unstable_frame(write_half, &snapshot).await?;
    }

    Ok(())
}

fn task_signal_target(task_pgid: u32, entry: Option<&diag::ProcessEntry>) -> Pid {
    let task_pgid = entry.map(|entry| entry.task_pgid).unwrap_or(task_pgid);
    Pid::from_raw(-(task_pgid as i32))
}

fn task_process_alive(task_pgid: u32, entry: &diag::ProcessEntry) -> bool {
    let target = task_signal_target(task_pgid, Some(entry)).as_raw() as libc::pid_t;
    let rc = unsafe { libc::kill(target, 0) };
    rc == 0 || nix::errno::Errno::last() == nix::errno::Errno::EPERM
}

async fn perform_up_daemon_stop(state: &Arc<ArcSwap<UpDaemonState>>, keeper_pid: u32) -> bool {
    warn!(keeper_pid, "up daemon stop: begin stop sequence");
    {
        let s = state.load();
        // serve is tracked in process_list.processes under its PID,
        // so .keys() already covers it — no extra chain needed.
        for (&task_pgid, entry) in s.process_list.processes.iter() {
            warn!(task_pgid, "up daemon stop: sending SIGTERM to task group");
            let _ = nix::sys::signal::kill(
                task_signal_target(task_pgid, Some(entry)),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
    }

    warn!(
        keeper_pid,
        "up daemon stop: waiting for keeper process exit"
    );
    let keeper_dead = kill_and_wait_for_exit_async(keeper_pid, Duration::from_secs(5)).await;

    if !keeper_dead {
        warn!("keeper pid {} did not exit within 5 seconds", keeper_pid);
        reap_dead_task_groups_into_state(state);
        return false;
    }

    warn!("up daemon stop: keeper exited; waiting for managed child processes");
    reap_dead_task_groups_into_state(state);
    wait_all_children_async(state, Duration::from_secs(5)).await;
    if any_child_alive(state) {
        warn!(
            "up daemon stop: keeper is dead but children still alive; keeping socket loop running"
        );
        return false;
    }

    warn!("up daemon stop: keeper dead and no child processes alive; exiting daemon");
    true
}

/// Returns true if any tracked task group still has living processes.
/// Killed tasks are ignored; they remain in the process table
/// for history but are known dead.
fn any_child_alive(state: &Arc<ArcSwap<UpDaemonState>>) -> bool {
    let s = state.load();
    s.process_list
        .processes
        .iter()
        .filter(|(_, e)| !matches!(e.status, diag::ProcessStatus::Killed))
        .any(|(&task_pgid, entry)| task_process_alive(task_pgid, entry))
}

fn reap_dead_task_groups_into_state(state: &Arc<ArcSwap<UpDaemonState>>) -> Vec<u32> {
    let tracked_task_pgids: Vec<u32> = {
        let snapshot = state.load();
        snapshot
            .process_list
            .processes
            .iter()
            .filter(|(_, entry)| !matches!(entry.status, diag::ProcessStatus::Killed))
            .map(|(&task_pgid, _)| task_pgid)
            .collect()
    };

    if tracked_task_pgids.is_empty() {
        return Vec::new();
    }

    let mut new = (*state.load_full()).clone();
    let mut exited_task_pgids = Vec::new();
    let mut changed = false;

    for task_pgid in tracked_task_pgids {
        loop {
            match nix::sys::wait::waitpid(
                Pid::from_raw(-(task_pgid as i32)),
                Some(nix::sys::wait::WaitPidFlag::WNOHANG),
            ) {
                Ok(nix::sys::wait::WaitStatus::Exited(_, _))
                | Ok(nix::sys::wait::WaitStatus::Signaled(_, _, _)) => {}
                Ok(nix::sys::wait::WaitStatus::StillAlive)
                | Err(nix::errno::Errno::ECHILD)
                | Err(nix::errno::Errno::ESRCH) => break,
                Ok(_) => break,
                Err(err) => {
                    warn!(task_pgid, %err, "waitpid on task group failed during reap");
                    break;
                }
            }
        }

        let alive = new
            .process_list
            .processes
            .get(&task_pgid)
            .is_some_and(|entry| task_process_alive(task_pgid, entry));
        if !alive {
            if let Some(entry) = new.process_list.processes.get_mut(&task_pgid) {
                if !matches!(entry.status, diag::ProcessStatus::Killed) {
                    info!(task_pgid, previous_status = ?entry.status, "task marked killed");
                    entry.status = diag::ProcessStatus::Killed;
                    exited_task_pgids.push(task_pgid);
                    changed = true;
                }
            }
            if new.serve_pid == task_pgid {
                new.serve_pid = 0;
                changed = true;
            }
        }
    }

    if changed {
        state.store(Arc::new(new));
    }

    exited_task_pgids
}

fn spawn_cli_process(
    cli: &Cli,
    ns_alive: &nsproxy_core::NsAlive,
    sandbox_status: &nsproxy_core::sandbox::SandboxStatus,
    ns: diag::NamespaceSpawn,
) -> Result<Option<(u32, std::os::unix::io::RawFd, std::os::unix::io::RawFd)>> {
    let exe = std::env::current_exe()?;
    let fd_file = cli_to_inheritable_fd(cli)?;
    let fd = fd_file.as_raw_fd();

    let (stdout_r, stdout_w) = pipe()?;
    let (stderr_r, stderr_w) = pipe()?;

    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            let _ = nix::unistd::close(stdout_w);
            let _ = nix::unistd::close(stderr_w);
            Ok(Some((child.as_raw() as u32, stdout_r, stderr_r)))
        }
        ForkResult::Child => {
            let _ = nix::unistd::close(stdout_r);
            let _ = nix::unistd::close(stderr_r);
            let _ = dup2(stdout_w, 1);
            let _ = dup2(stderr_w, 2);
            let _ = nix::unistd::close(stdout_w);
            let _ = nix::unistd::close(stderr_w);
            let _ = setpgid(Pid::from_raw(0), Pid::from_raw(0));

            if matches!(ns, diag::NamespaceSpawn::Inside) {
                enter_ns_sandboxed(ns_alive, sandbox_status, &ns_alive.bind_mount)?;
            }

            let dbus_session_address = if matches!(ns, diag::NamespaceSpawn::Inside) {
                maybe_session_bus_address(ns_alive)
            } else {
                None
            };
            let dbus_system_address = if matches!(ns, diag::NamespaceSpawn::Inside) {
                maybe_system_bus_address(ns_alive)
            } else {
                None
            };

            let fd_str = fd.to_string();
            let exe_s = exe.to_string_lossy();
            let argv = [to_cstr(exe_s.as_ref()), to_cstr(&fd_str)];
            let envs = build_spawn_env_cstrings(
                ns_alive,
                dbus_session_address.as_deref(),
                dbus_system_address.as_deref(),
            )?;

            let _ = execve(&to_cstr(exe_s.as_ref()), &argv, &envs);
            exit_with_warn(127, "cli memfd handoff exec failed in child");
        }
    }
}

/// Connect to the UI control socket, send a `ControlSocketGreeting::UpDaemon` frame,
/// and return the stream ready for `handle_up_client`.
async fn connect_and_greet_up(ctrl_path: &Path, profile: &str) -> Result<tokio::net::UnixStream> {
    let mut stream = tokio::net::UnixStream::connect(ctrl_path).await?;
    diag::control_handshake_client(&mut stream).await?;
    let greeting = diag::ControlSocketGreeting::UpDaemon {
        name: profile.to_string(),
    };
    let frame = diag::encode_control_greeting(&greeting)?;
    use tokio::io::AsyncWriteExt as _;
    stream.write_all(&frame).await?;
    Ok(stream)
}

/// Connect to the UI control socket, send a `ControlSocketGreeting::ServeDaemon` frame,
/// and return the stream ready to be handed to `DiagServer::add_reversed_client`.
async fn connect_and_greet_serve(
    ctrl_path: &Path,
    profile: &str,
) -> Result<tokio::net::UnixStream> {
    let mut stream = tokio::net::UnixStream::connect(ctrl_path).await?;
    diag::control_handshake_client(&mut stream).await?;
    let greeting = diag::ControlSocketGreeting::ServeDaemon {
        name: profile.to_string(),
    };
    let frame = diag::encode_control_greeting(&greeting)?;
    use tokio::io::AsyncWriteExt as _;
    stream.write_all(&frame).await?;
    Ok(stream)
}

async fn connect_and_greet_root_daemon(ctrl_path: &Path) -> Result<tokio::net::UnixStream> {
    let mut stream = tokio::net::UnixStream::connect(ctrl_path).await?;
    diag::control_handshake_client(&mut stream).await?;
    let frame = diag::encode_control_greeting(&diag::ControlSocketGreeting::RootDaemon)?;
    use tokio::io::AsyncWriteExt as _;
    stream.write_all(&frame).await?;
    Ok(stream)
}

fn ensure_daemon_path_allowed(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("daemon path must be absolute: {:?}", path);
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        bail!("daemon path must not contain '..': {:?}", path);
    }
    let root = state_paths::persist_root();
    if !path.starts_with(&root) {
        bail!("daemon path {:?} escapes persist root {:?}", path, root);
    }
    Ok(())
}

fn daemon_ok(
    op_id: u64,
    message: String,
    profile: Option<String>,
    path: Option<PathBuf>,
) -> diag::RootDaemonEvent {
    diag::RootDaemonEvent {
        op_id,
        result: diag::RootDaemonResult::Ok {
            message,
            profile,
            path,
        },
    }
}

fn daemon_err(
    op_id: u64,
    message: String,
    profile: Option<String>,
    path: Option<PathBuf>,
) -> diag::RootDaemonEvent {
    diag::RootDaemonEvent {
        op_id,
        result: diag::RootDaemonResult::Error {
            message,
            profile,
            path,
        },
    }
}

enum RootDaemonAction {
    Reply(diag::RootDaemonEvent),
    ReplyAndStop(diag::RootDaemonEvent),
}

fn root_daemon_op_name(op: &diag::RootDaemonOp) -> &'static str {
    match op {
        diag::RootDaemonOp::Ping => "ping",
        diag::RootDaemonOp::Stop => "stop",
        diag::RootDaemonOp::InitializeBasisNamespace => "initialize_basis_namespace",
        diag::RootDaemonOp::CreateDirAll { .. } => "create_dir_all",
        diag::RootDaemonOp::ReadFile { .. } => "read_file",
        diag::RootDaemonOp::WriteFile { .. } => "write_file",
        diag::RootDaemonOp::CreateProfile { .. } => "create_profile",
    }
}

/// Create missing mount sources declared by a newly-created profile.
///
/// Both CLI and root-daemon profile creation call this so UI-created profiles
/// receive the same initialized `@` source tree as CLI-created profiles.
fn create_profile_mount_sources(profile: &TemplateConfig) -> Result<()> {
    info!("Determining ownership for created mount source directories...");
    let (owner_uid, owner_gid) = if let Some(uid) = profile.sargs.uid {
        let gid = profile.sargs.gid.unwrap_or_else(|| {
            uzers::get_user_by_uid(uid)
                .map(|user| user.primary_group_id())
                .unwrap_or(uid)
        });
        (uid, gid)
    } else {
        let uid = if let Ok(id) = std::env::var(nsproxy_common::UID_HINT_VAR) {
            id.parse()?
        } else if let Ok(id) = std::env::var("SUDO_UID") {
            id.parse()?
        } else {
            let res = nix::unistd::getresuid()?;
            if !res.real.is_root() {
                res.real.as_raw()
            } else {
                1000 // Preserve the legacy CLI profile-create fallback.
            }
        };
        let gid = uzers::get_user_by_uid(uid)
            .map(|user| user.primary_group_id())
            .unwrap_or(uid);
        (uid, gid)
    };
    info!("Using ownership: uid={}, gid={}", owner_uid, owner_gid);

    info!("Creating missing mount source directories...");
    for mount in &profile.mounts {
        if !mount.source.exists() {
            info!("  Creating: {:?}", mount.source);
            std::fs::create_dir_all(&mount.source)?;
            nix::unistd::chown(
                &mount.source,
                Some(nix::unistd::Uid::from_raw(owner_uid)),
                Some(nix::unistd::Gid::from_raw(owner_gid)),
            )?;
            info!("  Set ownership to uid={}, gid={}", owner_uid, owner_gid);
        } else {
            info!("  Mount source exists: {:?}", mount.source);
        }
    }

    Ok(())
}

fn handle_root_daemon_request(req: diag::RootDaemonRequest) -> RootDaemonAction {
    let op_id = req.op_id;
    let op_name = root_daemon_op_name(&req.op);
    match &req.op {
        diag::RootDaemonOp::Ping => {
            info!(op_id, op = op_name, "root daemon op received");
        }
        diag::RootDaemonOp::Stop => {
            info!(op_id, op = op_name, "root daemon op received");
        }
        diag::RootDaemonOp::InitializeBasisNamespace => {
            info!(op_id, op = op_name, "root daemon op received");
        }
        diag::RootDaemonOp::CreateDirAll { path } => {
            info!(op_id, op = op_name, path = %path.display(), "root daemon op received");
        }
        diag::RootDaemonOp::ReadFile { path } => {
            info!(op_id, op = op_name, path = %path.display(), "root daemon op received");
        }
        diag::RootDaemonOp::WriteFile {
            path,
            create_parent,
            ..
        } => {
            info!(
                op_id,
                op = op_name,
                path = %path.display(),
                create_parent,
                "root daemon op received"
            );
        }
        diag::RootDaemonOp::CreateProfile { name, .. } => {
            info!(op_id, op = op_name, profile = %name, "root daemon op received");
        }
    }
    match req.op {
        diag::RootDaemonOp::Ping => {
            info!(
                op_id,
                op = op_name,
                build_tree_hash = nsproxy_core::build_tree_hash(),
                "root daemon op completed"
            );
            RootDaemonAction::Reply(diag::RootDaemonEvent {
                op_id,
                result: diag::RootDaemonResult::Pong {
                    version: nsproxy_core::build_tree_hash().to_string(),
                },
            })
        }
        diag::RootDaemonOp::Stop => {
            info!(
                op_id,
                op = op_name,
                build_tree_hash = nsproxy_core::build_tree_hash(),
                "root daemon op completed"
            );
            RootDaemonAction::ReplyAndStop(daemon_ok(
                op_id,
                format!("stopping sp daemon {}", nsproxy_core::build_tree_hash()),
                None,
                None,
            ))
        }
        diag::RootDaemonOp::InitializeBasisNamespace => RootDaemonAction::Reply(
            match initialize_basis_namespace(false) {
                Ok(init) => diag::RootDaemonEvent {
                    op_id,
                    result: diag::RootDaemonResult::NamespaceInitialized {
                        current: init.current,
                        basis_ns: init.basis_ns,
                        initialized: init.initialized,
                    },
                },
                Err(err) => daemon_err(op_id, err.to_string(), None, None),
            },
        ),
        diag::RootDaemonOp::CreateDirAll { path } => RootDaemonAction::Reply(
            match ensure_daemon_path_allowed(&path)
                .and_then(|_| std::fs::create_dir_all(&path).map_err(anyhow::Error::from))
            {
                Ok(()) => {
                    info!(op_id, op = op_name, path = %path.display(), "root daemon op completed");
                    daemon_ok(
                        op_id,
                        format!("created {}", path.display()),
                        None,
                        Some(path),
                    )
                }
                Err(err) => {
                    warn!(op_id, op = op_name, path = %path.display(), error = %err, "root daemon op failed");
                    daemon_err(op_id, err.to_string(), None, Some(path))
                }
            },
        ),
        diag::RootDaemonOp::ReadFile { path } => RootDaemonAction::Reply(
            match ensure_daemon_path_allowed(&path)
                .and_then(|_| std::fs::read_to_string(&path).map_err(anyhow::Error::from))
            {
                Ok(content) => {
                    info!(op_id, op = op_name, path = %path.display(), "root daemon op completed");
                    diag::RootDaemonEvent {
                        op_id,
                        result: diag::RootDaemonResult::ReadFile { content, path },
                    }
                }
                Err(err) => {
                    warn!(op_id, op = op_name, path = %path.display(), error = %err, "root daemon op failed");
                    daemon_err(op_id, err.to_string(), None, Some(path))
                }
            },
        ),
        diag::RootDaemonOp::WriteFile {
            path,
            content,
            create_parent,
        } => {
            let result = (|| -> Result<()> {
                ensure_daemon_path_allowed(&path)?;
                if create_parent {
                    if let Some(parent) = path.parent() {
                        ensure_daemon_path_allowed(parent)?;
                        std::fs::create_dir_all(parent)?;
                    }
                }
                nsproxy_core::write_file_atomic(&path, &content)?;
                Ok(())
            })();
            RootDaemonAction::Reply(match result {
                Ok(()) => {
                    info!(op_id, op = op_name, path = %path.display(), "root daemon op completed");
                    daemon_ok(op_id, format!("wrote {}", path.display()), None, Some(path))
                }
                Err(err) => {
                    warn!(op_id, op = op_name, path = %path.display(), error = %err, "root daemon op failed");
                    daemon_err(op_id, err.to_string(), None, Some(path))
                }
            })
        }
        diag::RootDaemonOp::CreateProfile {
            name,
            profile_content,
            hot_content,
        } => {
            let profile = name.clone();
            let result = (|| -> Result<()> {
                if profile.is_empty() || profile.contains('/') {
                    bail!("invalid profile name: {}", profile);
                }
                let profile_dir = state_paths::profile_dir(&profile);
                let profile_path = state_paths::profile_config(&profile);
                let hot_path = state_paths::hot_config(&profile);
                ensure_daemon_path_allowed(&profile_dir)?;
                ensure_daemon_path_allowed(&profile_path)?;
                ensure_daemon_path_allowed(&hot_path)?;
                if profile_dir.exists() {
                    bail!("profile '{}' already exists", profile);
                }
                let mut template: TemplateConfig = serde_json::from_str(&profile_content)?;
                template.validate()?;
                template.expand_placeholders(&profile_dir);
                std::fs::create_dir_all(&profile_dir)?;
                std::fs::write(&profile_path, profile_content.as_bytes())?;
                if let Some(hot_content) = hot_content {
                    std::fs::write(&hot_path, hot_content.as_bytes())?;
                }
                create_profile_mount_sources(&template)?;
                Ok(())
            })();
            RootDaemonAction::Reply(match result {
                Ok(()) => {
                    info!(op_id, op = op_name, profile = %profile, "root daemon op completed");
                    daemon_ok(
                        op_id,
                        format!("created profile {}", profile),
                        Some(profile),
                        None,
                    )
                }
                Err(err) => {
                    warn!(op_id, op = op_name, profile = %profile, error = %err, "root daemon op failed");
                    daemon_err(op_id, err.to_string(), Some(profile), None)
                }
            })
        }
    }
}

async fn handle_root_daemon_client(
    stream: tokio::net::UnixStream,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    mut log_rx: tokio::sync::broadcast::Receiver<Arc<Vec<u8>>>,
) -> Result<()> {
    let (mut read_half, mut write_half) = stream.into_split();
    let mut upgraded = false;
    loop {
        tokio::select! {
            req = read_bincode_frame_async::<diag::RootDaemonWireRequest, _>(&mut read_half) => {
                let Some(req) = req? else {
                    break;
                };
                match req {
                    diag::RootDaemonWireRequest::Stable(stable_req) => {
                        match stable_req {
                            diag::StableRequest::Ping => {
                                let stable_evt = diag::RootDaemonWireEvent::Stable(diag::StableEvent::Pong);
                                write_bincode_frame_async(&mut write_half, &stable_evt).await?;
                            }
                            diag::StableRequest::GracefulShutdown => {
                                let stable_evt = diag::RootDaemonWireEvent::Stable(diag::StableEvent::ShuttingDown);
                                write_bincode_frame_async(&mut write_half, &stable_evt).await?;
                                let _ = shutdown_tx.send(true);
                                break;
                            }
                            diag::StableRequest::Upgrade { build_tree_hash } => {
                                let local_hash = nsproxy_core::build_tree_hash();
                                upgraded = true;
                                let stable_evt = if build_tree_hash == local_hash {
                                    diag::RootDaemonWireEvent::Stable(diag::StableEvent::UpgradeAccepted {
                                        build_tree_hash: local_hash.to_string(),
                                    })
                                } else {
                                    warn!(
                                        local_hash = %local_hash,
                                        remote_hash = %build_tree_hash,
                                        "root daemon upgrade accepted with hash mismatch; client decides whether to continue"
                                    );
                                    diag::RootDaemonWireEvent::Stable(diag::StableEvent::UpgradeAccepted {
                                        build_tree_hash: local_hash.to_string(),
                                    })
                                };
                                write_bincode_frame_async(&mut write_half, &stable_evt).await?;
                            }
                        }
                    }
                    diag::RootDaemonWireRequest::Unstable(req) => {
                        if !upgraded {
                            let stable_evt = diag::RootDaemonWireEvent::Stable(diag::StableEvent::Error {
                                msg: "root daemon protocol upgrade required before requests".to_string(),
                            });
                            write_bincode_frame_async(&mut write_half, &stable_evt).await?;
                            continue;
                        }
                        match handle_root_daemon_request(req) {
                            RootDaemonAction::Reply(event) => {
                                write_bincode_frame_async(&mut write_half, &diag::RootDaemonWireEvent::Unstable(event)).await?;
                            }
                            RootDaemonAction::ReplyAndStop(event) => {
                                write_bincode_frame_async(&mut write_half, &diag::RootDaemonWireEvent::Unstable(event)).await?;
                                let _ = shutdown_tx.send(true);
                                break;
                            }
                        }
                    }
                    diag::RootDaemonWireRequest::QueryRecentLogs { limit } => {
                        let entries = diag::query_recent_logs(limit);
                        let evt = diag::RootDaemonWireEvent::RecentLogs(entries);
                        write_bincode_frame_async(&mut write_half, &evt).await?;
                    }
                }
            }
            log_result = log_rx.recv() => {
                match log_result {
                    Ok(frame) => write_half.write_all(&frame).await?,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(skipped, "root daemon log client lagged");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
    Ok(())
}

async fn run_root_daemon(control_socket: Option<PathBuf>) -> Result<()> {
    diag::init_root_daemon_log_broadcast();
    let sock_path = diag::root_daemon_sock_path();
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&sock_path);
    let listener = tokio::net::UnixListener::bind(&sock_path)?;
    std::fs::set_permissions(&sock_path, Permissions::from_mode(0o666))?;
    info!(sock = %sock_path.display(), "root daemon listening");
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    if let Some(ctrl_path) = control_socket {
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(nsproxy_common::trace_spawn_result(
            "root daemon reversed client",
            async move {
                match connect_and_greet_root_daemon(&ctrl_path).await {
                    Ok(stream) => {
                        let log_rx = diag::subscribe_root_daemon_logs()
                        .expect("root daemon log broadcast must be initialised before control socket connect");
                        handle_root_daemon_client(stream, shutdown_tx, log_rx).await?;
                        warn!("root daemon reversed client handler exited cleanly");
                    }
                    Err(err) => {
                        warn!(path = %ctrl_path.display(), error = %err, "root daemon failed to connect to UI control socket")
                    }
                }
                Ok::<(), anyhow::Error>(())
            },
        ));
    }

    loop {
        tokio::select! {
            res = listener.accept() => {
                let (mut stream, _) = res?;
                if let Err(err) = diag::handshake_server(&mut stream, diag::ProtocolChannel::Daemon).await {
                    warn!(error = %err, "root daemon handshake failed");
                    continue;
                }
                let shutdown_tx = shutdown_tx.clone();
                let log_rx = diag::subscribe_root_daemon_logs()
                    .expect("root daemon log broadcast must be initialised before accept loop");
                tokio::spawn(nsproxy_common::trace_spawn_result(
                    "root daemon accepted client",
                    async move {
                    handle_root_daemon_client(stream, shutdown_tx, log_rx).await?;
                    warn!("root daemon client handler exited cleanly");
                    Ok::<(), anyhow::Error>(())
                },
                ));
            }
            changed = shutdown_rx.changed() => {
                match changed {
                    Ok(()) if *shutdown_rx.borrow() => {
                        warn!(sock = %sock_path.display(), "root daemon stopping cooperatively");
                        break;
                    }
                    Ok(()) => {}
                    Err(_) => break,
                }
            }
        }
    }

    let _ = std::fs::remove_file(&sock_path);
    Ok(())
}

fn spawn_daemon_process(
    args: &diag::SpawnArgs,
    ns_alive: &nsproxy_core::NsAlive,
    sandbox_status: &nsproxy_core::sandbox::SandboxStatus,
) -> Result<(
    Clone3Result,
    std::os::unix::io::RawFd,
    std::os::unix::io::RawFd,
)> {
    let exec = args
        .exec
        .clone()
        .ok_or_else(|| anyhow!("spawn args missing exec"))?;
    let exec_resolved = if exec.contains('/') {
        exec.clone()
    } else {
        match which::which(exec.as_str()) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => exec.clone(),
        }
    };
    let cmd = std::ffi::CString::new(exec_resolved.as_str())?;

    let mut argv: Vec<std::ffi::CString> = if args.args.is_empty() {
        vec![std::ffi::CString::new(exec.as_str())?]
    } else {
        args.args
            .iter()
            .map(|a| std::ffi::CString::new(a.as_str()))
            .collect::<std::result::Result<Vec<_>, _>>()?
    };

    if argv.is_empty() {
        argv.push(std::ffi::CString::new(exec.as_str())?);
    }

    let (stdout_r, stdout_w) = pipe()?;
    let (stderr_r, stderr_w) = pipe()?;

    let clone = nsproxy_core::sys::clone3::<false>(false, false)?;
    match &clone {
        Clone3Result::IsChild { .. } => {
            let _ = nix::unistd::close(stdout_r);
            let _ = nix::unistd::close(stderr_r);
            let _ = dup2(stdout_w, 1);
            let _ = dup2(stderr_w, 2);
            let _ = nix::unistd::close(stdout_w);
            let _ = nix::unistd::close(stderr_w);
            let _ = setpgid(Pid::from_raw(0), Pid::from_raw(0));

            if matches!(args.ns, diag::NamespaceSpawn::Inside) {
                enter_ns_sandboxed(ns_alive, sandbox_status, &ns_alive.bind_mount)?;
            }

            let dbus_session_address = if matches!(args.ns, diag::NamespaceSpawn::Inside) {
                maybe_session_bus_address(ns_alive)
            } else {
                None
            };
            let dbus_system_address = if matches!(args.ns, diag::NamespaceSpawn::Inside) {
                maybe_system_bus_address(ns_alive)
            } else {
                None
            };
            let env_c = build_spawn_env_cstrings(
                ns_alive,
                dbus_session_address.as_deref(),
                dbus_system_address.as_deref(),
            )?;

            if !args.gids.is_empty() {
                setgroups(
                    &args
                        .gids
                        .iter()
                        .map(|g| Gid::from_raw(*g))
                        .collect::<Vec<_>>(),
                )?;
            }

            if let Some(gid) = args.gid {
                let g = Gid::from_raw(gid);
                setresgid(g, g, g)?;
            }

            if let Some(uid) = args.uid {
                let u = Uid::from_raw(uid);
                setresuid(u, u, u)?;
            }

            if let Some(cwd) = &args.cwd {
                chdir(cwd)?;
            }

            match execve(cmd.as_c_str(), &argv, &env_c) {
                Ok(_) => unreachable!(),
                Err(e) => {
                    error!("daemon spawn execve failed: {}", e);
                    exit_with_warn(127, "daemon spawn execve failed in child");
                }
            }
        }
        Clone3Result::Parent { .. } => {
            let _ = nix::unistd::close(stdout_w);
            let _ = nix::unistd::close(stderr_w);
        }
    }

    Ok((clone, stdout_r, stderr_r))
}

fn spawn_pty_process(
    args: &diag::SpawnArgs,
    ns_alive: &nsproxy_core::NsAlive,
    sandbox_status: &nsproxy_core::sandbox::SandboxStatus,
) -> Result<(u32, OwnedFd)> {
    let exec = args
        .exec
        .clone()
        .ok_or_else(|| anyhow!("spawn args missing exec"))?;
    let exec_resolved = if exec.contains('/') {
        exec.clone()
    } else {
        match which::which(exec.as_str()) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => exec.clone(),
        }
    };
    let cmd = std::ffi::CString::new(exec_resolved.as_str())?;

    let mut argv: Vec<std::ffi::CString> = if args.args.is_empty() {
        vec![std::ffi::CString::new(exec.as_str())?]
    } else {
        args.args
            .iter()
            .map(|a| std::ffi::CString::new(a.as_str()))
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    if argv.is_empty() {
        argv.push(std::ffi::CString::new(exec.as_str())?);
    }

    let pty = openpty(None, None)?;
    match unsafe { fork()? } {
        ForkResult::Parent { child } => Ok((child.as_raw() as u32, pty.master)),
        ForkResult::Child => {
            let slave_fd = pty.slave.as_raw_fd();
            let _ = setsid();
            let _ = unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) };
            let _ = dup2(slave_fd, 0);
            let _ = dup2(slave_fd, 1);
            let _ = dup2(slave_fd, 2);

            if matches!(args.ns, diag::NamespaceSpawn::Inside) {
                enter_ns_sandboxed(ns_alive, sandbox_status, &ns_alive.bind_mount)?;
            }

            let dbus_session_address = if matches!(args.ns, diag::NamespaceSpawn::Inside) {
                maybe_session_bus_address(ns_alive)
            } else {
                None
            };
            let dbus_system_address = if matches!(args.ns, diag::NamespaceSpawn::Inside) {
                maybe_system_bus_address(ns_alive)
            } else {
                None
            };
            let env_c = build_spawn_env_cstrings(
                ns_alive,
                dbus_session_address.as_deref(),
                dbus_system_address.as_deref(),
            )?;

            if !args.gids.is_empty() {
                setgroups(
                    &args
                        .gids
                        .iter()
                        .map(|g| Gid::from_raw(*g))
                        .collect::<Vec<_>>(),
                )?;
            }

            if let Some(gid) = args.gid {
                let g = Gid::from_raw(gid);
                setresgid(g, g, g)?;
            }

            if let Some(uid) = args.uid {
                let u = Uid::from_raw(uid);
                setresuid(u, u, u)?;
            }

            if let Some(cwd) = &args.cwd {
                chdir(cwd)?;
            }

            match execve(cmd.as_c_str(), &argv, &env_c) {
                Ok(_) => unreachable!(),
                Err(e) => {
                    error!("pty spawn execve failed: {}", e);
                    exit_with_warn(127, "pty spawn execve failed in child");
                }
            }
        }
    }
}

fn kill_and_wait_for_exit(pid: u32, timeout: Duration) -> bool {
    if pid == 0 {
        return false;
    }

    let target = Pid::from_raw(pid as i32);
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        if let Err(e) = nix::sys::signal::kill(target, nix::sys::signal::Signal::SIGKILL) {
            match e {
                nix::errno::Errno::ESRCH => {
                    info!("pid {} is gone (no such process)", pid);
                    return true;
                }
                _ => {
                    warn!("failed to send SIGKILL to pid {}: {}", pid, e);
                }
            }
        }

        match nix::sys::wait::waitpid(target, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
            Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                // still running
            }
            Ok(nix::sys::wait::WaitStatus::Exited(waited_pid, code)) => {
                if code == 0 {
                    warn!(
                        pid,
                        waited_pid = waited_pid.as_raw(),
                        code,
                        "pid reaped after intentional exit"
                    );
                } else {
                    warn!(
                        pid,
                        waited_pid = waited_pid.as_raw(),
                        code,
                        "pid reaped after nonzero exit"
                    );
                }
                return true;
            }
            Ok(nix::sys::wait::WaitStatus::Signaled(waited_pid, signal, dumped_core)) => {
                warn!(
                    pid,
                    waited_pid = waited_pid.as_raw(),
                    ?signal,
                    dumped_core,
                    "pid reaped after signal"
                );
                return true;
            }
            Ok(_) => {
                info!("pid {} ended", pid);
                return true;
            }
            Err(nix::errno::Errno::ECHILD) => {
                info!("pid {} ended (ECHILD)", pid);
                return true;
            }
            Err(nix::errno::Errno::ESRCH) => {
                info!("pid {} is gone (ESRCH)", pid);
                return true;
            }
            Err(e) => {
                warn!("waitpid for pid {} failed: {}", pid, e);
            }
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    false
}

fn configured_sandbox_root(profile: &str) -> Option<PathBuf> {
    let profile_path = state_paths::profile_config(profile);
    if !profile_path.exists() {
        return Some(state_paths::pivot_root(profile));
    }
    let conf = TemplateConfig::load(&profile_path)
        .map_err(|e| {
            warn!(
                "could not read profile config for rootfs path, skipping rootfs cleanup: {}",
                e
            )
        })
        .ok()?;
    Some(match conf.rootfs {
        Rootfs::Default => state_paths::pivot_root(profile),
        Rootfs::Tempfs => state_paths::pivot_root_mem(profile),
        Rootfs::Path(path) => path,
    })
}

fn request_graceful_up_shutdown(profile: &str) {
    let sock_path = diag::up_sock_path(profile);
    if !sock_path.exists() {
        return;
    }

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            warn!(
                profile,
                "failed to create runtime for up-daemon shutdown request: {}", err
            );
            return;
        }
    };

    if let Err(err) = rt.block_on(async {
        let mut stream = diag::connect_up_daemon_stable(&sock_path).await?;
        stream
            .send_stable_request(&diag::StableRequest::GracefulShutdown)
            .await?;
        match tokio::time::timeout(Duration::from_secs(5), stream.next_event()).await {
            Ok(Ok(Some(diag::UpWireEvent::Stable(diag::StableEvent::ShuttingDown))))
            | Ok(Ok(Some(diag::UpWireEvent::Unstable(diag::DaemonEvent::Stopping))))
            | Ok(Ok(None)) => Ok::<(), anyhow::Error>(()),
            Ok(Ok(Some(diag::UpWireEvent::Stable(diag::StableEvent::Error { msg })))) => {
                bail!("up daemon returned error on graceful shutdown: {}", msg)
            }
            Ok(Ok(Some(diag::UpWireEvent::Unstable(diag::DaemonEvent::Error { msg })))) => {
                bail!("up daemon returned error on graceful shutdown: {}", msg)
            }
            Ok(Ok(Some(other))) => {
                bail!("unexpected response from up daemon: {:?}", other)
            }
            Ok(Err(err)) => Err(err.into()),
            Err(_) => bail!("timed out waiting for graceful shutdown acknowledgement"),
        }
    }) {
        warn!(
            profile,
            "failed to request graceful up-daemon shutdown: {}", err
        );
    }
}

/// Detach the sandbox-owned mount targets created by [crate::sandbox::build_skeleton].
///
/// This intentionally targets only the top-level skeleton mounts (`/pivot`, `/proc`,
/// `/sys`, `/tmp`, `/run`) and does not recurse into mount targets under `/pivot`,
/// which belong to the old root after `pivot_root`.
fn cleanup_sandbox_mounts(ns_alive: &nsproxy_core::NsAlive, sandbox_root: &Path) -> Result<()> {
    let Some(child_pid) = ns_alive.child_pid else {
        return Ok(());
    };

    if !pid_is_alive(child_pid) || !sandbox_root.exists() {
        return Ok(());
    }

    match unsafe { fork()? } {
        ForkResult::Parent { child } => match nix::sys::wait::waitpid(child, None)? {
            nix::sys::wait::WaitStatus::Exited(_, 0) => Ok(()),
            nix::sys::wait::WaitStatus::Exited(_, code) => {
                bail!("sandbox cleanup helper exited with status {}", code)
            }
            nix::sys::wait::WaitStatus::Signaled(_, signal, _) => {
                bail!("sandbox cleanup helper terminated by signal {:?}", signal)
            }
            status => bail!("sandbox cleanup helper ended unexpectedly: {:?}", status),
        },
        ForkResult::Child => {
            let cleanup_targets = [
                Path::new("/pivot"),
                Path::new("/proc"),
                Path::new("/sys"),
                Path::new("/tmp"),
                Path::new("/run"),
            ];
            let exit_code = match enter_ns(ns_alive, &ns_alive.bind_mount).and_then(|_| {
                if sandbox_root.exists() {
                    umount_detach_targets(&cleanup_targets)
                } else {
                    Ok(())
                }
            }) {
                Ok(()) => 0,
                Err(err) => {
                    warn!(
                        "failed to clean sandbox-owned mounts for {:?}: {}",
                        sandbox_root, err
                    );
                    1
                }
            };
            if exit_code == 0 {
                exit_with_warn(0, "sandbox cleanup helper finished successfully");
            } else {
                exit_with_warn(
                    exit_code,
                    "sandbox cleanup helper finished with cleanup errors",
                );
            }
        }
    }
}

fn pid_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    PathBuf::from("/proc").join(pid.to_string()).exists()
}

fn sanitize_veth_label(label: &str) -> String {
    let mut sanitized: String = label
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect();
    if sanitized.is_empty() {
        sanitized.push_str("ns");
    }
    sanitized
}

fn veth_interface_name(base: &str, suffix: &str) -> String {
    const MAX_IFNAME_LEN: usize = 15;
    let suffix = format!("_{suffix}");
    let budget = MAX_IFNAME_LEN.saturating_sub(suffix.len());
    let trimmed = if base.len() > budget {
        &base[..budget]
    } else {
        base
    };
    format!("{trimmed}{suffix}")
}

fn resolve_veth_endpoint(arg: &NsArg) -> Result<VethEndpoint> {
    match arg {
        NsArg::This => Ok(VethEndpoint {
            arg: NsArg::This,
            label: "this".to_string(),
            target: VethNamespaceTarget::Pid(std::process::id()),
            source: NSSource::Pid(std::process::id() as i32),
        }),
        NsArg::Basis | NsArg::Container(_) => {
            let registry = NamespacesRegistry::load_locked()?;
            let (label, namespaces) = match arg {
                NsArg::Basis => ("basis".to_string(), registry.basis_ns.ok_or_else(|| {
                    anyhow!("basis namespace is not recorded; run 'sp init' first")
                })?),
                NsArg::Container(profile) => (
                    sanitize_veth_label(profile),
                    registry.profiles.get(profile).cloned().ok_or_else(|| {
                        anyhow!("namespace for profile {} is not recorded", profile)
                    })?,
                ),
                NsArg::This => unreachable!(),
            };
            let source = namespaces.net.source;
            let target = match &source {
                NSSource::Pid(pid) => VethNamespaceTarget::Pid(u32::try_from(*pid)
                    .map_err(|_| anyhow!("recorded {} namespace has invalid pid {}", label, pid))?),
                NSSource::Path(path) => {
                    VethNamespaceTarget::Fd(Arc::new(fs::File::open(path)?))
                }
                NSSource::Unavail(_) => {
                    bail!("recorded {} namespace has no usable process or namespace file", label)
                }
            };
            Ok(VethEndpoint {
                arg: arg.clone(),
                label,
                target,
                source,
            })
        }
    }
}

fn veth_endpoint_is_current(endpoint: &VethEndpoint) -> bool {
    matches!(&endpoint.target, VethNamespaceTarget::Pid(pid) if *pid == std::process::id())
}

fn run_in_netns_clone3_source<T, F>(source: NSSource, op: F) -> Result<T>
where
    T: Serialize + serde::de::DeserializeOwned,
    F: FnOnce() -> Result<T>,
{
    match nsproxy_core::sys::clone3::<false>(false, false) {
        Ok(Clone3Result::IsChild { mut tx }) => {
            let outcome = match (|| -> Result<T> {
                source.enter(CloneFlags::CLONE_NEWNET)?;
                op()
            })() {
                Ok(value) => NetnsChildResult::Ok(value),
                Err(err) => NetnsChildResult::Err(err.to_string()),
            };

            let payload = bincode::serialize(&outcome).expect("serialize netns child result");
            tx.write_all(&(payload.len() as u32).to_le_bytes())?;
            tx.write_all(&payload)?;
            exit_with_warn(0, "netns clone child sent result to parent");
        }
        Ok(Clone3Result::Parent {
            child_pid, mut tx, ..
        }) => {
            let mut len_buf = [0u8; 4];
            tx.read_exact(&mut len_buf)?;
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len];
            tx.read_exact(&mut payload)?;
            let _ = nix::sys::wait::waitpid(Pid::from_raw(child_pid), None);
            match bincode::deserialize::<NetnsChildResult<T>>(&payload)? {
                NetnsChildResult::Ok(value) => Ok(value),
                NetnsChildResult::Err(msg) => Err(anyhow!(msg)),
            }
        }
        Err(err) => Err(err),
    }
}

async fn fetch_ipv4_in_namespace(source: NSSource) -> Result<Vec<Ipv4Addr>> {
    if matches!(&source, NSSource::Pid(pid) if *pid == std::process::id() as i32) {
        let nl = tokio_netlink_conn()?;
        let addrs = nl.fetch_all_ip_addrs().await?;
        Ok(addrs
            .into_iter()
            .filter_map(|net| match net {
                IpNetwork::V4(v4) => Some(v4.ip()),
                _ => None,
            })
            .collect())
    } else {
        run_in_netns_clone3_source(source, move || {
            run_tokio_on_fresh_thread(move || async move {
                let nl = tokio_netlink_conn()?;
                let addrs = nl.fetch_all_ip_addrs().await?;
                Ok::<Vec<Ipv4Addr>, anyhow::Error>(
                    addrs
                        .into_iter()
                        .filter_map(|net| match net {
                            IpNetwork::V4(v4) => Some(v4.ip()),
                            _ => None,
                        })
                        .collect(),
                )
            })
        })
    }
}

async fn remove_link_if_exists_in_namespace(source: NSSource, name: &str) -> Result<()> {
    if matches!(&source, NSSource::Pid(pid) if *pid == std::process::id() as i32) {
        let nl = tokio_netlink_conn()?;
        nl.remove_link_if_exists(name).await
    } else {
        let name = name.to_string();
        run_in_netns_clone3_source(source, move || {
            run_tokio_on_fresh_thread(move || async move {
                let nl = tokio_netlink_conn()?;
                nl.remove_link_if_exists(&name).await?;
                Ok::<(), anyhow::Error>(())
            })
        })
    }
}

async fn configure_veth_endpoint(
    source: NSSource,
    if_name: String,
    ip: Ipv4Addr,
    prefix: u8,
) -> Result<()> {
    if matches!(&source, NSSource::Pid(pid) if *pid == std::process::id() as i32) {
        let nl = tokio_netlink_conn()?;
        nl.up_lo().await?;
        let dev = nl.fetch_link_by_name(if_name).await?;
        nl.address()
            .add(dev.header.index, ip.into(), prefix)
            .execute()
            .await?;
        nl.link()
            .set(
                LinkMessageBuilder::<LinkUnspec>::default()
                    .index(dev.header.index)
                    .up()
                    .build(),
            )
            .execute()
            .await?;
        Ok(())
    } else {
        run_in_netns_clone3_source(source, move || {
            run_tokio_on_fresh_thread(move || async move {
                let nl = tokio_netlink_conn()?;
                nl.up_lo().await?;
                let dev = nl.fetch_link_by_name(if_name).await?;
                nl.address()
                    .add(dev.header.index, ip.into(), prefix)
                    .execute()
                    .await?;
                nl.link()
                    .set(
                        LinkMessageBuilder::<LinkUnspec>::default()
                            .index(dev.header.index)
                            .up()
                            .build(),
                    )
                    .execute()
                    .await?;
                Ok::<(), anyhow::Error>(())
            })
        })
    }
}

fn run_tokio_on_fresh_thread<F, Fut, T>(make_future: F) -> Result<T>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T>> + Send + 'static,
    T: Send + 'static,
{
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(make_future())
    })
    .join()
    .map_err(|panic| {
        let msg = if let Some(s) = panic.downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = panic.downcast_ref::<String>() {
            s.clone()
        } else {
            "tokio helper thread panicked".to_string()
        };
        anyhow!(msg)
    })?
}

fn enter_all_profile_namespaces_of_pid(pid: u32) -> Result<()> {
    warn!(pid, "up preflight: entering mount namespace");
    let source = NSSource::Pid(pid as i32);
    source.enter(CloneFlags::CLONE_NEWNS)?;
    warn!(pid, "up preflight: entering network namespace");
    source.enter(CloneFlags::CLONE_NEWNET)?;
    warn!(pid, "up preflight: entering pid namespace");
    source.enter(CloneFlags::CLONE_NEWPID)?;
    warn!(pid, "up preflight: entered all target namespaces");
    Ok(())
}

async fn kill_and_wait_for_exit_async(task_pgid: u32, timeout: Duration) -> bool {
    if task_pgid == 0 {
        return false;
    }

    let target = Pid::from_raw(-(task_pgid as i32));
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        if let Err(e) = nix::sys::signal::kill(target, nix::sys::signal::Signal::SIGKILL) {
            match e {
                nix::errno::Errno::ESRCH => {
                    info!("task group {} is gone (no such process)", task_pgid);
                    return true;
                }
                _ => {
                    warn!("failed to send SIGKILL to task group {}: {}", task_pgid, e);
                }
            }
        }

        match nix::sys::wait::waitpid(target, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
            Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                // still running
            }
            Ok(nix::sys::wait::WaitStatus::Exited(waited_pid, code)) => {
                if unsafe { libc::kill(-(task_pgid as libc::pid_t), 0) } != 0
                    && nix::errno::Errno::last() == nix::errno::Errno::ESRCH
                {
                    if code == 0 {
                        warn!(
                            task_pgid,
                            waited_pid = waited_pid.as_raw(),
                            code,
                            "task group reaped after intentional exit"
                        );
                    } else {
                        warn!(
                            task_pgid,
                            waited_pid = waited_pid.as_raw(),
                            code,
                            "task group reaped after nonzero exit"
                        );
                    }
                    return true;
                }
            }
            Ok(nix::sys::wait::WaitStatus::Signaled(waited_pid, signal, dumped_core)) => {
                if unsafe { libc::kill(-(task_pgid as libc::pid_t), 0) } != 0
                    && nix::errno::Errno::last() == nix::errno::Errno::ESRCH
                {
                    warn!(
                        task_pgid,
                        waited_pid = waited_pid.as_raw(),
                        ?signal,
                        dumped_core,
                        "task group reaped after signal"
                    );
                    return true;
                }
            }
            Ok(_) => {
                if unsafe { libc::kill(-(task_pgid as libc::pid_t), 0) } != 0
                    && nix::errno::Errno::last() == nix::errno::Errno::ESRCH
                {
                    info!("task group {} ended", task_pgid);
                    return true;
                }
            }
            Err(nix::errno::Errno::ECHILD) => {
                if unsafe { libc::kill(-(task_pgid as libc::pid_t), 0) } != 0
                    && nix::errno::Errno::last() == nix::errno::Errno::ESRCH
                {
                    info!("task group {} ended (ECHILD)", task_pgid);
                    return true;
                }
            }
            Err(nix::errno::Errno::ESRCH) => {
                info!("task group {} is gone (ESRCH)", task_pgid);
                return true;
            }
            Err(e) => {
                warn!("waitpid for task group {} failed: {}", task_pgid, e);
            }
        }

        sleep(Duration::from_millis(100)).await;
    }

    false
}

/// Wait for all tracked task groups to exit, driving each with
/// `kill_and_wait_for_exit_async` concurrently via `FuturesUnordered`.
/// Updates `state` by reaping dead task groups when done.
async fn wait_all_children_async(state: &Arc<ArcSwap<UpDaemonState>>, timeout: Duration) {
    use futures::StreamExt as _;

    let task_pgids: Vec<u32> = {
        let s = state.load();
        // serve is stored in process_list.processes under its own task pgid;
        // no extra chain required.
        s.process_list
            .processes
            .iter()
            .filter(|(_, e)| !matches!(e.status, diag::ProcessStatus::Killed))
            .map(|(&task_pgid, _)| task_pgid)
            .collect()
    };

    if task_pgids.is_empty() {
        return;
    }

    let mut futs: FuturesUnordered<_> = task_pgids
        .into_iter()
        .map(|task_pgid| kill_and_wait_for_exit_async(task_pgid, timeout))
        .collect();

    while futs.next().await.is_some() {}

    reap_dead_task_groups_into_state(state);
}

fn write_bincode_frame<T: Serialize>(stream: &mut UnixStream, val: &T) -> Result<()> {
    let payload = bincode::serialize(val)?;
    stream.write_all(&(payload.len() as u32).to_le_bytes())?;
    stream.write_all(&payload)?;
    Ok(())
}

fn read_bincode_frame<T: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(Some(bincode::deserialize(&payload)?))
}

async fn write_bincode_frame_async<T: Serialize, W: tokio::io::AsyncWriteExt + Unpin>(
    stream: &mut W,
    val: &T,
) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;
    let payload = bincode::serialize(val)?;
    stream
        .write_all(&(payload.len() as u32).to_le_bytes())
        .await?;
    stream.write_all(&payload).await?;
    Ok(())
}

async fn read_bincode_frame_async<
    T: for<'de> Deserialize<'de>,
    R: tokio::io::AsyncReadExt + Unpin,
>(
    stream: &mut R,
) -> Result<Option<T>> {
    use tokio::io::AsyncReadExt as _;
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok(Some(bincode::deserialize(&payload)?))
}

/// Watch a HotConfig JSON file for changes and apply mount operations.
///
/// Runs in a loop, re-reading the file on each data-modify event,
/// and applying any new `mnt` / `mounts` entries.
async fn watch_hot_mounts(hot_path: &Path, vars: nsproxy_core::PathExpansionState) -> Result<()> {
    if !hot_path.exists() {
        info!("hot config {:?} does not exist, skipping watcher", hot_path);
        return Ok(());
    }

    let (mut watcher, mut rx) = {
        let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);
        let watcher = RecommendedWatcher::new(
            move |res: std::result::Result<Event, notify::Error>| {
                if let Ok(res) = res {
                    if matches!(res.kind, EventKind::Modify(ModifyKind::Data(_))) {
                        let _ = tx.try_send(());
                    }
                }
            },
            notify::Config::default(),
        )?;
        (watcher, rx)
    };

    watcher.watch(hot_path, notify::RecursiveMode::NonRecursive)?;
    info!("watching hot config {:?} for mount changes", hot_path);

    let mut prev_hot: Option<HotConfig> = None;

    while let Some(()) = rx.recv().await {
        let fc = match tokio::fs::read_to_string(hot_path).await {
            Ok(fc) => fc,
            Err(e) => {
                warn!("failed to read hot config: {}", e);
                continue;
            }
        };
        let mut hot: HotConfig = match serde_json::from_str(&fc) {
            Ok(h) => h,
            Err(e) => {
                warn!("failed to parse hot config: {}", e);
                continue;
            }
        };

        if let Err(err) = hot.process_and_save(hot_path) {
            warn!(%err, "failed to persist normalized hot config");
        }
        hot.expand_with(&vars);

        if prev_hot.as_ref() == Some(&hot) {
            continue;
        }

        info!("hot config changed, applying mount updates");
        match hot.merged_mounts() {
            Ok(mounts) => {
                if !mounts.is_empty() {
                    if let Err(e) = nsproxy_core::sandbox::apply_mounts(&vars, &mounts) {
                        warn!("failed to apply hot mounts: {}", e);
                    }
                }
            }
            Err(e) => warn!("failed to merge hot mounts: {}", e),
        }

        prev_hot = Some(hot);
    }

    Ok(())
}
