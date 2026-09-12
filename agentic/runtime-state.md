# Runtime, state, and sandboxing

Load this note for CLI commands, profile persistence, configuration, namespace entry, sandbox mounts, and process spawning.

## Runtime and state

- Commands are centralized in `MainCommand` (`Up`, `Serve`, `Sandbox`) in `crates/nsproxy-core/src/lib.rs`.
- Persistent profile state defaults to `/nsp3`; search `PERSIST_ROOT`, `state_paths::persist_root`, and `state_paths::set_persist_root` in `crates/common/src/lib.rs`. `Cli.root` overrides it per process.
- `NsAlive` records `child_pid`, `up_pid`, `serve_pid`, bind-mount state, and optional browser profile. Definition: `crates/common/src/lib.rs`; namespace-entry uses: `crates/nsproxy-core/src/cmd_common.rs`.
- The standardized state interface is `PersistentState`; path helpers are under `state_paths`. Search `profile_ns_meta` and `state_blueprint.rs`.
- `HotConfig` owns DNS, TUN, devices, mounts, locals, and daemon fields. `TemplateConfig` owns sandbox mode, mounts, chmod, env, and hot-config linkage.
- Stateful path expansion uses `PathExpansionState::{expand_with,expand_source,expand_target}`.
- Domains use canonical trailing-dot normalization via `normalize_domain` in `crates/common/src/lib.rs`.
- Long-lived shell/daemon invocations log `{type, pid, nsid, args}` as one JSON object per line in the boot-scoped append-only JSONL file at `state_paths::process_log()` (`/nsp3/nsproxy-process-log.jsonl` by default). `args` is the serialized `Cli` JSON object, so memfd-launched commands retain their structured arguments across versions; definitely short-lived commands such as `completions`, `id`, and `version` are excluded. The boot ID marker at `process_log_boot()` rotates the logical history once per kernel boot; boot rotation is locked and normal writes use append mode.

## Sandboxing and mounts

- `SandboxMode` and `TemplateConfig.sandbox_mode`: `crates/nsproxy-core/src/lib.rs`.
- Pivot orchestration: `apply_pivot`, `build_skeleton`, `apply_mounts`, `apply_chmod`, `detect_sandbox_state`, `assert_mount_ns_isolated` in `crates/nsproxy-core/src/sandbox.rs`.
- Mount primitives: `mount_bind_rw_explicit`, `mount_bind_ro_explicit`, `mount_tmpfs`, `pivot_root_into`, `mount_bind_root` in `crates/nsproxy-core/src/sys.rs`.
- Profile-scoped staging path: `state_paths::pivot_root_dir`.

## Spawning in a namespace

Daemonized workloads should outlive the UI action and remain supervised by `sp up`:

- UI commands: `SupervisorCommand::{StartDaemon,StartServe}` in `crates/nsproxy-ui/src/supervisor.rs`.
- Wire requests: `DaemonRequest::{Spawn,SpawnCli}`.
- `handle_up_client` dispatches to `spawn_daemon_process` or structured memfd-based `spawn_cli_process` in `crates/nsproxy-core/src/bin/nsproxy.rs`.
- Tracking lives in `UpDaemonState.process_list`; updates use `ProcessListSnapshot` and `DaemonEvent::ProcessExit`.
- Privileged UI launches choose the `sproxy` wrapper via `nsproxy_path` and `spawn_nsproxy_cli`; `sproxy` authenticates and re-execs `nsproxy`.

Non-daemonized interactive work should exit with its process tree:

- `enter_ns` enters namespaces from `NsAlive` in `crates/nsproxy-core/src/cmd_common.rs`.
- `ShellPrefs::{spawn_in_ns,spawn}` performs clone, setns, and exec in `crates/nsproxy-core/src/shell.rs`.
- `MainCommand::Sandbox` uses this path with pivot/mount orchestration. See [case-sp-sandbox-hotconfig-mounts.md](case-sp-sandbox-hotconfig-mounts.md) for the current HotConfig mount behavior and risks.

## Hotconfig watcher boundary

- `sp sandbox` initially reads `hot.json`, expands paths, merges `mnt` and `mounts`, and applies those mounts after sandbox setup. This also applies in Overlay mode, where no pivot occurs; `TemplateConfig.mounts` are only applied by the pivot path.
- `sp serve` deliberately skips live HotConfig mount reconciliation. `watch_hot_mounts` exists but currently has no caller, so `hot.json` changes do not automatically reapply `mnt` / `mounts`.
- The watcher does not create, remove, or reconfigure veth pairs. `sp up` reconciles persisted `HotConfig.veth` entries and writes per-entry results to `veth_status.json`; temporary requests use the separate `MainCommand::Veth` path documented in `agentic/ui.md`.
