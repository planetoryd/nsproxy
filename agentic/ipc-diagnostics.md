# IPC, networking, and diagnostics

Load this note for `sp up`, `sp serve`, Unix socket protocols, reconnection, routing, diagnostic state, and the UI supervisor actor. For spawn semantics, also load `agentic/runtime-state.md`.

## Core paths and protocol

- `UplinkHub` owns the proxy map and pluggable routing through `with_routing` / `set_routing` in `crates/nsproxy-core/src/uplink.rs`.
- `sp up` listens on `/nsp3/{name}/up.sock`; search `up_sock_path`, `run_up_daemon`, and `handle_up_client`.
- `sp serve` diagnostics listen on `/nsp3/{name}/tun_diag.sock`; search `diag_sock_path`, `Router::init_diag`, and `DiagServer::start`.
- Frames are bincode payloads prefixed by a little-endian `u32`. Search `encode_frame`, `read_frame`, `write_bincode_frame`, `read_bincode_frame`, and async variants in `crates/diag/src/lib.rs` and `crates/nsproxy-core/src/bin/nsproxy.rs`.

## Server and client ownership

- Serve entry/probe: `cmd_serve` in `crates/nsproxy-core/src/bin/nsproxy.rs`.
- Per-diagnostic-client handling: `serve_client`, `DiagServer::emit`, `DiagServer::install_as_global` in `crates/diag/src/lib.rs`.
- Up requests include `GetProcessList`, `Spawn`, `SpawnCli`, and `Stop`; handling is in `handle_up_client`.
- UI connection guards and loops: `ensure_up_client`, `ensure_diag_client`, `up_stream_loop`, `diag_stream_loop` in `crates/nsproxy-ui/src/supervisor.rs`.

## Event-driven bidirectional connection pattern

Both service processes and the UI can establish the active channel; core correctness must not depend on polling.

- The UI listens on `/nsp3/nsproxy-ui-{pid}.sock` through `control_socket_accept_loop`.
- `sp init` creates `/nsp3` and sets that root directory to mode `0777`, allowing an
  unprivileged UI to bind its control socket there. It does not change permissions of
  a custom `--root` directory.
- Services greet it with `ControlSocketGreeting::{UpDaemon,ServeDaemon}` via `connect_and_greet_up` / `connect_and_greet_serve`.
- UI injection paths are `InjectUpStream`, `InjectDiagStream`, and `run_injected_up_stream`.
- On UI restart, `up_client_loop` can connect to an existing daemon through `diag::connect_up_daemon`.
- When UI launches `sp up`, `Cli.control_socket` lets the daemon connect back immediately.
- Lifecycle is driven by accept/connect/stream-close events. Retry helpers (`retry_delay`, `sleep_or_cancelled`) are fallback behavior, not discovery architecture.

## Diagnostic state

- Event history: `event_ring`, `DIAG_EVENT_RING_CAP` in `crates/diag/src/lib.rs`.
- Connection actor: `ConnsState`, `ConnsSummary`, `ConnsActor`, `ConnsCmd`.
- Runtime commands: `SetTrackConns`, `ResetConnsState`, `QueryRecentDiagEvents`.

## UI supervisor actor

- Actor boundary: `Supervisor`, `SupervisorCommand`, `SupervisorEvent`, `Supervisor::run`, `tokio::select!` in `crates/nsproxy-ui/src/supervisor.rs`.
- Handle/task split: `SupervisorHandle::{new,send,try_recv_snapshot}` and the watch channel.
- Main integration: `SupervisorHandle::new`, `SupervisorCommand::Init`, and `try_recv_snapshot` in `crates/nsproxy-ui/src/main.rs`.
