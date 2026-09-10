# Rootfs and bind-mount concerns

## Rootfs backing and persistence

- `Rootfs::Default` pivots into `/nsp3/rootfs/{profile}`. Unbound paths in that rootfs are backed by the persistent filesystem and survive reboot.
- `Rootfs::Tempfs` mounts a fresh tmpfs at `/tmp/nsproxy_{profile}` before building the pivot root. Unbound files there are RAM-backed and disappear when the mount is destroyed, including across reboot.
- `Rootfs::Path(path)` uses the filesystem backing the configured path, so persistence depends on that filesystem.
- The container's `/tmp` and `/run` are separate fresh tmpfs mounts in every pivot mode and are ephemeral.

## Bind-mount I/O

- A bind mount does not copy data through the rootfs or maintain a second file copy. VFS path lookup switches to the source mount at the mountpoint.
- Reads and writes go directly to the bind source filesystem. The source may be disk-backed, tmpfs-backed, or remote; its filesystem determines the I/O behavior.
- The overhead is limited to mount setup and a small path-lookup/mountpoint cost. Many mounts can increase setup and metadata overhead, but normal file I/O does not make a rootfs roundtrip.
- In the pivot skeleton, `/nsp3/config` is bind-mounted read-write, so changes there persist independently of whether the pivot root is tmpfs-backed.

## Old root warning

- After `pivot_root`, the former host root is available at `/pivot` until detached. Writes through `/pivot` target the host filesystem and are not isolated in the container rootfs.

## Code anchors

- Pivot selection and setup: `crates/nsproxy-core/src/sandbox.rs`, `apply_pivot` and `build_skeleton`.
- Rootfs paths: `crates/common/src/lib.rs`, `state_paths::pivot_root` and `state_paths::pivot_root_mem`.
- Bind primitives: `crates/nsproxy-core/src/sys.rs`, `mount_bind_rw_explicit` and `mount_bind_ro_explicit`.
- Rootfs mode definitions: `crates/nsproxy-core/src/lib.rs`, `Rootfs` and `SandboxMode`.
