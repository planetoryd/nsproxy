
```bash
noume@noume-pc ~/n/nsproxy (master)> RUST_BACKTRACE=1 sudo -E ./target/debug/nsproxy init
[2023-12-04T09:37:12Z INFO  nsproxy::sys] UserNS inited
[2023-12-04T09:37:12Z INFO  nsproxy] ("/etc/nsproxy/user", "/etc/nsproxy/private/mnt")
[2023-12-04T09:37:12Z DEBUG nsproxy::sys] Subproc exit
noume@noume-pc ~/n/nsproxy (master)> grep etc /proc/self/mountinfo
59 64 0:31 /@/etc/nsproxy/private /etc/nsproxy/private rw,noatime - btrfs /dev/nvme0n1p2 rw,compress=zstd:3,ssd,discard=async,space_cache=v2,subvolid=256,subvol=/@
330 59 0:31 /@/etc/nsproxy/private /etc/nsproxy/private rw,noatime - btrfs /dev/nvme0n1p2 rw,compress=zstd:3,ssd,discard=async,space_cache=v2,subvolid=256,subvol=/@
637 64 0:4 user:[4026533048] /etc/nsproxy/user rw shared:278 - nsfs nsfs rw
749 330 0:4 mnt:[4026533049] /etc/nsproxy/private/mnt rw - nsfs nsfs rw
```