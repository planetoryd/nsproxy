# NSProxy

Kernel-namespaces-based alternative to proxychains.

> Part of Accessible OPSEC series (if there even is).

## Usage 

It's recommended to use the veth + tun2proxy method. 

```bash
./nsproxy install -s # installs nsproxy and sproxy to your /usr/local (requires root) and makes sproxy suid
# it assumes sproxy is in the same directory as its nsproxy binary
# even though sproxy is SUID, it still runs SUDO to check your permission
sproxy veth -t ./test_proxy.json # gives you a shell inside a proxied container
# later you may
sproxy node <index> run # enter that container from another shell
```

## Rationale

- Firefox and its derivatives, leak traffic even with SOCKS5 proxy configured
    - Most browsers, Firefox, Floorp (false advertised malware), and even Librewolf, caused my firewall to pop up when I opened it.
        - which by my OPSEC standard is unacceptable.
- Proxychains may silently fail and leak traffic (but it's a great tool if you put it in a netns which nullfies the downsides)
    - because it avoids the roundtrip of TUN and make the app connect to SOCKS5 endpoint directly
- Nsproxy creates containers which better suits the OPSEC use case than [sing-box](https://github.com/SagerNet/sing-box)
- [Tun2socks](https://github.com/xjasonlyu/tun2socks) does not have virtual DNS
- VPNs (in the sense the binaries VPN vendors distribute) do not care about the OPSEC usecase. 
- Portmaster does not handle the use case this tool is concerning. 
    - I find it dishonest because its per-app-vpn feature only works with *their* VPNs
- Opensnitch does not have the `redirect/restrict programs to certain net interfaces, addresses (of socks5)` feature.

## The usecase

- You use non-conventional protocols. You need userspace TUNs.
- You want to have some apps proxied, and others not.
- You have a diverse need for proxied routing, and you don't want to read a ton of docs.
- You don't want to mess with other parts of your system. 
- You want to proxy Flatpak apps.

## We've got you covered

Root or not

- `sproxy` requires root but less trouble
    - connects the container to your root/initial netns through veth (max performance)
    - `sproxy` is just a wrapper that starts `nsproxy`.
- `nsproxy userns`
    - initialises a user ns. This is a one-time operation, it just mounts them
    - It's possible to not mount the NS and have a long-running process, but it's not implemented
- `nsproxy socks2tun --new-userns`
    - requires no root, throughout the whole process.

The proxy 

- The current recommended usage is `sproxy veth -t <config>`
    - Provides a TUN for non-socks5-capable programs
    - Provides a veth to your root net ns to access your proxies
- If your proxy client is opensourced, it can be made to accept a socket from nsproxy
    - Nsproxy will create a container and you can access the proxy through a SOCKS5 endpoint in the container.
- If your proxy is opensourced and has custom TUN logic, it can be made to accepet the TUN file descriptor from nsproxy
- If your proxy can not be modified, you can use the `socks2tun` subcommand to connect to its SOCKS5 endpoint.

The app

- If your app doesn't work with SOCKS5
    - If your app works with LD_PRELOAD, you don't need a TUN.
        - You may use proxychains inside an Nsproxy container
        - Nsproxy creates a SOCKS5 endpoint in the container that is passed to the proxy
    - Nsproxy may create a TUN and pass it to the proxy
    - Nsproxy may create a TUN and route it to the proxy's SOCKS5 endpoint
- If your app works with SOCKS5
    - You just connect to the SOCKS5 endpoint in the container
    - You can use the `veth` method

## Fix flatpak networking, sideways.

You can run `nsproxy watch ./test_proxy.json` to automatically proxy flatpak apps.

Currently it's not recommended (bad for anonymity) to have multiple instances of an app because the data could not be segregated, see [the issue](https://github.com/flatpak/flatpak/issues/1170).

## Development

- Netlink manipulation (including Netfilter) libraries in Rust
- Tun2socks implementation with [ipstack](https://github.com/narrowlink/ipstack)
    - Virtual DNS included
    - The original branch used [tun2proxy](https://github.com/blechschmidt/tun2proxy) but the `smoltcp` it uses has bugs which makes it unusable.
- Rangemap based IP allocation (or suitable object) library
- Forked PidFd with `impl AsFd for PidFd`
- Mounting network namespaces, preparing them for use, everything, in Rust.