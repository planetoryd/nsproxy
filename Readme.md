# NSProxy

Kernel-namespaces-based alternative to proxychains.

> Part of Accessible OPSEC series (if there even is). 

## Rationale

- Firefox and its derivatives, leak traffic even with SOCKS5 proxy configured
    - Browsers in general have a lot of telemetry, which is unacceptable for what this project is trying to do.
- Proxychains may silently fail and leak traffic (but it's a great tool if you put it in a netns which nullfies the downsides)
- Nsproxy creates containers which better suits the OPSEC use case than [sing-box](https://github.com/SagerNet/sing-box)
- [Tun2socks](https://github.com/xjasonlyu/tun2socks) does not have virtual DNS
- VPNs (in the sense the binaries VPN vendors distribute) do not care about the OPSEC usecase. 

## The usecase

- You use non-conventional protocols. You need userspace TUNs.
- You have a diverse need for proxied routing, and you don't want to read a ton of docs.
- You want to have some apps proxied, and others not.
- You sometimes use darknets.
- You don't want to mess with other parts of your system. 
- You want to proxy Flatpak apps.

## We've got you covered

The proxy 

- If your proxy client is opensourced, it can be made to accept a socket from nsproxy
    - Nsproxy will create a container and you can access the proxy through a SOCKS5 endpoint in the container.
- If your proxy is opensourced and has custom TUN logic, it can be made to accepet the TUN file descriptor from nsproxy
- If your proxy can not be modified, you can use the `socks2tun` subcommand to connect to its SOCKS5 endpoint.

The app

- If your app doesn't work with SOCKS5
    - If your app works with LD_PRELOAD, you don't need a TUN.
        - You may use proxychains inside an Nsproxy container
        - Nsproxy creates a SOCKS5 endpoint in the container
    - Nsproxy may create a TUN and pass it to the proxy
    - Nsproxy may create a TUN and route it to the proxy's SOCKS5 endpoint
- If your app works with SOCKS5
    - You just connect to the SOCKS5 endpoint in the container

## Fix flatpak networking, sideways.

You can run `nsproxy watch ./test_proxy.json` to automatically proxy flatpak apps.

Currently it's not recommended (bad for anonymity) to have multiple instances of an app because the data could not be segregated, see [the issue](https://github.com/flatpak/flatpak/issues/1170).


## Usage 

```bash
./target/debug/nsproxy 
2023-12-19T15:24:04.337533Z  INFO nsproxy: SHA1: 340b180ff3f2dd484e5e1043dd0cf9c7074db293
an alternative to proxychains based on linux kernel namespaces

Usage: nsproxy <COMMAND>

Commands:
  socks2tun  One of the many methods, use TUN2Proxy and pass a device FD to it. TUN2proxy will connect to a SOCKS5 proxy in its NS, and serve a TUN in the app NS
  watch      Start as watcher daemon. This uses the socks2tun method
  probe      Run probe process acccording to the graph. ID for Node ID
  tun2proxy  Run TUN2Proxy daemon. This must be run as a systemd service
  init       Requires root or equivalent. Initiatializes user and mount namespaces. Actions other than this may be performed (also usually) rootlessly It's recommend to use SUDO because I need the deprivileged UID
  info       
  userns     Enter the initialized user&mnt ns
  node       
  veth       You should use this through "sproxy" the SUID wrapper if you are not in a userns. It tries to find an unallocated subnet, and the created NS is not registered in the state file
  setns      
  help       Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## Future work

The throughput isn't good and it perhaps makes more sense to make firewalls work. 