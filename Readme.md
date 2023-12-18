# NSProxy

Kernel-namespaces-based alternative to proxychains.

> Part of Accessible OPSEC series (if there even is). 

## Rationale

- Firefox and its derivatives, leak traffic even with SOCKS5 proxy configured
    - Browsers in general have a lot of telemetry, which is unacceptable for what this project is trying to do.
- Proxychains may silently fail and leak traffic (but it's a great tool if you put it in a netns which nullfies the downsides)
- Nsproxy creates containers which better suits the OPSEC use case than https://github.com/SagerNet/sing-box 
- [Tun2socks](https://github.com/xjasonlyu/tun2socks) does not have virtual DNS
- VPNs (in the sense the binaries VPN vendors distribute) do not care about the OPSEC usecase. 

## The usecase

- You use non-conventional protocols. You need userspace TUNs.
- You have a diverse need for proxied routing, and you don't want to read a ton of docs.
- You want to have some apps proxied, and others not.
- You sometimes use darknets.
- You don't want to mess with other parts of your system. 

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



