Syswg is a Wireguard manager for the linux kernel.

Its similar to userspace-wireguard-socks to host a Wireguard server/client, only this one does require root and system permissions.

Its primarily designed if you want to have high wireguard performance, and designed specifically for the uwgsocks-ui when you run it in a docker container with NET_ADMIN privilege.

Features:
- Uses the kernel Wireguard interface, not `/dev/net/tun`. Therefore this does not run in all environments.
- Supports automatic Wireguard setup through a HTTP API and yaml config, including peers
- Automatically setups nftables rules for the ACLs, the same ACL format that the userspace wireguard also uses
- Exposes status about the Wireguard server

The primary advantage over wgquick is that it has a rest api allowing a HTTP backend to easily integrate with the Wireguard interface, without mangling with wg commands or ip commands or other shell injections/dependencies, since the go binary directly calls the kernel syscall ABI to setup Wireguard and firewall

In the UI server you can use the system wireguard by using the --system argument, ensure that uwgkm binary is available.