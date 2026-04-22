# Simple wireguard server

A rootless WireGuard control plane built on top of
[uwgsocks](https://github.com/reindertpelsma/userspace-wireguard-socks).

It gives you a browser UI for running a WireGuard server, relay hub, or small
peer-synced mesh without Docker privileges, kernel modules, or system routing
changes.

## What it does

- manages peers, ACLs, forwards, transports, and runtime updates from the browser
- generates transport-aware client configs, including `#!` directives for `uwgsocks`
- publishes protected internal services through login-gated subdomains
- exposes `/proxy` and `/socket` frontend paths for clients and tooling
- can host a managed TURN daemon with per-user TURN credentials

## Quick Start

```bash
./compile.sh
./uwgsocks-ui -listen 0.0.0.0:8080
```

First startup prints a random admin password and, by default, a bootstrap
WireGuard client config.

Unix-like install:

```bash
curl -fsSL https://raw.githubusercontent.com/reindertpelsma/simple-wireguard-server/main/install.sh | sh
```

Windows install:

```powershell
curl.exe -fsSLo install.bat https://raw.githubusercontent.com/reindertpelsma/simple-wireguard-server/main/install.bat
install.bat
```

Release tags also publish:
- `ghcr.io/reindertpelsma/simple-wireguard-server:<tag>`

## Platform Status

- Supported and repeatedly tested:
  - Linux, macOS, Windows, FreeBSD

See [docs/testing.md](docs/testing.md) for OpenBSD notes and the current
source-build caveat there.

## Documentation

- [Configuration guide](docs/configuration.md)
- [Proxy and routing behavior](docs/proxy-routing.md)
- [Socket protocol](docs/socket-protocol.md)
- [Testing](docs/testing.md)
- [OpenAPI schema](docs/openapi.yaml)

## License

ISC License. See [LICENSE](./LICENSE) for details.
