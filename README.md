# Simple WireGuard Server

Browser UI for managing WireGuard users, client configs, ACLs, and protected
service exposure.

`uwgsocks-ui` is the browser UI and management daemon for
[userspace-wireguard-socks](https://github.com/reindertpelsma/userspace-wireguard-socks).
It manages `uwgsocks` by default and can switch to `uwgkm` when you want kernel
WireGuard on Linux.

If you want a browser UI for managing WireGuard users and client configs, plus
groups, ACLs, protected subdomain exposure, and the option to stay rootless,
this is the control plane for that.

For most deployments you only need two binaries on the same host:

- `uwgsocks` for the data plane
- `uwgsocks-ui` for the browser UI and management layer

That keeps the setup close to plain WireGuard config management: install the
data plane, start the UI, create users, download configs, and only add extras
when you actually need them.

What operators get:

- create, edit, disable, and expire WireGuard users and client configs from the browser
- show QR codes, download config files, and issue one-time config share links
- publish internal web services through login-protected subdomains
- enforce groups and ACLs so peers only reach the networks and services they should
- see connected peers and per-peer traffic charts in the UI
- support local login, 2FA, and OIDC for operator access
- run rootless by default with `uwgsocks`, or switch to `uwgkm` on Linux if you want kernel WireGuard
- add optional extras like HTTP proxy access and TURN-based firewall traversal when you need them

![Dashboard overview](docs/assets/dashboard.jpg)

## Quick Start

Install the two required binaries:

```bash
curl -fsSL https://raw.githubusercontent.com/reindertpelsma/userspace-wireguard-socks/main/install.sh | sh -s -- uwgsocks
curl -fsSL https://raw.githubusercontent.com/reindertpelsma/simple-wireguard-server/main/install.sh | sh -s -- uwgsocks-ui
```

Start the UI:

```bash
uwgsocks-ui -listen 0.0.0.0:8080
```

On first start it creates the database, generates secrets, prints the bootstrap
admin password, and starts a managed `uwgsocks` child daemon by default.

Then open `http://YOUR-HOST:8080/login`, sign in, create your first user, and
download a WireGuard config from the browser.

![Login screen](docs/assets/login.jpg)

## Install Options

Optional extras:

TURN relay / firewall traversal support:

```bash
curl -fsSL https://raw.githubusercontent.com/reindertpelsma/userspace-wireguard-socks/main/install.sh | sh -s -- turn
```

Kernel-mode manager for Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/reindertpelsma/simple-wireguard-server/main/install.sh | sh -s -- uwgkm
```

Windows install:

```powershell
curl.exe -fsSLo install.bat https://raw.githubusercontent.com/reindertpelsma/simple-wireguard-server/main/install.bat
install.bat
```

Build from source:

```bash
./compile.sh
```

Source builds need:

- Go 1.25+
- Node.js 20.19+ for the frontend build

Windows:

- use the release page binaries, or
- run `install.bat` / `install.ps1`

Release tags also publish:

- `ghcr.io/reindertpelsma/simple-wireguard-server:<tag>`

## What It Manages

- WireGuard users and client configs:
  create users, assign devices, download configs, scan QR codes, rotate access,
  and send one-time share links without hand-editing `.conf` files
- Policy and segmentation:
  define groups, attach users and peers to them, and enforce ACLs that limit
  which networks, ports, and services each peer can reach
- Protected service exposure:
  publish internal web apps through managed subdomains with login-gated access,
  instead of opening those backends directly to the internet
- Operator access:
  keep admin login local with passwords and 2FA, or connect the UI to OIDC so
  your team signs in with the identity provider you already use

Extras such as HTTP proxy access, `/socket`, TURN hosting, and `uwgkm` are
available, but they are not required for the main WireGuard management flow.

## Documentation

Start with the guided flow:

- [How-To Index](docs/howto/README.md)
- [01 Install And Bootstrap](docs/howto/01-install-and-bootstrap.md)
- [02 Users And Client Configs](docs/howto/02-users-and-client-configs.md)
- [03 Groups And ACLs](docs/howto/03-groups-and-acls.md)
- [04 Services And Public Ingress](docs/howto/04-services-and-public-ingress.md)
- [05 Browser Proxy And Socket Access](docs/howto/05-browser-proxy-and-socket-access.md)
- [06 Reverse Proxy And TLS](docs/howto/06-reverse-proxy-and-tls.md)
- [07 OIDC Login](docs/howto/07-oidc-login.md)
- [08 Kernel Mode With Uwgkm](docs/howto/08-kernel-mode-with-uwgkm.md)
- [09 Managed TURN Hosting](docs/howto/09-managed-turn-hosting.md)

Deep reference docs:

- [UI config reference](docs/reference/config-reference.md)
- [CLI and environment reference](docs/reference/cli-reference.md)
- [Reverse proxy reference](docs/reference/reverse-proxy.md)
- [Uwgkm mode reference](docs/reference/uwgkm.md)
- [Managed TURN hosting reference](docs/reference/turn-hosting.md)
- [Managed daemon configuration reference](docs/reference/daemon-configuration.md)
- [Proxy and routing behavior](docs/reference/proxy-routing.md)
- [Socket protocol](docs/reference/socket-protocol.md)
- [Testing](docs/reference/testing.md)
- [OpenAPI HTML reference](docs/reference/openapi.html)
- [OpenAPI schema](docs/reference/openapi.yaml)

## Platform Status

- Supported and repeatedly tested: Linux, macOS, Windows, FreeBSD
- Linux-only component: `uwgkm`
- OpenBSD source builds currently depend on reusing a prebuilt `dist/`

See [docs/reference/testing.md](docs/reference/testing.md) for the current test
surface and platform notes.

## License

ISC License. See [LICENSE](LICENSE) for details.
