# Simple wireguard server

A rootless WireGuard control plane built on [uwgsocks](https://github.com/reindertpelsma/userspace-wireguard-socks).

Build a secure WireGuard server, relay hub, or small peer-synced mesh without Docker privileges, kernel modules, or system routing changes.

## Quick Start (20 Seconds)

1. **Build or download:**
   Download:
   ```bash
   wget https://github.com/reindertpelsma/simple-wireguard-server/releases/download/0.1/uwgsocks-ui
   wget https://github.com/reindertpelsma/userspace-wireguard-socks/releases/download/0.2/uwgsocks
   wget https://github.com/reindertpelsma/simple-wireguard-server/releases/download/0.1/uwgkm #If you want to use Kernel Wireguard, requires root
   chmod +x uwgsocks-ui uwgsocks uwgkm
   ```

   Or compile from source. Ensure you clone [https://github.com/reindertpelsma/userspace-wireguard-socks](https://github.com/reindertpelsma/userspace-wireguard-socks)
   ```bash
   ./compile.sh
   ```
3. **Run (Default SQLite + Auto-discovery):**
   ```bash
   ./uwgsocks-ui -listen 0.0.0.0:8080
   ```
   On the very first startup, the server now prints a random admin password and generates a bootstrap WireGuard client config unless you disable it with `-generate-config=false`.
4. **Docker**
   No special capabilities required, this simple wireguard server works even in the most restrictive containers

   ```bash
   docker compose build
   docker compose up -d
   ```
5. **Login:** Open `http://localhost:8080` and sign in with `admin` plus the password printed in the terminal. 

## Why use it

- Run a WireGuard server stack under any Unix account
- Manage peers, ACLs, forwards, transports, and runtime updates from the browser
- Publish internal services through login-gated subdomains
- Expose a single-domain `/proxy` and `/socket` frontend for clients and tooling
- Generate transport-aware WireGuard configs, including `#!` directives understood by `uwgsocks`
- Optionally enable peer syncing / P2P discovery for direct paths or multi-server client distribution

## Key Features

- **Admin Dashboard:** Real-time metrics, handshakes, short-term traffic graphs, and global setting management.
- **Responsive UI:** Mobile-friendly layout with both dark and light themes.
- **No system permissions or docker required** Setup a one-click wireguard server with a nice UI on any Linux machine under any account. Supports both Kernel wireguard and userspace implmentation.
- **2FA and OIDC:** Local users can enable TOTP 2FA, and operators can enable OIDC login with CLI flags or environment variables.
- **SD-WAN Ready:** Group peers by user, manage firewall ACLs, and handle multi-user environments.
- **IPv6 support:** First class support for IPv6
- **Runtime Traffic Shaping:** Admins can update per-peer upload/download/latency shapers while the daemon is running.
- **Configuration Merging:** Support for merging UI settings with a custom baseline YAML config.
- **Shareable Configs:** Create self-authenticated config links with optional expiry or one-time use; E2E links keep the decrypting nonce in the URL fragment.
- **Zero-Trust Security:** Client private keys never touch the server (encrypted in-browser via AES-GCM).
- **Transport-aware client configs:** Offer the right endpoint, `Transport = ...`, `#!URL=...`, `#!TURN=...`, or `#!Control=...` per client profile instead of one fixed bootstrap path.
- **Peer syncing / P2P:** Optional tunnel-only control endpoint lets `uwgsocks` clients discover other peers, sync distributed clients between servers, and attempt direct UDP paths without introducing a separate control plane stack.
- **NAT Traversal:** Built-in TURN server support for connectivity through strict firewalls/CGNAT, by hosting a small TURN server see the userspace wireguard socks project.
- **Secure by Default:** Argon2id hashing, encryption at rest for DB fields, and single-port HTTP/HTTPS multiplexing.
- **Reverse Proxy Aware:** Trust configured proxy CIDRs for `X-Forwarded-For` / `X-Forwarded-Proto`, set an explicit canonical base URL, and expose optional browser access paths through `/proxy`, `/socket`, and protected service subdomains.
- **Tag-based ACLs:** Assign policy tags to users and peers, attach extra CIDRs to tags, and write ACLs against users or tags while the daemon still receives concrete IP/CIDR rules.

## Advanced Usage

Detailed technical documentation and API schemas are available in the [docs/](./docs) folder.

### CLI Flags
- `-listen`: Port to host the UI and API (Supports HTTP/HTTPS multiplexing).
- `-baseline-config`: Path to a baseline YAML to merge with UI settings.
- `-turn-server`: Use a TURN relay for all WireGuard traffic.
- `-db-type`: Supports `sqlite` (default), `mysql`, and `postgres`.
- `-dsn`: Database connection string.
- `-wg-url`: Connect to daemon via Unix socket (default) or HTTP.
- `-generate-config`: Immediately mint and print a bootstrap WireGuard client config on startup. Defaults to enabled on the first boot.
- `-frontend-dir`: Serve dashboard assets from a custom Vite `dist` directory instead of the embedded bundle.
- `-extract-dist`: Extract the embedded dashboard bundle to a directory and exit.
- `-oidc-issuer`, `-oidc-client-id`, `-oidc-client-secret`, `-oidc-redirect-url`: Enable OIDC sign-in. The same values can be supplied with `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, and `OIDC_REDIRECT_URL`.

## Documentation

- [Configuration reference](docs/configuration.md)
- [Proxy and routing behavior](docs/proxy-routing.md)
- [Raw socket and `/socket` protocol](docs/socket-protocol.md)
- [Testing and integration coverage](docs/testing.md)
- [OpenAPI schema](docs/openapi.yaml)

## License
ISC License. See [LICENSE](./LICENSE) for details.
