# Simple wireguard server

A wireguard server manager without system installation requirements, based on [uwgsocks](https://github.com/reindertpelsma/userspace-wireguard-socks)

Build a secure, rootless SD-WAN or VPN exit node in seconds.

## Quick Start (20 Seconds)

1. **Build or download:**
   Ensure you clone [https://github.com/reindertpelsma/userspace-wireguard-socks](https://github.com/reindertpelsma/userspace-wireguard-socks)
   
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
- **NAT Traversal:** Built-in TURN server support for connectivity through strict firewalls/CGNAT, by hosting a small TURN server see the userspace wireguard socks project.
- **Secure by Default:** Argon2id hashing, encryption at rest for DB fields, and single-port HTTP/HTTPS multiplexing.

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

## License
ISC License. See [LICENSE](./LICENSE) for details.
