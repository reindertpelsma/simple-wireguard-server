# uwgsocks-ui

A wireguard server manager without system installation requirements, based on [uwgsocks](https://github.com/reindertpelsma/userspace-wireguard-socks)

Build a secure, rootless SD-WAN or VPN exit node in seconds.

## Quick Start (20 Seconds)

1. **Build Everything:**
   ```bash
   ./compile.sh
   ```
2. **Run (Default SQLite + Auto-discovery):**
   ```bash
   ./uwgsocks-ui -listen 0.0.0.0:8080
   ```
   On the very first startup, the server now prints a random admin password and generates a bootstrap WireGuard client config unless you disable it with `-generate-config=false`.
3. **Run with TURN (NAT Traversal):**
   ```bash
   ./uwgsocks-ui -turn-server my-turn.com:3478 -turn-user user -turn-pass pass
   ```
4. **Login:** Open `http://localhost:8080` and sign in with `admin` plus the password printed in the terminal.

## Key Features

- **Zero-Trust Security:** Client private keys never touch the server (encrypted in-browser via AES-GCM).
- **NAT Traversal:** Built-in **TURN server support** for connectivity through strict firewalls/CGNAT.
- **TCP MSS Clamping:** Automatic tunnel MTU enforcement for reliable TCP performance.
- **SD-WAN Ready:** Group peers by user, manage firewall ACLs, and handle multi-user environments.
- **Dual-Stack IP:** Automatically assigns IPv4 (/32) and IPv6 (/128) addresses to every peer.
- **Configuration Merging:** Support for merging UI settings with a custom baseline YAML config.
- **Admin Dashboard:** Real-time metrics, handshakes, short-term traffic graphs, and global setting management.
- **Bootstrap Friendly:** First-run random admin credentials plus optional `-generate-config` output for immediate SSH-only bring-up.
- **Shareable Configs:** Create self-authenticated config links with optional expiry or one-time use; E2E links keep the decrypting nonce in the URL fragment.
- **Responsive UI:** Mobile-friendly layout with both dark and light themes.
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

## License
ISC License. See [LICENSE](./LICENSE) for details.
