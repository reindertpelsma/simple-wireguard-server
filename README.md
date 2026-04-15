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
3. **Run with TURN (NAT Traversal):**
   ```bash
   ./uwgsocks-ui -turn-server my-turn.com:3478 -turn-user user -turn-pass pass
   ```
4. **Login:** Open `http://localhost:8080` (admin/admin).

## Key Features

- **Zero-Trust Security:** Client private keys never touch the server (encrypted in-browser via AES-GCM).
- **NAT Traversal:** Built-in **TURN server support** for connectivity through strict firewalls/CGNAT.
- **TCP MSS Clamping:** Automatic tunnel MTU enforcement for reliable TCP performance.
- **SD-WAN Ready:** Group peers by user, manage firewall ACLs, and handle multi-user environments.
- **Dual-Stack IP:** Automatically assigns IPv4 (/32) and IPv6 (/128) addresses to every peer.
- **Configuration Merging:** Support for merging UI settings with a custom baseline YAML config.
- **Admin Dashboard:** Real-time metrics, handshakes, data usage, and global setting management.
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

## License
ISC License. See [LICENSE](./LICENSE) for details.
