# simple-wireguard-server (uwgsocks-ui)

## What this is
A WireGuard server manager UI (`uwgsocks-ui` binary) that manages an `uwgsocks` (or `uwgkm` for kernel mode) daemon. No root required. Built in Go + React/Vite.

## Project layout
- `main.go` — all core HTTP handlers, DB models, YAML generation, daemon API proxy, IP allocation, crypto helpers
- `daemon_control.go` — start/stop/restart managed daemon subprocess
- `network_defaults.go` — IP detection, MTU discovery, transport resolution helpers
- `peer_config.go` — client WireGuard config generation (`buildClientConfigText`), transport resolution
- `yaml_admin.go` — YAML config admin handlers, `buildCanonicalYAMLBytes`
- `bootstrap.go` — first-start admin user and bootstrap peer generation
- `traffic.go` — in-memory traffic history tracker
- `share.go` — shareable config link handling
- `request_origin.go` — trusted reverse proxy CIDRs, canonical URL, client IP helpers
- `access_proxy.go` — `/proxy`, `/socket`, and exposed-service reverse proxy handling
- `acl_tags.go` — user/peer policy tag expansion and backend ACL evaluation for browser/proxy access
- `oidc.go` — OIDC login integration
- `auth_extra.go` — TOTP/2FA helpers
- `frontend/` — Vite/React frontend (components in `src/components/`)
- `dist/` — embedded frontend build (go:embed)
- `uwg_canonical.yaml` — generated canonical config written to disk for the daemon

## Database (GORM/SQLite default)
Models: `User`, `Peer`, `GlobalConfig`, `ACLRule`, `TransportConfig`, `SharedConfigLink`.
Reverse proxy/access models: `AccessProxyCredential`, `ExposedService`.
Policy tag model: `PolicyTag`; `User.Tags`, `Peer.Tags`, `ACLRule.SrcUsers`, and `ACLRule.SrcTags` are expanded into concrete IP/CIDR ACLs before pushing to uwgsocks.

`GlobalConfig` is a key-value table. Settings are read with `getConfig(key)` and written with `gdb.Model(&GlobalConfig{}).Where("key = ?", k).Update("value", v)`.

Key settings stored in GlobalConfig:
- `server_privkey`, `server_pubkey` — server WireGuard keys
- `server_endpoint` — advertised endpoint for clients
- `client_dns`, `client_subnet_ipv4`, `client_subnet_ipv6` — IP allocation pool and DNS
- `enable_client_ipv6` — whether to allocate IPv6 addresses to clients (auto-detected on first start)
- `global_mtu` — MTU advertised in client configs
- `default_transport` — transport name for the Endpoint/Transport line in client configs
- `e2e_encryption_enabled`, `allow_custom_private_key`, `public_keys_visible`, `endpoints_visible`
- `yaml_l3_forwarding`, `yaml_block_rfc`, `yaml_host_forward`, `yaml_socks5_port`, `yaml_http_port`, `yaml_proxy_username`, `yaml_proxy_password`, `yaml_inbound_transparent`, `yaml_socks5_udp`
- `custom_yaml_enabled`, `custom_yaml` — optional full YAML override
- `acl_inbound_default`, `acl_outbound_default`, `acl_relay_default`
- `client_config_tcp` — #!TCP directive value for downloaded configs ("" / "supported" / "required")
- `client_config_turn_url` — #!TURN= URL for downloaded configs
- `client_config_skipverifytls` — #!SkipVerifyTLS directive ("" or "yes")
- `client_config_url` — #!URL= value for downloaded configs
- `trusted_proxy_cidrs` — comma/newline separated proxy source CIDRs allowed to supply `X-Forwarded-For` and `X-Forwarded-Proto`
- `web_base_url` — canonical UI base URL including `http://` or `https://`; request-derived when empty
- `http_proxy_access_enabled` — enables authenticated CONNECT proxy access on `/proxy`
- `socket_proxy_enabled`, `socket_proxy_http_port` — enables `/socket` forwarding to a loopback HTTP WireGuard transport listener
- `exposed_services_enabled`, `service_auth_cookie_seconds` — controls Host-based protected service reverse proxying

## Public vs admin config
`publicConfigMap()` returns keys exposed to all authenticated users (used by frontend to build WireGuard configs). `adminConfigMap()` returns all keys (admin-only).

`publicConfigKeys` in `peer_config.go` controls which keys are in the public map.

## Transport system
`TransportConfig` DB model maps to the `transports:` YAML block. On transport create/update/delete, `generateCanonicalYAML()` is called and the daemon is automatically restarted via `restartManagedDaemon()`.

`resolveDefaultTransportNameUI()` picks the transport for the client config Transport= line.

`buildClientConfigText()` (backend) and `buildWireGuardConfig()` (frontend `src/lib/config.js`) both generate the WireGuard config text. They must stay in sync.

## Daemon management
`startManagedDaemon()` spawns `uwgsocks --config uwg_canonical.yaml` as a child process.
`restartManagedDaemon()` regenerates YAML, stops, starts, then re-syncs peers and ACLs.
Peers are pushed live via `/v1/peers`. ACLs are pushed live via `/v1/acls`. Transports require a restart.

## #! directives in client configs
uwgsocks parses `#!` directive lines in WireGuard config files:
- `#!TURN=<url>` in [Interface] — use TURN relay (e.g. `turn+tls://user:pass@host:3478`)
- `#!TCP=required` in [Peer] — require TCP transport
- `#!SkipVerifyTLS=yes` in [Peer] — skip TLS verification
- `#!URL=<url>` in [Peer] — use HTTP/WebSocket URL for transport

These are configurable per-server in GlobalConfig and appended to downloaded client configs.

## IPv6 auto-detection
On first start, `detectIPv6Internet()` is called. If successful, `enable_client_ipv6` defaults to `"true"` and clients get both IPv4 and IPv6 addresses allocated. Otherwise only IPv4. The setting is editable in the admin settings page.

## Frontend
- `src/lib/api.js` — all API calls
- `src/lib/config.js` — `buildWireGuardConfig()`, `downloadConfigFile()`
- `src/components/ConfigModal.jsx` — shows and downloads peer configs
- `src/components/SettingsTab.jsx` — global settings + YAML override + 2FA
- `src/components/TransportsTab.jsx` — transport CRUD
- `src/components/PeersTab.jsx` — peer management

## Build
```bash
./compile.sh          # builds uwgsocks-ui + frontend
cd frontend && npm run build   # frontend only
```

## Run
```bash
./uwgsocks-ui -listen 0.0.0.0:8080
```
Default: sqlite `wgui.db`, auto-discovers `uwgsocks` or `uwgkm` binary alongside itself.
