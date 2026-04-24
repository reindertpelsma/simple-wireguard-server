<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# UI Config Reference

This page documents the `GlobalConfig` keys stored by `uwgsocks-ui`. These are
the settings you change through the admin UI and that the backend persists in
the database.

Derived public fields such as `client_transport_profiles`,
`client_config_control_url`, and `turn_listener_count` are computed at runtime
and are not stored as `GlobalConfig` rows.

## Server Identity And Transport Defaults

| Key | Purpose |
| --- | --- |
| `server_privkey` | Managed daemon private key. Stored server-side only. |
| `server_pubkey` | Public key published into client configs. |
| `server_endpoint` | Advertised server endpoint for downloaded client configs. |
| `default_transport` | Preferred transport profile for generated client configs. |
| `global_mtu` | MTU written into generated client configs. |

## Addressing And Client Routes

| Key | Purpose |
| --- | --- |
| `client_dns` | DNS server address written into generated client configs. |
| `client_allowed_ips` | `AllowedIPs` written into the server peer block in generated client configs. |
| `client_subnet_ipv4` | Legacy flat IPv4 peer pool for peers without a group subnet. |
| `client_subnet_ipv6` | Legacy flat IPv6 peer pool for peers without a group subnet. |
| `enable_client_ipv6` | Enables IPv6 address allocation for peers. |
| `group_base_subnet` | IPv4 pool used for auto-assigned per-group subnets. |
| `group_subnet_bits` | Prefix length of each auto-assigned IPv4 group subnet. |
| `group_base_subnet_ipv6` | IPv6 pool used for auto-assigned per-group subnets. |
| `group_subnet_ipv6_bits` | Prefix length of each auto-assigned IPv6 group subnet. |

## Visibility And Client Ownership

| Key | Purpose |
| --- | --- |
| `public_keys_visible` | Allows non-admin users to view peer public keys in the UI. |
| `endpoints_visible` | Allows non-admin users to view peer endpoint information in the UI. |
| `peers_visible_to_all` | Controls whether users can see peers beyond their own ownership scope. |
| `allow_custom_private_key` | Allows a user-supplied private key during peer creation. |
| `e2e_encryption_enabled` | Enables at-rest private key protection for downloadable configs and stored peer material. |

## Peer Sync And Multi-Server Coordination

| Key | Purpose |
| --- | --- |
| `peer_sync_mode` | Controls whether peer sync is disabled, enabled for everyone, or opt-in. |
| `peer_sync_port` | Port used for the UI-generated peer sync control URL. |

## Generated Daemon YAML

These settings feed the canonical `uwg_canonical.yaml` that the UI writes for
the managed `uwgsocks` child.

| Key | Purpose |
| --- | --- |
| `yaml_l3_forwarding` | Enables layer-3 forwarding in the managed daemon config. |
| `yaml_block_rfc` | Blocks RFC-reserved ranges from leaking to direct fallback paths. |
| `yaml_host_forward_redirect_ip` | Loopback or host IP used for host-forward redirects. |
| `yaml_socks5_port` | Local SOCKS5 listener port for the managed daemon. |
| `yaml_http_port` | Local HTTP proxy listener port for the managed daemon. |
| `yaml_proxy_username` | Optional upstream proxy username used by the UI’s own `/proxy` relay path. |
| `yaml_proxy_password` | Optional upstream proxy password paired with `yaml_proxy_username`. |
| `yaml_inbound_transparent` | Enables transparent inbound termination in the managed daemon. |
| `yaml_socks5_udp` | Enables SOCKS5 UDP ASSOCIATE on the managed daemon. |
| `custom_yaml_enabled` | Switches the daemon config generator into custom YAML override mode. |
| `custom_yaml` | Full canonical YAML override body. |
| `acl_inbound_default` | Default inbound ACL action pushed to `uwgsocks`. |
| `acl_outbound_default` | Default outbound ACL action pushed to `uwgsocks`. |
| `acl_relay_default` | Default relay ACL action pushed to `uwgsocks`. |

## Downloaded Client Directives

These settings control extra `#!` directives appended to generated configs for
`uwgsocks`-aware clients.

| Key | Purpose |
| --- | --- |
| `client_config_tcp` | `#!TCP=` mode for generated configs. |
| `client_config_turn_url` | `#!TURN=` URL for generated configs. |
| `client_config_skipverifytls` | `#!SkipVerifyTLS=` directive for generated configs. |
| `client_config_url` | `#!URL=` directive for generated configs. |

## Web Edge, Reverse Proxy, And Browser Access

| Key | Purpose |
| --- | --- |
| `trusted_proxy_cidrs` | Reverse proxy CIDRs allowed to supply forwarded client IP and scheme headers. |
| `web_base_url` | Canonical external base URL used for redirects, callbacks, and generated URLs. |
| `http_proxy_access_enabled` | Enables authenticated HTTP CONNECT access on `/proxy`. |
| `socket_proxy_enabled` | Enables the single-domain `/socket` transport path. |
| `socket_proxy_http_port` | Local loopback HTTP listener port used behind `/socket`. |
| `exposed_services_enabled` | Enables published service reverse proxying through UI hostnames. |
| `service_auth_cookie_seconds` | Lifetime of service access cookies issued after UI auth. |

## Auth And Session Lifetime

| Key | Purpose |
| --- | --- |
| `auth_sudo_timeout_seconds` | Duration a recent-password check remains valid for privileged actions. |
| `auth_session_timeout_seconds` | Session lifetime for browser login cookies. |

## Managed TURN Hosting

| Key | Purpose |
| --- | --- |
| `turn_hosting_enabled` | Enables management and startup of the child TURN daemon. |
| `turn_hosting_realm` | TURN realm returned by the managed daemon. |
| `turn_hosting_relay_ip` | Public relay IP advertised by the managed TURN daemon. |
| `turn_allow_user_credentials` | Allows non-admin users to create their own TURN credentials. |
| `turn_max_user_credentials` | Maximum TURN credentials per user. |
| `turn_user_port_start` | Start of the per-user relay port range. |
| `turn_user_port_end` | End of the per-user relay port range. |

