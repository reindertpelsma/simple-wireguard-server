<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# CLI And Environment Reference

`uwgsocks-ui` is normally started as one long-running web process that manages
`uwgsocks` or `uwgkm` as a child daemon.

## Core Flags

| Flag | Purpose |
| --- | --- |
| `-listen` | HTTP or HTTPS listen address. |
| `-data-dir` | Directory that holds `wgui.db`, secrets, generated YAML, and certs. |
| `-manage` | Enables managed child-daemon lifecycle. Defaults to `true`. |
| `-daemon-path` | Explicit path to the `uwgsocks` binary. |
| `-wg-url` | Runtime API URL for the managed daemon. Defaults to `unix://uwgsocks.sock`. |
| `-wg-token` | Runtime API bearer token for TCP-hosted daemon APIs. |
| `-baseline-config` | Baseline YAML merged into the managed daemon config before UI overrides. |
| `-generate-config` | Prints a bootstrap client config on first start. |

## TLS Flags

| Flag | Purpose |
| --- | --- |
| `-tls-cert` | TLS certificate path for direct UI HTTPS serving. |
| `-tls-key` | TLS key path for direct UI HTTPS serving. |
| `-frontend-dir` | Serve a local frontend `dist/` directory instead of the embedded assets. |
| `-extract-dist` | Extract embedded frontend assets and exit. |

## OIDC Flags

| Flag | Purpose |
| --- | --- |
| `-oidc-issuer` | OIDC issuer URL. Enables OIDC when combined with a client ID. |
| `-oidc-client-id` | OIDC client ID. |
| `-oidc-client-secret` | OIDC client secret. |
| `-oidc-redirect-url` | Explicit callback URL. When omitted, the UI derives one from the request or `web_base_url`. |

## Kernel-Mode Flags

| Flag | Purpose |
| --- | --- |
| `-system` | Force kernel-mode `uwgkm` management. Linux-only. |
| `-auto-system` | Auto-detect whether kernel-mode should be used. |

## Managed TURN Flags

| Flag | Purpose |
| --- | --- |
| `-turn-daemon-path` | Explicit path to the `turn` binary. |
| `-turn-api-url` | Managed TURN API URL. Defaults to `unix://turn.sock`. |
| `-turn-api-token` | Managed TURN API bearer token. |
| `-turn-server` | TURN server host:port advertised into client configs. |
| `-turn-user` | TURN username advertised into client configs. |
| `-turn-pass` | TURN password advertised into client configs. |
| `-turn-realm` | TURN realm advertised into client configs. |
| `-turn-include-wg-public-key` | Appends encrypted WireGuard public key metadata to generated TURN usernames. |

## Database Flags

| Flag | Purpose |
| --- | --- |
| `-db-type` | Database backend: `sqlite`, `mysql`, or `postgres`. |
| `-dsn` | Database DSN or sqlite filename. Defaults to `wgui.db`. |

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `OIDC_ISSUER` | Fallback for `-oidc-issuer`. |
| `OIDC_CLIENT_ID` | Fallback for `-oidc-client-id`. |
| `OIDC_CLIENT_SECRET` | Fallback for `-oidc-client-secret`. |
| `OIDC_REDIRECT_URL` | Fallback for `-oidc-redirect-url`. |
| `SYSTEM_MODE=true` | Enables kernel-mode behavior without passing `-system`. |
| `WG_PUBLIC_ENDPOINT` | Overrides the initial default for `server_endpoint` on bootstrap. |
| `WG_CLIENT_DNS` | Overrides the initial default for `client_dns` on bootstrap. |

