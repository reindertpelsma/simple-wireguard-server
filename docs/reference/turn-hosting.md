<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Managed TURN Hosting Reference

`uwgsocks-ui` can manage a child `turn` daemon and issue TURN credentials to
users from the same browser UI.

## What Is Stored In The UI

The UI stores and manages:

- TURN listeners
- TURN realm
- relay IP override
- per-user TURN credentials
- optional self-service credential issuance
- relay port ranges

## Listener Types

Managed listeners support:

- `udp`
- `tcp`
- `tls`
- `dtls`
- `http`
- `https`
- `quic`

HTTP, HTTPS, and QUIC listeners default to `/turn` unless a custom path is
configured.

## Credential Model

Each TURN credential belongs to a UI user. The UI can:

- create credentials as an admin
- optionally allow self-service credential creation
- attach a WireGuard public key hint to the TURN username
- expose connection profiles back to the user

## Relevant GlobalConfig Keys

- `turn_hosting_enabled`
- `turn_hosting_realm`
- `turn_hosting_relay_ip`
- `turn_allow_user_credentials`
- `turn_max_user_credentials`
- `turn_user_port_start`
- `turn_user_port_end`

## Managed Runtime

The UI writes `turn_canonical.yaml` and starts the `turn` child daemon when
TURN hosting is enabled. Listener changes trigger daemon restarts; status and
credential activity are surfaced back through the UI.

