<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Uwgkm Mode Reference

`uwgkm` is the Linux kernel-mode manager that `uwgsocks-ui` can launch instead
of the default userspace `uwgsocks` child.

## Default Behavior

By default, the UI manages `uwgsocks`:

- rootless-first
- userspace networking
- proxy, service, and transport-centric workflow

## Kernel Mode

Use `-system` or `-auto-system` when you want the UI to manage `uwgkm`.

This is appropriate when:

- the host is Linux
- you want kernel WireGuard
- your deployment model accepts the required privilege level

## Operational Difference

`uwgsocks` is the better default for:

- containers
- CI jobs
- rootless deployments
- userspace proxy-first deployments

`uwgkm` is for:

- Linux hosts with kernel WireGuard available
- environments that prefer kernel interfaces over the userspace model

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/reindertpelsma/simple-wireguard-server/main/install.sh | sh -s -- uwgkm
```

