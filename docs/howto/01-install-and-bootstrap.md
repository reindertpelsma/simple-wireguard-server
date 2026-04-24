<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 01 Install And Bootstrap

Previous: [How-To Index](README.md)  
Next: [02 Users And Client Configs](02-users-and-client-configs.md)

This is the shortest path from a blank host to a running UI.

![Login page](../assets/login.jpg)

## Install The Data Plane

Install `uwgsocks` and `turn` from the main repository:

```bash
curl -fsSL https://raw.githubusercontent.com/reindertpelsma/userspace-wireguard-socks/main/install.sh | sh -s -- uwgsocks
curl -fsSL https://raw.githubusercontent.com/reindertpelsma/userspace-wireguard-socks/main/install.sh | sh -s -- turn
```

## Install The UI

```bash
curl -fsSL https://raw.githubusercontent.com/reindertpelsma/simple-wireguard-server/main/install.sh | sh -s -- uwgsocks-ui
```

Optional Linux kernel-mode helper:

```bash
curl -fsSL https://raw.githubusercontent.com/reindertpelsma/simple-wireguard-server/main/install.sh | sh -s -- uwgkm
```

Windows:

```powershell
curl.exe -fsSLo install.bat https://raw.githubusercontent.com/reindertpelsma/simple-wireguard-server/main/install.bat
install.bat
```

## Start The UI

```bash
uwgsocks-ui -listen 0.0.0.0:8080
```

What happens on first start:

- the UI creates `wgui.db`
- it creates `wgui_secrets.json`
- it prints a bootstrap admin password
- it prints a bootstrap WireGuard client config
- it starts and manages `uwgsocks` automatically

## Log In

Open:

```text
http://YOUR-HOST:8080/login
```

Use the printed bootstrap credentials:

- username: `admin`
- password: the random password printed on stdout

The first useful admin actions are:

1. change the advertised endpoint
2. verify the generated client subnet ranges
3. create a named user
4. create the first non-bootstrap peer

## Build From Source

```bash
./compile.sh
./uwgsocks-ui -listen 0.0.0.0:8080
```

Source builds require Go `1.25+` and Node.js `20.19+`.
