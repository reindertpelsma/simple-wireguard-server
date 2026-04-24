<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 08 Kernel Mode With Uwgkm

Previous: [07 OIDC Login](07-oidc-login.md)  
Next: [09 Managed TURN Hosting](09-managed-turn-hosting.md)

The default path is rootless `uwgsocks`. `uwgkm` is the Linux kernel-mode
alternative when you explicitly want kernel WireGuard managed from the same UI.

![Settings page](../assets/settings.jpg)

## When To Use It

Use `uwgkm` when:

- you want kernel WireGuard on Linux
- you are comfortable with the extra privilege model
- you do not need the rootless userspace-first deployment shape

Stay on `uwgsocks` when:

- you want rootless operation
- you are running in containers or CI
- you want the userspace proxy and interception-first model

## Start In Kernel Mode

```bash
uwgsocks-ui -system
```

Or let the UI auto-detect:

```bash
uwgsocks-ui -auto-system
```

See [../reference/uwgkm.md](../reference/uwgkm.md) for the daemon-selection
rules and operational tradeoffs.
