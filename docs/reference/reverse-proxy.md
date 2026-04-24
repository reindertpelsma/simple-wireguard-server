<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Reverse Proxy Reference

`uwgsocks-ui` is designed to sit behind a normal HTTPS reverse proxy.

## Trust Model

Two settings matter:

- `trusted_proxy_cidrs`
- `web_base_url`

`trusted_proxy_cidrs` controls which proxy source addresses may supply
forwarded client IP and scheme headers. `web_base_url` controls the canonical
external URL used for generated links, redirects, OIDC callbacks, and
single-domain transport profiles.

## Recommended Topology

```text
Internet -> HTTPS reverse proxy -> uwgsocks-ui -> managed uwgsocks / turn
```

Run the UI on loopback or a private interface and terminate public TLS on the
edge proxy.

## Why `web_base_url` Matters

Without `web_base_url`, the UI has to derive its external origin from the
incoming request. That is fragile when:

- a load balancer rewrites headers
- there are multiple public hostnames
- OIDC callback URLs must be exact
- generated `/socket` transport URLs must point to the public origin

Set it to the final public origin, for example:

```text
https://wireguard.example.com
```

## Why `trusted_proxy_cidrs` Matters

Without `trusted_proxy_cidrs`, forwarded headers are ignored. That keeps the UI
safe by default, but it also means:

- client IPs look like the proxy IP
- scheme detection may fall back to `http`
- origin-derived URLs may be wrong

Set it to the exact proxy or load balancer source ranges, not `0.0.0.0/0`
unless that is genuinely the only trust model you want.

