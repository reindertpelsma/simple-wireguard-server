<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Testing

This repository has two layers of automated validation:

- backend and integration tests for `uwgsocks-ui`
- frontend lint and Vitest coverage for the React UI

## Local Validation

Build the frontend first, or use `./compile.sh`, because the Go binary embeds
`dist/*`.

```bash
./compile.sh
go test ./...

cd frontend
npm run lint
npx vitest run
```

If you want the exact sequence used in this sandbox, the following passed after
building the frontend with Node.js `22.14.0`:

```bash
./compile.sh
go test ./...
cd frontend && npm run lint
cd frontend && npx vitest run
```

## What The Go Suite Covers

The Go test suite covers:

- login and session flows
- TOTP and OIDC callback handling
- peer, user, ACL, forward, and transport CRUD
- canonical YAML generation
- child daemon restart wiring
- public shared-config access
- `/proxy` and `/socket` handling
- exposed service reverse proxy behavior
- TURN listener and credential management
- end-to-end managed-daemon smoke paths through a real `uwgsocks` child process

## What The Frontend Suite Covers

The frontend suite currently covers:

- login page behavior
- client config generation helpers

Linting also runs across the React codebase.

## Platform Notes

- Linux, macOS, Windows, and FreeBSD are the primary tested platforms.
- Linux is the only platform that can use `uwgkm`.
- Source builds need Node.js `20.19+` because the current Vite toolchain no
  longer supports Node 18.
- OpenBSD remains a special case for source builds because it may need a
  prebuilt frontend `dist/`.

## CI Shape

The repository CI already builds the frontend before backend tests and release
packaging. That is important, because `go test ./...` on a fresh clone will
otherwise fail until `dist/` exists.
