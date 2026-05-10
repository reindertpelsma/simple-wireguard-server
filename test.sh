#!/usr/bin/env bash
# test.sh — three-tier test runner for simple-wireguard-server.
#
# Usage:
#   bash test.sh            # all tiers
#   bash test.sh unit       # tier 1 only
#   bash test.sh int        # tier 2 only (sibling-repo build)
#   bash test.sh release    # tier 3 only (latest published release binary)
#   bash test.sh uwgkm      # tier 4 only (kernel-mode WireGuard smoke)
set -euo pipefail

TIER="${1:-all}"

run_unit() {
    echo "=== Tier 1: unit tests ==="
    go test -short -count=1 -timeout 60s ./...
}

run_integration_sibling() {
    echo "=== Tier 2: integration tests (sibling repo build) ==="
    go test -tags integration -count=1 -timeout 300s ./...
}

run_integration_release() {
    echo "=== Tier 3: integration tests (latest published release) ==="
    command -v gh >/dev/null 2>&1 || { echo "gh CLI required for release download" >&2; exit 1; }

    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    arch=$(uname -m)
    case "$arch" in
        x86_64)  arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        *) echo "Unsupported arch: $arch" >&2; exit 1 ;;
    esac
    os=$(uname -s | tr '[:upper:]' '[:lower:]')

    echo "Downloading uwgsocks-${os}-${arch} from latest release..."
    gh release download \
        --repo reindertpelsma/userspace-wireguard-socks \
        --pattern "uwgsocks-${os}-${arch}" \
        --dir "$tmpdir" \
        --clobber
    bin="$tmpdir/uwgsocks-${os}-${arch}"
    chmod +x "$bin"

    echo "Running integration tests with $bin"
    UWGSOCKS_BIN="$bin" go test -tags integration -count=1 -timeout 300s ./...
}

run_uwgkm() {
    echo "=== Tier 4: uwgkm kernel-mode smoke test ==="
    go test -tags integration -count=1 -timeout 60s -run TestIntegrationUwgKM ./...
}

case "$TIER" in
    unit)    run_unit ;;
    int)     run_integration_sibling ;;
    release) run_integration_release ;;
    uwgkm)   run_uwgkm ;;
    all)
        run_unit
        run_integration_sibling
        run_integration_release
        run_uwgkm
        ;;
    *)
        echo "Unknown tier: $TIER. Use: unit | int | release | uwgkm | all" >&2
        exit 1
        ;;
esac
echo "=== All requested tests passed ==="
