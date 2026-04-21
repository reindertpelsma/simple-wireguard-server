#!/usr/bin/env bash
set -euo pipefail

export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

if ! command -v go >/dev/null 2>&1; then
  if [ -x "${HOME}/sdk/go/bin/go" ]; then
    export PATH="${HOME}/sdk/go/bin:${PATH}"
  fi
fi

if ! command -v go >/dev/null 2>&1; then
  echo "Go toolchain not found on PATH. Install Go 1.25+ or add it to PATH." >&2
  exit 127
fi

export CGO_ENABLED=0

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
if [ "$ARCH" == "x86_64" ]; then ARCH="amd64"; fi

if [ ! -f "./uwgsocks" ]; then
    if [ -d "./userspace-wireguard-socks" ]; then
        if [ ! -f "./userspace-wireguard-socks/uwgsocks" ]; then
            (cd userspace-wireguard-socks && go build -o uwgsocks ./cmd/uwgsocks)
        fi
        cp ./userspace-wireguard-socks/uwgsocks .
    else
        if [ -d "../userspace-wireguard-socks" ]; then
            if [ ! -f ../userspace-wireguard-socks/uwgsocks ]; then
                (cd ../userspace-wireguard-socks && go build -o uwgsocks ./cmd/uwgsocks)
            fi
            cp ../userspace-wireguard-socks/uwgsocks .
        else
            if [ ! -f "../uwgsocks" ]; then
                if [ -f "../uwgsocks.go" ]; then
                    cd .. && go build -o uwgsocks ./cmd/uwgsocks && cd uwgsocks-ui
                else
                    echo "uwgsocks not found, either clone as sub repo in this folder, put it on the parent folder, or make this a sub folder of the uwgsocks"
                    echo "Continuing building without uwgsocks"
                fi
            fi
            cp ../uwgsocks .
        fi
    fi
fi

# 2. Build Frontend
echo "Building frontend..."

if ! command -v npm >/dev/null 2>&1; then
  for candidate in \
    "${HOME}/.nvm/versions/node/$(ls "${HOME}/.nvm/versions/node/" 2>/dev/null | sort -V | tail -1)/bin" \
    "${HOME}/.fnm/node-versions/$(ls "${HOME}/.fnm/node-versions/" 2>/dev/null | sort -V | tail -1)/installation/bin" \
    "${HOME}/.volta/bin" \
    "/opt/homebrew/bin" \
    "/usr/local/bin" \
    "/usr/local/opt/node/bin"; do
    if [ -x "${candidate}/npm" ]; then
      export PATH="${candidate}:${PATH}"
      break
    fi
  done
fi

if [ -d "frontend" ]; then
    rm -rf frontend/dist 2> /dev/null || /bin/true
    cd frontend && npm install && npm run build
    cd ../
    rm -rf dist 2> /dev/null || /bin/true
    mkdir -p dist
    cp -r frontend/dist/* ./dist/
else
    echo "Source frontend dir not found. Skipping frontend build (hope dist exists)."
fi

build_syswg() {
    # 3. Build Binaries
    echo "Building uwgkm (Kernel Manager)..."
    (cd syswg && go build -ldflags="-s -w" -o ../uwgkm main.go || echo "Building syswg failed, will continue without syswg" )
}

if [ "$OS" == "linux" ]; then
    build_syswg
fi

echo "Building uwgsocks-ui binary..."
CGO_ENABLED=0 go build -ldflags="-s -w" -o uwgsocks-ui

echo "Done! Run with: ./uwgsocks-ui -listen 0.0.0.0:8080"
