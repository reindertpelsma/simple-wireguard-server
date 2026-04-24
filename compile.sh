#!/bin/sh
set -eu

export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
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

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; fi

if [ "${CGO_ENABLED:-}" = "" ]; then
    if [ "$OS" = "openbsd" ]; then
        export CGO_ENABLED=1
    else
        export CGO_ENABLED=0
    fi
fi

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
            else
                cp ../uwgsocks .
            fi
        fi
    fi
fi

# 2. Build Frontend
echo "Building frontend..."

if ! command -v npm >/dev/null 2>&1; then
  latest_dir() {
    if [ -d "$1" ]; then
      find "$1" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -1
    fi
  }
  nvm_latest="$(latest_dir "${HOME}/.nvm/versions/node")"
  fnm_latest="$(latest_dir "${HOME}/.fnm/node-versions")"
  for candidate in \
    "${nvm_latest:+$nvm_latest/bin}" \
    "${fnm_latest:+$fnm_latest/installation/bin}" \
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

if [ "${UWG_UI_SKIP_FRONTEND_BUILD:-0}" != "1" ]; then
    if ! command -v node >/dev/null 2>&1; then
        echo "Node.js is required for the frontend build. Install Node.js 20.19+." >&2
        exit 127
    fi
    if ! node -e 'const [ma, mi] = process.versions.node.split(".").map(Number); if (ma < 20 || (ma === 20 && mi < 19)) process.exit(1)'; then
        echo "Node.js 20.19+ is required for the frontend build." >&2
        exit 1
    fi
fi

if [ "${UWG_UI_SKIP_FRONTEND_BUILD:-0}" = "1" ]; then
    if [ ! -f "./dist/index.html" ]; then
        echo "UWG_UI_SKIP_FRONTEND_BUILD=1 was set but ./dist is missing. Provide a prebuilt dist/ first." >&2
        exit 1
    fi
    echo "Skipping frontend build and using existing ./dist"
elif [ -d "frontend" ]; then
    rm -rf frontend/dist 2> /dev/null || /bin/true
    if (cd frontend && npm install && npm run build); then
        rm -rf dist 2> /dev/null || /bin/true
        mkdir -p dist
        cp -r frontend/dist/* ./dist/
    else
        echo "Frontend build failed." >&2
        if [ -f "./dist/index.html" ]; then
            echo "Using existing ./dist as fallback." >&2
        else
            exit 1
        fi
    fi
else
    echo "Source frontend dir not found. Skipping frontend build (hope dist exists)."
fi

build_syswg() {
    # 3. Build Binaries
    echo "Building uwgkm (Kernel Manager)..."
    (cd syswg && go build -ldflags="-s -w" -o ../uwgkm main.go || echo "Building syswg failed, will continue without syswg" )
}

if [ "$OS" = "linux" ]; then
    build_syswg
fi

echo "Building uwgsocks-ui binary..."
CGO_ENABLED=0 go build -ldflags="-s -w" -o uwgsocks-ui

echo "Done! Run with: ./uwgsocks-ui -listen 0.0.0.0:8080"
