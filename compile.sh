#!/bin/bash
set -e

export CGO_ENABLED=0
# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
if [ "$ARCH" == "x86_64" ]; then ARCH="amd64"; fi

if [ ! -f "./uwgsocks" ]; then
    if [ ! -f "../uwgsocks" ]; then
        echo "uwgsocks binary not found in parent dir. Hoping the uwgsocks source code is in the parent directory"
        cd .. && go build -o uwgsocks ./cmd/uwgsocks && cd uwgsocks-ui
    fi
    cp ../uwgsocks .
fi

# 2. Build Frontend
echo "Building frontend..."
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

# 3. Build Binaries
echo "Building uwgkm (Kernel Manager)..."
echo "Note if this fails, then you can comment out this binary in compile.sh when you do not need kernel-based Wireguard that requires root"
cd syswg && go build -ldflags="-s -w" -o ../uwgkm main.go && cd ..

echo "Building uwgsocks-ui binary..."
CGO_ENABLED=1 go build -ldflags="-s -w" -o uwgsocks-ui

echo "Done! Run with: ./uwgsocks-ui -listen 0.0.0.0:8080"
