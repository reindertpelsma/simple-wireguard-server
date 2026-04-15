#!/bin/bash
set -e

export CGO_ENABLED=0
# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
if [ "$ARCH" == "x86_64" ]; then ARCH="amd64"; fi

# 1. Ensure uwgsocks exists
if [ ! -f "../uwgsocks" ]; then
    echo "uwgsocks binary not found in parent dir. Attempting to build from source..."
    cd .. && go build -o uwgsocks ./cmd/uwgsocks && cd uwgsocks-ui
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
cd syswg && go build -ldflags="-s -w" -o ../uwgkm main.go && cd ..

echo "Building uwgsocks-ui binary..."
CGO_ENABLED=1 go build -ldflags="-s -w" -o uwgsocks-ui main.go

echo "Done! Run with: ./uwgsocks-ui -listen 0.0.0.0:8080"
