#!/bin/bash
set -e

export CGO_ENABLED=0
# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
if [ "$ARCH" == "x86_64" ]; then ARCH="amd64"; fi

if [ ! -f "./uwgsocks" ]; then
    if [ -d "./userspace-wireguard-socks"]; then
        if [ ! -f "./userspace-wireguard-socks/uwgsocks"]; then
            (cd userspace-wireguard-socks && go build -o uwgsocks ./cmd/uwgsocks)
        fi
        cp ./userspace-wireguard-socks/uwgsocks .
    else
        if [ -d "../userspace-wireguard-socks"]; then
            if [ ! -f ../userspace-wireguard-socks/uwgsocks ]; then
                (cd ../userspace-wireguard-socks && go build -o uwgsocks ./cmd/uwgsocks)
            fi
            cp ../userspace-wireguard-socks/uwgsocks .
        else
            if [ ! -f "../uwgsocks" ]; then
                if [ -f "../uwgsocks.go"]; then
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
