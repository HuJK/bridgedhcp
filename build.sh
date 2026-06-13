#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

export CGO_ENABLED=0
LDFLAGS="-s -w"
OUTDIR="build"

mkdir -p "$OUTDIR"

echo "Building bridgedhcp-android-arm64..."
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$LDFLAGS" -o "$OUTDIR/bridgedhcp-android-arm64" ./cmd/bridgedhcp

echo "Building bridgedhcp-linux-amd64..."
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o "$OUTDIR/bridgedhcp-linux-amd64" ./cmd/bridgedhcp

for bin in "$OUTDIR"/bridgedhcp-*; do
    file "$bin" | grep -q "statically linked" || { echo "ERROR: $bin is not statically linked"; exit 1; }
    echo "$bin: statically linked OK"
done

echo "Done. Binaries in $OUTDIR/"
