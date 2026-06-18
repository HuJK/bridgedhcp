#!/usr/bin/env bash
# Build bridgedhcp static binaries into dist/.
#
#   ./build.sh            # both targets (default)
#   ./build.sh arm64      # GOARCH=arm64 -> dist/bridgedhcp-android-arm64
#   ./build.sh amd64      # GOARCH=amd64 -> dist/bridgedhcp-linux-amd64
#
# CGO is always off so the binaries are fully static (no glibc/bionic linkage),
# which is required to run as the Android root daemon.
set -euo pipefail
cd "$(dirname "$0")"

export CGO_ENABLED=0
LDFLAGS="-s -w"
OUTDIR="dist"
mkdir -p "$OUTDIR"

build_one() {
    local goarch="$1" out="$2"
    echo "Building $out..."
    GOOS=linux GOARCH="$goarch" go build -trimpath -ldflags "$LDFLAGS" -o "$OUTDIR/$out" ./cmd/bridgedhcp
    file "$OUTDIR/$out" | grep -q "statically linked" || { echo "ERROR: $OUTDIR/$out is not statically linked"; exit 1; }
    echo "$OUTDIR/$out: statically linked OK"
}

case "${1:-all}" in
    arm64|aarch64) build_one arm64 bridgedhcp-android-arm64 ;;
    amd64|x64)     build_one amd64 bridgedhcp-linux-amd64 ;;
    all)           build_one arm64 bridgedhcp-android-arm64
                   build_one amd64 bridgedhcp-linux-amd64 ;;
    *)             echo "usage: $0 [all|arm64|amd64]" >&2; exit 2 ;;
esac

echo "Done. Binaries in $OUTDIR/"
