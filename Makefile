# CGO is always off: every dependency is pure Go, and a static binary is
# required for Android (no glibc/bionic linkage). Don't drop CGO_ENABLED=0 —
# with cgo enabled the stdlib net/os.user packages silently link libc.
export CGO_ENABLED = 0

LDFLAGS := -s -w

.PHONY: build build-android build-linux-amd64 test test-integration vet check-static

build:
	go build ./cmd/bridgedhcp

# Android (root daemon) target: static linux/arm64 binary, no libc.
build-android:
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o bridgedhcp-android-arm64 ./cmd/bridgedhcp
	$(MAKE) check-static BIN=bridgedhcp-android-arm64

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bridgedhcp-linux-amd64 ./cmd/bridgedhcp
	$(MAKE) check-static BIN=bridgedhcp-linux-amd64

# Fails if the produced binary picked up dynamic linkage.
check-static:
	@file "$(BIN)" | grep -q "statically linked" || { echo "ERROR: $(BIN) is not statically linked"; exit 1; }
	@echo "$(BIN): statically linked OK"

vet:
	go vet ./internal/... ./cmd/...

# -race needs cgo; only the test binary links libc, shipped binaries stay
# static (the global CGO_ENABLED=0 still applies to the build targets).
test:
	CGO_ENABLED=1 go test ./internal/... -race -count=1

# Requires root: creates network namespaces and veth pairs.
test-integration: build
	go test ./tests/... -tags=integration -count=1 -v -timeout 10m
