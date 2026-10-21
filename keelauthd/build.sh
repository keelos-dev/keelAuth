#!/bin/sh
# Build keelauthd for keelAuth (FreeBSD amd64, static, no cgo) into keelauthd/keelauthd; vet and test first.
#   keelauthd/build.sh            the image build (tools/image) installs keelauthd/keelauthd as /usr/local/sbin/keelauthd
set -e
cd "$(dirname "$0")"
GO=${GO:-$(command -v go || echo "$HOME/.local/go/bin/go")}
V=${VERSION:-$(git describe --always --dirty 2>/dev/null || echo dev)}
$GO vet ./...
$GO test ./...
GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 $GO build -trimpath -ldflags "-s -w -X main.version=$V" -o keelauthd ./cmd/keelauthd
echo "keelauthd $V: $(ls -l keelauthd | awk '{print $5}') bytes"
