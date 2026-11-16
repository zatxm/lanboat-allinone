#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o build/lanboat-allinone ./cmd/lanboat-allinone

# Check the linked package graph, rather than assuming unused go.mod entries are linked.
go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./cmd/lanboat-allinone > build/dependencies.txt
if grep -Ev '^(github.com/zatxm/lanboat-allinone/(native|internal/nativecmd|cmd/lanboat-allinone)|go.uber.org/(zap|multierr)(/.*)?|github.com/andybalholm/brotli(/matchfinder)?|github.com/klauspost/compress(/(zstd(/internal/xxhash)?|fse|huff0|internal/(cpuinfo|le|raceinfo|snapref|regmask)))?)?$' build/dependencies.txt; then
  echo 'Independent build unexpectedly imports an unapproved third-party package' >&2
  exit 1
fi
sha256sum build/lanboat-allinone > build/SHA256SUMS
