#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

target_os=${1:?usage: package-release.sh OS ARCH}
target_arch=${2:?usage: package-release.sh OS ARCH}
case "$target_os/$target_arch" in
  linux/amd64|linux/arm64|windows/amd64|windows/arm64|darwin/amd64|darwin/arm64) ;;
  *) echo "Unsupported release target: $target_os/$target_arch" >&2; exit 1 ;;
esac

mkdir -p dist
payload=$(mktemp -d)
trap 'rm -rf "$payload"' EXIT
binary=lanboat-allinone-$target_os-$target_arch
if [[ $target_os == windows ]]; then binary+=.exe; fi
CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" \
  go build -mod=readonly -trimpath -buildvcs=false -ldflags '-s -w -buildid=' \
  -o "$payload/$binary" ./cmd/lanboat-allinone

if [[ $target_os == darwin ]]; then
  echo 'UPX disables modern macOS support; publishing the stripped native Mach-O executable.'
else
  upx -9 -q "$payload/$binary"
  upx -t -q "$payload/$binary"
fi

mv "$payload/$binary" "dist/$binary"
(cd dist; sha256sum "$binary" > "$binary.sha256")
echo "$PWD/dist/$binary"
