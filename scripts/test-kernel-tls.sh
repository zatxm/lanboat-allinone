#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work="$ROOT/.cache/kernel-tls-vm"
stage="$work/root"
mkdir -p "$stage" "$stage/proc" "$stage/sys" "$stage/dev" "$stage/tmp"
release=${LANBOAT_TEST_KERNEL_RELEASE:-$(uname -r)}
kernel=${LANBOAT_TEST_KERNEL_IMAGE:-}
if [[ -z "$kernel" ]]; then
  kernel="$work/vmlinuz-$release"
  if [[ ! -r "$kernel" && -r "/boot/vmlinuz-$release" ]]; then
    kernel="/boot/vmlinuz-$release"
  fi
fi
if [[ ! -r "$kernel" ]]; then
  printf 'Set LANBOAT_TEST_KERNEL_IMAGE to a readable Linux kernel matching /lib/modules/%s\n' "$release" >&2
  exit 1
fi
command -v qemu-system-x86_64 >/dev/null
for name in gf128mul aesni-intel chacha chacha20poly1305 tls; do
  module=$(find "/lib/modules/$release/kernel" -name "$name.ko.zst" -print -quit)
  [[ -n "$module" ]]
  zstd -q -d -c "$module" > "$stage/$name.ko"
done
cd "$ROOT"
CGO_ENABLED=0 go build -trimpath -o "$stage/init" ./internal/testkernel
CGO_ENABLED=0 go test -c -o "$stage/native.test" ./native
(
  cd "$stage"
  find . -print0 | cpio --null -o -H newc --quiet | gzip -1 > "$work/initramfs.gz"
)
timeout 120s qemu-system-x86_64 -nodefaults -no-reboot -nographic -serial stdio -m 384M -smp 2 -cpu max -kernel "$kernel" -initrd "$work/initramfs.gz" -append 'console=ttyS0 panic=-1 quiet' > "$work/output.log" 2>&1
cat "$work/output.log"
rg -q '^LANBOAT_KERNEL_TEST_EXIT=0' "$work/output.log"
