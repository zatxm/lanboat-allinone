#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work="$ROOT/.cache/generic-mux-migration/kernel-vm"
stage="$work/root"
: "${LANBOAT_TEST_KERNEL_IMAGE:?set a readable Linux kernel image}"
: "${LANBOAT_TEST_BRUTAL_MODULE:?set brutal.ko built for that kernel}"
command -v qemu-system-x86_64 >/dev/null
mkdir -p "$stage"/{proc,sys,dev,tmp}
cp -- "$LANBOAT_TEST_BRUTAL_MODULE" "$stage/brutal.ko"
rm -f -- "$stage/sing-box"
if [[ -n "${LANBOAT_TEST_SINGBOX15:-}" ]]; then
 cp -- "$LANBOAT_TEST_SINGBOX15" "$stage/sing-box"
 while IFS= read -r library; do
  mkdir -p -- "$stage$(dirname -- "$library")"
  cp -L -- "$library" "$stage$library"
 done < <(ldd "$LANBOAT_TEST_SINGBOX15" | awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}')
fi
cd "$ROOT"
CGO_ENABLED=0 go build -trimpath -o "$stage/init" ./internal/testkernel
CGO_ENABLED=0 go test -c -o "$stage/native.test" ./native
(
 cd "$stage"
 find . -print0 | cpio --null -o -H newc --quiet | gzip -1 > "$work/initramfs.gz"
)
accel=tcg
if [[ -r /dev/kvm && -w /dev/kvm ]]; then accel=kvm; fi
timeout 120s qemu-system-x86_64 -nodefaults -no-reboot -nographic -serial stdio -accel "$accel" -m 384M -smp 2 -cpu max -kernel "$LANBOAT_TEST_KERNEL_IMAGE" -initrd "$work/initramfs.gz" -append 'console=ttyS0 panic=-1 quiet lanboat_test_brutal=1' > "$work/output.log" 2>&1
cat "$work/output.log"
rg -q '^LANBOAT_KERNEL_TEST_EXIT=0' "$work/output.log"
