#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work="$ROOT/.cache/icmp-trace-vm"
stage="$work/root"
mkdir -p "$stage/proc" "$stage/sys" "$stage/dev" "$stage/tmp"
kernel=${LANBOAT_TEST_KERNEL_IMAGE:-$ROOT/.cache/kernel-tls-vm/vmlinuz-$(uname -r)}
[[ -r "$kernel" ]]
command -v qemu-system-x86_64 >/dev/null
: > "$stage/modules.list"
while read -r module; do
 name=$(basename "$module" .ko.zst)
 zstd -q -d -c "$module" > "$stage/$name.ko"
 printf '%s\n' "$name" >> "$stage/modules.list"
done < <(for name in nf_tables nfnetlink_queue nft_queue nft_fib_inet nft_reject_inet nft_ct nft_tproxy; do modprobe --show-depends "$name"; done | awk '$1=="insmod"&&!seen[$2]++{print $2}')
nft=$(command -v nft)
cp --parents "$nft" "$stage"
while read -r library; do
 cp --parents "$library" "$stage"
done < <(ldd "$nft" | awk '{for(i=1;i<=NF;i++)if($i~/^\//)print $i}')
mkdir -p "$stage/etc"
cp /etc/protocols /etc/services "$stage/etc/"
cd "$ROOT"
CGO_ENABLED=0 go build -trimpath -o "$stage/init" ./internal/testicmp
CGO_ENABLED=0 go test -c -o "$stage/native.test" ./native
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o "$stage/lanboat-allinone" ./cmd/lanboat-allinone
(
 cd "$stage"
 find . -print0 | cpio --null -o -H newc --quiet | gzip -1 > "$work/initramfs.gz"
)
timeout 180s qemu-system-x86_64 -nodefaults -no-reboot -nographic -serial stdio -m 512M -smp 2 -cpu max -kernel "$kernel" -initrd "$work/initramfs.gz" -append 'console=ttyS0 panic=-1 quiet' > "$work/output.log" 2>&1
cat "$work/output.log"
rg -q '^LANBOAT_ICMP_TEST_EXIT=0' "$work/output.log"
