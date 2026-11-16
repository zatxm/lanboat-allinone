#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -z ${LANBOAT_TEST_REFERENCE:-} || ! -x ${LANBOAT_TEST_REFERENCE:-} ]]; then
  echo 'Set LANBOAT_TEST_REFERENCE to an executable sing-box-compatible reference; interoperability tests must not be skipped.' >&2
  exit 1
fi
if [[ -z ${LANBOAT_TEST_GOST:-} || ! -x ${LANBOAT_TEST_GOST:-} ]]; then
  echo 'Set LANBOAT_TEST_GOST to an official GOST executable for Relay interoperability.' >&2
  exit 1
fi
if [[ -z ${LANBOAT_TEST_BROOK:-} || ! -x ${LANBOAT_TEST_BROOK:-} ]]; then
  echo 'Set LANBOAT_TEST_BROOK to an official Brook executable for client/server TCP/UDP interoperability.' >&2
  exit 1
fi
if [[ -z ${LANBOAT_TEST_BROOK_SIMPLE:-} ]]; then
  export LANBOAT_TEST_BROOK_SIMPLE
  LANBOAT_TEST_BROOK_SIMPLE=$(python3 tests/prepare-brook-simple-reference.py)
fi
if [[ ! -x ${LANBOAT_TEST_BROOK_SIMPLE:-} ]]; then
  echo 'LANBOAT_TEST_BROOK_SIMPLE must retain the upstream simple protocol.' >&2
  exit 1
fi
if [[ -z ${LANBOAT_TEST_SINGBOX15:-} || ! -x ${LANBOAT_TEST_SINGBOX15:-} ]]; then
  echo 'Set LANBOAT_TEST_SINGBOX15 to an official1.15 reference for Shadowsocks2022 interoperability.' >&2
  exit 1
fi
if [[ ! -x ${LANBOAT_TEST_TRUST_SERVER:-} || ! -x ${LANBOAT_TEST_TRUST_CLIENT:-} ]]; then
 echo 'Set LANBOAT_TEST_TRUST_SERVER and LANBOAT_TEST_TRUST_CLIENT to official TrustTunnel endpoint/client executables.' >&2
 exit 1
fi
python3 -c 'from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305'
if [[ -z ${LANBOAT_TEST_SUDOKU:-} ]]; then
 export LANBOAT_TEST_SUDOKU
 LANBOAT_TEST_SUDOKU=$(python3 tests/prepare-sudoku-reference.py)
fi
if [[ ! -x ${LANBOAT_TEST_SUDOKU:-} ]]; then
 echo 'LANBOAT_TEST_SUDOKU must be the pinned external Sudoku reference.' >&2
 exit 1
fi
if [[ -z ${LANBOAT_TEST_SNELL_DIR:-} || ! -x ${LANBOAT_TEST_SNELL_DIR:-}/4.1.1/snell-server || ! -x ${LANBOAT_TEST_SNELL_DIR:-}/5.0.1/snell-server || ! -x ${LANBOAT_TEST_SNELL_DIR:-}/legacy-server ]]; then
  echo 'Set LANBOAT_TEST_SNELL_DIR to the official Snell reference directory (legacy-server, 4.1.1, 5.0.1).' >&2
  exit 1
fi
if [[ -z ${LANBOAT_TEST_SSR:-} || ! -f ${LANBOAT_TEST_SSR:-}/shadowsocks/server.py ]]; then
  echo 'Set LANBOAT_TEST_SSR to the Python SSR reference checkout.' >&2
  exit 1
fi
if [[ ! -f ${LANBOAT_TEST_SS_OTA:-}/shadowsocks/tcprelay.py ]]; then
  echo 'Set LANBOAT_TEST_SS_OTA to the official Shadowsocks2.9.1 source directory for legacy OTA interoperability.' >&2
  exit 1
fi
if [[ -z ${LANBOAT_TEST_QUIC:-} ]]; then
  mkdir -p .cache/quic-reference
  go build -C tests/quic-reference -trimpath -o ../../.cache/quic-reference/quic-reference .
  export LANBOAT_TEST_QUIC="$PWD/.cache/quic-reference/quic-reference"
fi
if [[ -z ${LANBOAT_TEST_QUIC_CAPTURES:-} ]]; then
  export LANBOAT_TEST_QUIC_CAPTURES
  LANBOAT_TEST_QUIC_CAPTURES=$(python3 tests/prepare-quic-client-captures.py)
fi
if [[ -z ${LANBOAT_TEST_CHROME_CAPTURE:-} ]]; then
  export LANBOAT_TEST_CHROME_CAPTURE
  LANBOAT_TEST_CHROME_CAPTURE=$(python3 tests/capture-quic-chrome.py)
fi
if [[ -z ${LANBOAT_TEST_UQUIC:-} ]]; then
  mkdir -p .cache/quic-client
  go build -C tests/quic-client-reference -trimpath -o ../../.cache/quic-client/uquic-reference .
  export LANBOAT_TEST_UQUIC="$PWD/.cache/quic-client/uquic-reference"
fi
if [[ ! -x ${LANBOAT_TEST_TUIC4:-} || ! -x ${LANBOAT_TEST_TUIC4_CLIENT:-} ]]; then
 echo 'Set LANBOAT_TEST_TUIC4 and LANBOAT_TEST_TUIC4_CLIENT to TUIC 0.8.5 reference server/client executables.' >&2
 exit 1
fi
if [[ ! -x ${LANBOAT_TEST_JUICITY:-} || ! -x ${LANBOAT_TEST_JUICITY_CLIENT:-} ]]; then
 echo 'Set LANBOAT_TEST_JUICITY and LANBOAT_TEST_JUICITY_CLIENT to reference Juicity server/client executables.' >&2
 exit 1
fi
if [[ -z ${LANBOAT_TEST_MIERU:-} ]]; then
 mkdir -p .cache/mieru-reference
 go build -C tests/mieru-reference -trimpath -o ../../.cache/mieru-reference/reference .
 export LANBOAT_TEST_MIERU="$PWD/.cache/mieru-reference/reference"
fi
if [[ ! -x ${LANBOAT_TEST_MIERU:-} ]]; then
 echo 'LANBOAT_TEST_MIERU must be the separately built Mieru3.38.0 reference.' >&2
 exit 1
fi
if [[ -z ${LANBOAT_TEST_MASQUE:-} ]]; then
 mkdir -p .cache/masque-reference
 go build -C tests/masque-reference -trimpath -o ../../.cache/masque-reference/masque-reference .
 export LANBOAT_TEST_MASQUE="$PWD/.cache/masque-reference/masque-reference"
fi
if [[ ! -x ${LANBOAT_TEST_MASQUE:-} ]]; then
 echo "LANBOAT_TEST_MASQUE must be an external MASQUE reference executable" >&2
 exit 1
fi
if [[ -z ${LANBOAT_TEST_OPENCONNECT:-} ]]; then
 export LANBOAT_TEST_OPENCONNECT
 LANBOAT_TEST_OPENCONNECT=$(python3 tests/prepare-openconnect-reference.py)
fi
if [[ ! -x ${LANBOAT_TEST_OPENCONNECT:-}/usr/sbin/openconnect || ! -x ${LANBOAT_TEST_OPENCONNECT:-}/usr/sbin/ocserv ]]; then
 echo 'LANBOAT_TEST_OPENCONNECT must contain official OpenConnect/ocserv reference binaries.' >&2
 exit 1
fi
if [[ -z ${LANBOAT_TEST_KERBEROS:-} ]]; then
 export LANBOAT_TEST_KERBEROS
 LANBOAT_TEST_KERBEROS=$(python3 tests/prepare-kerberos-reference.py)
fi
if [[ ! -x ${LANBOAT_TEST_KERBEROS:-}/usr/sbin/krb5kdc || ! -x ${LANBOAT_TEST_KERBEROS:-}/usr/bin/kinit.mit || ! -f ${LANBOAT_TEST_KERBEROS:-}/usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2 ]]; then
 echo 'LANBOAT_TEST_KERBEROS must contain the pinned test-only MIT KDC/GSSAPI reference.' >&2
 exit 1
fi
command -v openssl >/dev/null
command -v avahi-daemon >/dev/null
command -v dnsmasq >/dev/null
command -v dbus-daemon >/dev/null
command -v busctl >/dev/null
if [[ -z ${LANBOAT_TEST_SHADOWTLS:-} ]]; then
  export LANBOAT_TEST_SHADOWTLS
  LANBOAT_TEST_SHADOWTLS=$(python3 tests/prepare-shadowtls-reference.py)
fi
if [[ ! -x ${LANBOAT_TEST_SHADOWTLS:-} || ! -x $(dirname "$LANBOAT_TEST_SHADOWTLS")/shadow-tls-test-ca ]]; then
  echo 'LANBOAT_TEST_SHADOWTLS requires both pinned ShadowTLS server and test-CA client references.' >&2
  exit 1
fi
if [[ ! -x ${LANBOAT_TEST_XRAY:-} ]]; then
  echo 'Set LANBOAT_TEST_XRAY to an external Xray reference for VMess/VLESS Mux.Cool interoperability.' >&2
  exit 1
fi
if [[ -z ${LANBOAT_TEST_SIP003:-} ]]; then
  export LANBOAT_TEST_SIP003
  LANBOAT_TEST_SIP003=$(python3 tests/prepare-sip003-reference.py)
fi
if [[ ! -x ${LANBOAT_TEST_SIP003:-}/root/usr/bin/obfs-server || ! -x ${LANBOAT_TEST_SIP003:-}/v2ray-plugin_linux_amd64 ]]; then
  echo 'LANBOAT_TEST_SIP003 must contain pinned simple-obfs and v2ray-plugin references.' >&2
  exit 1
fi
command -v ssh >/dev/null
command -v sshd >/dev/null
command -v wg >/dev/null
if [[ -z ${LANBOAT_TEST_AMNEZIA:-} ]]; then
  export LANBOAT_TEST_AMNEZIA
  LANBOAT_TEST_AMNEZIA=$(bash tests/prepare-amnezia-reference.sh)
fi
if [[ ! -x ${LANBOAT_TEST_AMNEZIA:-} ]]; then
  echo 'LANBOAT_TEST_AMNEZIA must be an executable official AmneziaWG reference.' >&2
  exit 1
fi
if [[ -z ${LANBOAT_TEST_WGOBFS:-} ]]; then
  export LANBOAT_TEST_WGOBFS
  LANBOAT_TEST_WGOBFS=$(python3 tests/prepare-wgobfs-reference.py)
fi
if [[ ! -x ${LANBOAT_TEST_WGOBFS:-} ]]; then
  echo 'LANBOAT_TEST_WGOBFS must be an executable rs-wgobfs reference.' >&2
  exit 1
fi
if [[ -z ${LANBOAT_TEST_LUA:-} ]]; then
  export LANBOAT_TEST_LUA
  LANBOAT_TEST_LUA=$(python3 tests/prepare-lua-reference.py)
fi
if [[ ! -x ${LANBOAT_TEST_LUA:-} ]]; then
  echo 'LANBOAT_TEST_LUA must be an executable official Lua5.3 reference.' >&2
  exit 1
fi
if [[ -z ${LANBOAT_TEST_TROJAN_GO:-} ]]; then
  export LANBOAT_TEST_TROJAN_GO
  LANBOAT_TEST_TROJAN_GO=$(python3 tests/prepare-trojan-go-reference.py)
fi
if [[ ! -x ${LANBOAT_TEST_TROJAN_GO:-} ]]; then
  echo 'LANBOAT_TEST_TROJAN_GO must be an executable official Trojan-Go reference.' >&2
  exit 1
fi
if [[ -z ${LANBOAT_TEST_NAIVE:-} ]]; then
  export LANBOAT_TEST_NAIVE
  LANBOAT_TEST_NAIVE=$(python3 tests/prepare-naive-reference.py)
fi
if [[ ! -x ${LANBOAT_TEST_NAIVE:-} ]]; then
  echo 'LANBOAT_TEST_NAIVE must be an executable official NaiveProxy reference.' >&2
  exit 1
fi
if "$LANBOAT_TEST_REFERENCE" version | grep -q 'independent runtime'; then
  echo 'The independent build cannot be its own interoperability reference.' >&2
  exit 1
fi
if [[ -z ${LANBOAT_TEST_HYSTERIA1:-} ]]; then
  export LANBOAT_TEST_HYSTERIA1
  LANBOAT_TEST_HYSTERIA1=$(python3 tests/prepare-hysteria1-reference.py)
fi
if [[ ! -x ${LANBOAT_TEST_HYSTERIA1:-} ]]; then
  echo 'LANBOAT_TEST_HYSTERIA1 must be an official Hysteria1 executable.' >&2
  exit 1
fi
mkdir -p .cache
if [[ -z ${LANBOAT_TEST_PEBBLE:-} ]]; then
 export LANBOAT_TEST_PEBBLE
 LANBOAT_TEST_PEBBLE=$(bash tests/prepare-acme-reference.sh)
fi
if [[ ! -x ${LANBOAT_TEST_PEBBLE:-} ]]; then
 echo 'LANBOAT_TEST_PEBBLE must be the separate official ACME reference.' >&2
 exit 1
fi
if [[ -z ${LANBOAT_TEST_TAILSCALE:-} ]]; then
  go build -C tests/tailscale-reference -trimpath -o ../../.cache/tailscale-reference .
  export LANBOAT_TEST_TAILSCALE="$PWD/.cache/tailscale-reference"
fi
if [[ ! -x ${LANBOAT_TEST_TAILSCALE:-} ]]; then
  echo 'LANBOAT_TEST_TAILSCALE must be the separately built official Tailscale test reference.' >&2
  exit 1
fi
if [[ -z ${LANBOAT_TEST_KCPTUN:-} ]]; then
 mkdir -p .cache/kcptun-reference
 go build -C tests/kcptun-reference -trimpath -o ../../.cache/kcptun-reference/reference .
 export LANBOAT_TEST_KCPTUN="$PWD/.cache/kcptun-reference/reference"
fi
if [[ ! -x ${LANBOAT_TEST_KCPTUN:-} ]]; then
 echo 'LANBOAT_TEST_KCPTUN must use the unmodified kcp-go/smux/Snappy libraries in tests/kcptun-reference.' >&2
 exit 1
fi
if [[ -z ${LANBOAT_TEST_CLOAK:-} ]]; then
 export LANBOAT_TEST_CLOAK
 LANBOAT_TEST_CLOAK=$(python3 tests/prepare-cloak-reference.py)
fi
if [[ ! -x ${LANBOAT_TEST_CLOAK:-}/ck-client-linux-amd64-v2.12.0 || ! -x ${LANBOAT_TEST_CLOAK:-}/ck-server-linux-amd64-v2.12.0 ]]; then
 echo 'LANBOAT_TEST_CLOAK must contain the pinned official2.12.0 client and server.' >&2
 exit 1
fi
if [[ -z ${LANBOAT_TEST_DTLS13:-} ]]; then
 export LANBOAT_TEST_DTLS13
 LANBOAT_TEST_DTLS13=$(python3 tests/prepare-dtls13-reference.py)
fi
if [[ ! -x ${LANBOAT_TEST_DTLS13:-} ]]; then
 echo 'LANBOAT_TEST_DTLS13 must be the pinned external wolfSSL5.8.2 process.' >&2
 exit 1
fi
if [[ $(uname -s) == Linux ]]; then
 if [[ -z ${LANBOAT_TEST_BRUTAL_MODULE:-} ]]; then
  export LANBOAT_TEST_BRUTAL_MODULE
  LANBOAT_TEST_BRUTAL_MODULE=$(python3 tests/prepare-tcp-brutal-reference.py)
 fi
 [[ -r "$LANBOAT_TEST_BRUTAL_MODULE" ]] || { echo 'LANBOAT_TEST_BRUTAL_MODULE must be a readable module matching the test kernel' >&2; exit 1; }
 export LANBOAT_TEST_BRUTAL_VM=1
 export LANBOAT_TEST_KERNEL_TLS_VM=1
 export LANBOAT_TEST_ICMP_TRACE_VM=1
fi
test_failed=0
if ! go test -race -count=1 -timeout=1800s -json ./internal/nativecmd . > .cache/independent-tests.jsonl; then
 test_failed=1
fi
if [[ $test_failed == 0 ]]; then
 for group in '[a-f]' '[g-m]' '[n-s]' '([^a-s]|$)'; do
  if ! go test -race -count=1 -timeout=1800s -run "(?i)^(Test|Fuzz|Example)$group" -json ./native >> .cache/independent-tests.jsonl; then
   test_failed=1
   break
  fi
 done
fi
if [[ $test_failed != 0 ]]; then
  python3 - <<'PY'
import json
from pathlib import Path
for line in Path('.cache/independent-tests.jsonl').read_text().splitlines():
    event = json.loads(line)
    if event.get('Output'):
        print(event['Output'], end='')
PY
  exit 1
fi
go vet ./native ./internal/nativecmd . ./cmd/lanboat-allinone
python3 - <<'PY'
import json
from pathlib import Path
events = [json.loads(line) for line in Path('.cache/independent-tests.jsonl').read_text().splitlines()]
skipped = [event['Test'] for event in events if event.get('Action') == 'skip']
if skipped:
    raise SystemExit('Unexpected skipped tests: ' + ', '.join(skipped))
passed = [event['Test'] for event in events if event.get('Action') == 'pass' and 'Test' in event]
print(f'Independent runtime: {len(passed)} test cases passed; no skipped tests.')
PY

# Check the current release binary against the public1.15 DNS wire behavior.
bash scripts/build.sh
python3 tests/check-modern-wire.py > .cache/modern-wire-output.log
python3 tests/check-dns-parallel.py > .cache/dns-parallel-wire-output.log
python3 tests/check-ech-dns.py > .cache/ech-dns-wire-output.log
python3 tests/check-dns-network.py > .cache/dns-network-wire-output.log
