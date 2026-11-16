#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
reference_dir="$ROOT/.cache/amnezia-reference"
mkdir -p "$reference_dir/download"
cat > "$reference_dir/download/go.mod" <<'EOF'
module lanboat-amnezia-test-download

go 1.27.3
EOF
GOWORK=off go -C "$reference_dir/download" mod download -json github.com/amnezia-vpn/amneziawg-go/v3@v3.1.20260828 > "$reference_dir/module.json"
source_dir=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["Dir"])' "$reference_dir/module.json")
CGO_ENABLED=0 GOWORK=off go build -C "$source_dir" -mod=readonly -trimpath -o "$reference_dir/amneziawg-go" .
python3 - "$reference_dir" <<'PY'
import hashlib,json,pathlib,subprocess,sys
root=pathlib.Path(sys.argv[1]);module=json.loads((root/'module.json').read_text())
report=dict(module=module['Path'],version=module['Version'],module_sum=module['Sum'],go_mod_sum=module['GoModSum'],binary_sha256=hashlib.sha256((root/'amneziawg-go').read_bytes()).hexdigest(),go_version=subprocess.check_output(['go','version'],text=True).strip(),source='https://github.com/amnezia-vpn/amneziawg-go',scope='Official standalone reference only, built in module cache and not linked to Lanboat. Tests configure1.x/2.0 and3.x header protection,padding,trailers and randomized timers.')
(root/'provenance.json').write_text(json.dumps(report,indent=2)+'\n')
PY
printf '%s\n' "$reference_dir/amneziawg-go"
