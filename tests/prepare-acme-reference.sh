#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
reference_dir="$PWD/.cache/acme-reference"
mkdir -p "$reference_dir"
if [[ ! -x "$reference_dir/pebble" ]]; then
 GOBIN="$reference_dir" go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.8.0
fi
"$reference_dir/pebble" -version 2>&1 | head -n 1 >&2
printf '%s\n' "$reference_dir/pebble"
