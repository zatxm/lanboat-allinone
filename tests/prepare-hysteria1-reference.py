#!/usr/bin/env python3
"""Pinned official HY1 executable, used only by external interoperability tests."""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1] / '.cache/hysteria1-reference'
ROOT.mkdir(parents=True, exist_ok=True)
URL = 'https://github.com/HyNetworks/hysteria/releases/download/v1.3.5/hysteria-linux-amd64'
DIGEST = '41dc8bc3fff6fc1f031666eb294f10b481b80b66229d7c6aca88398d0fba839d'
binary = ROOT / 'hysteria'
if not binary.exists() or hashlib.sha256(binary.read_bytes()).hexdigest() != DIGEST:
    data = urllib.request.urlopen(URL, timeout=60).read()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise SystemExit('Hysteria1 reference checksum mismatch')
    binary.write_bytes(data)
binary.chmod(0o755)
(ROOT / 'provenance.json').write_text(json.dumps(dict(
    project='HyNetworks/hysteria', version='v1.3.5', commit='57c5164854d6cfe00bead730cce731da2babe406',
    url=URL, binary_sha256=DIGEST,
    scope='Unmodified official Linux amd64 release; external test process only, not linked into or shipped with the independent core.'
), indent=2) + '\n')
print(binary)
