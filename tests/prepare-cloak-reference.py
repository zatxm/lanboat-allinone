#!/usr/bin/env python3
"""Fetch pinned official Cloak processes for interoperability; not product code."""
import hashlib
import json
from pathlib import Path
import urllib.request

root = Path(__file__).resolve().parents[1] / '.cache/cloak-reference'
root.mkdir(parents=True, exist_ok=True)
artifacts = []
for role, digest in [('client', 'ceabde7e13cf0e9dd7f53f811d6f24c1246755911b06aa40fb541041016348e3'), ('server', 'f2bea92c99195ac26cd5749e80d07339d5582c103f73934b414150c6070dae4e')]:
    name = f'ck-{role}-linux-amd64-v2.12.0'
    url = f'https://github.com/cbeuw/Cloak/releases/download/v2.12.0/{name}'
    binary = root / name
    if not binary.exists() or hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != digest:
            raise SystemExit('Official Cloak reference checksum mismatch')
        binary.write_bytes(data)
    binary.chmod(0o755)
    artifacts.append(dict(role=role, file=name, url=url, sha256=digest))
(root / 'provenance.json').write_text(json.dumps(dict(project='cbeuw/Cloak', version='v2.12.0', commit='c3d5470', assets=artifacts, scope='Unmodified official Linux amd64 executables, SHA256 pinned to release asset digests; external test processes only, not product dependencies or packaged components'), indent=2) + '\n')
print(root)
