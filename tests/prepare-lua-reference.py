#!/usr/bin/env python3
"""Build the official language reference in the test cache, never in the core."""
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request

root = Path(__file__).resolve().parents[1] / '.cache/lua-reference'
root.mkdir(parents=True, exist_ok=True)
url = 'https://www.lua.org/ftp/lua-5.3.6.tar.gz'
checksum = 'fc5fd69bb8736323f026672b1b7235da613d7177e72558893a0bdcd320466d60'
archive = root / 'lua-5.3.6.tar.gz'
if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != checksum:
    content = urllib.request.urlopen(url, timeout=60).read()
    if hashlib.sha256(content).hexdigest() != checksum:
        raise SystemExit('Lua reference archive checksum mismatch')
    archive.write_bytes(content)
source = root / 'lua-5.3.6'
binary = source / 'src/lua'
if not binary.exists():
    with tarfile.open(archive, 'r:gz') as package:
        package.extractall(root, filter='data')
    # Avoid a readline dependency; the reference is used non-interactively.
    subprocess.run(['make', '-s', '-C', str(source), 'generic'], check=True, stdout=subprocess.DEVNULL)
report = dict(version='5.3.6', url=url, archive_sha256=checksum,
              binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
              scope='External test-only language reference; no Lua library or source linked into the core.')
(root / 'provenance.json').write_text(json.dumps(report, indent=2) + '\n')
print(binary)
