#!/usr/bin/env python3
"""Prepare the pinned official NaiveProxy test process, never a runtime dependency."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1] / '.cache/naive-reference'
ROOT.mkdir(parents=True, exist_ok=True)
VERSION = 'v154.0.8037.49-5'
URL = f'https://github.com/klzgrad/naiveproxy/releases/download/{VERSION}/naiveproxy-{VERSION}-linux-x64.tar.xz'
ARCHIVE = '80214dfea1767f6ecf63a3a79dc9f48b203460f51abc609357fff48dd5844c7d'
BINARY = 'f86c52be454eebc9134aad476f3fe91fcf90df7200c3df262a4d0a3d2de85464'
archive = ROOT / 'release.tar.xz'
if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE:
    data = urllib.request.urlopen(URL, timeout=60).read()
    if hashlib.sha256(data).hexdigest() != ARCHIVE:
        raise SystemExit('NaiveProxy reference archive checksum mismatch')
    archive.write_bytes(data)
with tarfile.open(fileobj=io.BytesIO(archive.read_bytes()), mode='r:xz') as package:
    member = next(m for m in package.getmembers() if m.isfile() and m.name.endswith('/naive'))
    data = package.extractfile(member).read()
if hashlib.sha256(data).hexdigest() != BINARY:
    raise SystemExit('NaiveProxy reference binary checksum mismatch')
binary = ROOT / 'naive'
binary.write_bytes(data)
binary.chmod(0o755)
(ROOT / 'provenance.json').write_text(json.dumps(dict(
    project='klzgrad/naiveproxy', version=VERSION, url=URL,
    archive_sha256=ARCHIVE, binary_sha256=BINARY,
    scope='Official unmodified Linux x64 client, external test-only process; no Chromium or protocol code linked into Lanboat.'
), indent=2) + '\n')
print(binary)
