#!/usr/bin/env python3
"""Prepare the official Trojan-Go reference process; never linked to the core."""
import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1] / '.cache/trojan-go-reference'
ROOT.mkdir(parents=True, exist_ok=True)
URL = 'https://github.com/p4gefau1t/trojan-go/releases/download/v0.10.6/trojan-go-linux-amd64.zip'
ARCHIVE = '764480722783a6d76ed8401f6d2f1d87d8df7e60bf261f69c67eb94b77e732af'
BINARY = 'cb7db31244ec4213c81cb4ef1080c92b44477a0b1dc101246304846e9d74b640'
archive = ROOT / 'release.zip'
if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE:
    data = urllib.request.urlopen(URL, timeout=60).read()
    if hashlib.sha256(data).hexdigest() != ARCHIVE:
        raise SystemExit('Trojan-Go reference archive checksum mismatch')
    archive.write_bytes(data)
with zipfile.ZipFile(io.BytesIO(archive.read_bytes())) as package:
    data = package.read('trojan-go')
if hashlib.sha256(data).hexdigest() != BINARY:
    raise SystemExit('Trojan-Go reference binary checksum mismatch')
binary = ROOT / 'trojan-go'
binary.write_bytes(data)
binary.chmod(0o755)
report = dict(project='p4gefau1t/trojan-go', version='v0.10.6', commit='2dc60f52e79ff8b910e78e444f1e80678e936450',
              url=URL, archive_sha256=ARCHIVE, binary_sha256=BINARY,
              scope='Official unmodified Linux amd64 release, external test-only process. No protocol code or dependency linked into Lanboat; UDP reference interoperability limited to4096 bytes, native endpoints separately validate60000 bytes.')
(ROOT / 'provenance.json').write_text(json.dumps(report, indent=2) + '\n')
print(binary)
