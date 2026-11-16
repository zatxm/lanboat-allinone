#!/usr/bin/env python3
"""Build a pinned, external DTLS1.3 PSK-DHE peer for interoperability tests only."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / '.cache/dtls13-reference'
CACHE.mkdir(parents=True, exist_ok=True)
VERSION = '5.8.2-stable'
URL = f'https://codeload.github.com/wolfSSL/wolfssl/tar.gz/refs/tags/v{VERSION}'
SHA = '3ef126e3466e2f8f6ebb62b916a7f8fb26c6709dbdf2b63a167759f2fdb53068'
archive = CACHE / 'wolfssl-5.8.2.tar.gz'
source = CACHE / f'wolfssl-{VERSION}'
library = source / 'src/.libs/libwolfssl.a'
if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != SHA:
    data = urllib.request.urlopen(URL, timeout=60).read()
    if hashlib.sha256(data).hexdigest() != SHA:
        raise SystemExit('DTLS1.3 reference archive checksum mismatch')
    archive.write_bytes(data)
if not library.exists():
    for tool in ('cc', 'make', 'autoconf', 'automake', 'libtoolize'):
        if not shutil.which(tool):
            raise SystemExit(f'DTLS1.3 external reference build requires {tool}; no system package is installed automatically')
    if not source.exists():
        with tarfile.open(archive) as package:
            package.extractall(CACHE, filter='data')
    with (CACHE / 'build.log').open('w') as log:
        for cmd in (
            ['bash', './autogen.sh'],
            ['./configure', '--enable-dtls', '--enable-dtls13', '--enable-psk',
             '--enable-curve25519', '--enable-chacha', '--enable-poly1305',
             '--disable-shared', '--disable-examples', '--disable-crypttests'],
            ['make', '-j4'],
        ):
            subprocess.run(cmd, cwd=source, stdout=log, stderr=subprocess.STDOUT, check=True)
binary = CACHE / 'reference'
subprocess.run([os.environ.get('CC', 'cc'), '-O2', '-I', str(source),
                str(ROOT / 'tests/dtls13-reference.c'), str(library), '-pthread', '-lm',
                '-o', str(binary)], check=True)
(CACHE / 'provenance.json').write_text(json.dumps(dict(
    project='wolfSSL/wolfssl', version=VERSION, url=URL, archive_sha256=SHA,
    library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
    harness_sha256=hashlib.sha256((ROOT / 'tests/dtls13-reference.c').read_bytes()).hexdigest(),
    binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
    scope='External test-only process; no wolfSSL code or dependency is linked into Lanboat.'
), indent=2) + '\n')
print(binary)
