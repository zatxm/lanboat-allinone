#!/usr/bin/env python3
"""Build an unmodified, pinned rs-wgobfs test process outside the Go module."""
import concurrent.futures
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tomllib
import urllib.request

COMMIT = 'c5e62796d3a8a063c71e4eb5ada6768eae45e7ae'
ARCHIVE_SHA256 = 'fee6ceed719e3bac828f101d30ebbd24f6afbe3be3ccf83def1fcdc6eee0b0bc'
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / '.cache/wgobfs-reference'
WORK.mkdir(parents=True, exist_ok=True)
url = 'https://codeload.github.com/infinet/rs-wgobfs/tar.gz/' + COMMIT
archive = WORK / 'source.tar.gz'
if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA256:
    data = urllib.request.urlopen(url, timeout=60).read()
    if hashlib.sha256(data).hexdigest() != ARCHIVE_SHA256:
        raise SystemExit('rs-wgobfs reference archive checksum mismatch')
    archive.write_bytes(data)
with tarfile.open(archive) as package:
    package.extractall(WORK / 'unpack', filter='data')
source = WORK / 'source'
shutil.copytree(WORK / 'unpack' / ('rs-wgobfs-' + COMMIT), source, dirs_exist_ok=True)
vendor = WORK / 'vendor'
vendor.mkdir(exist_ok=True)
lock = tomllib.loads((source / 'Cargo.lock').read_text())


def prepare_crate(crate):
    name, version, checksum = crate['name'], crate['version'], crate['checksum']
    dest = vendor / (name + '-' + version)
    stamp = dest / '.cargo-checksum.json'
    if stamp.exists() and json.loads(stamp.read_text())['package'] == checksum:
        return
    url = f'https://static.crates.io/crates/{name}/{name}-{version}.crate'
    data = urllib.request.urlopen(url, timeout=60).read()
    if hashlib.sha256(data).hexdigest() != checksum:
        raise RuntimeError('reference crate checksum mismatch: ' + name)
    with tarfile.open(fileobj=io.BytesIO(data)) as package:
        package.extractall(vendor, filter='data')
    files = {p.relative_to(dest).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in dest.rglob('*') if p.is_file() and p.name != '.cargo-checksum.json'}
    stamp.write_text(json.dumps(dict(package=checksum, files=files)))


with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
    list(pool.map(prepare_crate, (p for p in lock['package'] if 'source' in p)))
subprocess.run(['cargo', 'build', '--release', '--locked', '--offline', '--manifest-path', str(source / 'Cargo.toml'),
                '--config', 'source.crates-io.replace-with="wgobfs-vendor"',
                '--config', 'source.wgobfs-vendor.directory=' + json.dumps(str(vendor))], check=True, stdout=sys.stderr)
binary = WORK / 'rs-wgobfs'
shutil.copy2(source / 'target/release/rs-wgobfs', binary)
files = [source / 'Cargo.toml', source / 'Cargo.lock', *sorted((source / 'src').glob('*.rs'))]
report = dict(project='infinet/rs-wgobfs', version='0.6.2', commit=COMMIT, url=url, archive_sha256=ARCHIVE_SHA256,
              binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
              source_files_sha256={p.relative_to(source).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
              rust_version=subprocess.check_output(['rustc', '--version'], text=True).strip(),
              scope='Unmodified upstream CLI and locked Rust dependencies; external test process only, not linked or shipped. Reference UDP receive buffer is1500 bytes; packet-wire checks stay below this limit.')
(WORK / 'provenance.json').write_text(json.dumps(report, indent=2) + '\n')
print(binary)
