#!/usr/bin/env python3
"""Prepare external ShadowTLS peers, with a test-only private CA input for the client."""
import hashlib
import io
import json
import os
import platform
import subprocess
import sys
import tarfile
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / '.cache/shadowtls-reference'
URL = 'https://github.com/ihciah/shadow-tls/releases/download/v0.2.25/shadow-tls-x86_64-unknown-linux-musl'
SHA256 = 'a173f5f2d57f45211b68e10ceeddc15b1791077b914fa89747bc705fddc71532'
SOURCE_URL = 'https://codeload.github.com/ihciah/shadow-tls/tar.gz/refs/tags/v0.2.25'
SOURCE_SHA256 = '1d1d436734823ba0302de6e91883ed892ea710769c722a139990194ff5837224'
ANCHOR = '        let mut root_store = RootCertStore::empty();'
PATCH = '''
        if let Some(path) = std::env::var_os("LANBOAT_TEST_SHADOWTLS_CA_DER") {
            let der = std::fs::read(path).expect("read test CA");
            root_store.add(&rustls_fork_shadow_tls::Certificate(der)).expect("add test CA");
        }'''
sha = lambda data: hashlib.sha256(data).hexdigest()


def fetch(path, url, expected, limit):
    if path.exists() and sha(path.read_bytes()) == expected:
        return path.read_bytes()
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(limit + 1)
    if len(data) > limit or sha(data) != expected:
        raise SystemExit('ShadowTLS reference SHA256 mismatch: ' + path.name)
    temporary = path.with_suffix('.tmp')
    temporary.write_bytes(data)
    temporary.replace(path)
    return data


def main():
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'amd64'):
        raise SystemExit('The pinned ShadowTLS fixture requires Linux amd64.')
    CACHE.mkdir(parents=True, exist_ok=True)
    binary = CACHE / 'shadow-tls'
    fetch(binary, URL, SHA256, 16 << 20)
    binary.chmod(0o755)
    archive = fetch(CACHE / 'source.tar.gz', SOURCE_URL, SOURCE_SHA256, 8 << 20)
    source = CACHE / 'shadow-tls-0.2.25'
    # Verify every source file against the pinned archive, allowing exactly the CA patch.
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        for entry in tar.getmembers():
            path = Path(entry.name)
            if path.is_absolute() or '..' in path.parts or path.parts[0] != source.name or entry.issym() or entry.islnk():
                raise SystemExit('Unsafe ShadowTLS source archive path')
            if not entry.isfile():
                continue
            data = tar.extractfile(entry).read()
            if path.as_posix() == source.name + '/src/client.rs':
                original_client_sha = sha(data)
                text = data.decode()
                if text.count(ANCHOR) != 1:
                    raise SystemExit('ShadowTLS client trust-store anchor changed')
                data = text.replace(ANCHOR, ANCHOR + PATCH).encode()
                patched_client_sha = sha(data)
            target = CACHE / path
            if not target.exists() or target.read_bytes() != data:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
    env = dict(os.environ, RUSTUP_TOOLCHAIN='stable', CARGO_BUILD_JOBS='2', RUSTC_BOOTSTRAP='1')
    rustc = subprocess.check_output(['rustc', '--version'], env=env, text=True).strip()
    manifest = dict(source_sha256=SOURCE_SHA256, original_client_sha256=original_client_sha,
                    patched_client_sha256=patched_client_sha, rustc=rustc,
                    cargo_lock_sha256=sha((source / 'Cargo.lock').read_bytes()))
    adapted = CACHE / 'shadow-tls-test-ca'
    metadata = CACHE / 'client-build.json'
    old = json.loads(metadata.read_text()) if metadata.exists() else {}
    if not adapted.exists() or old != dict(manifest, binary_sha256=sha(adapted.read_bytes())):
        print('Building the external ShadowTLS client with only a private test CA input.', file=sys.stderr)
        subprocess.run(['cargo', 'build', '--release', '--locked', '--manifest-path', str(source / 'Cargo.toml')],
                       cwd=ROOT, env=env, stdout=sys.stderr, check=True)
        temporary = CACHE / 'client.tmp'
        temporary.write_bytes((source / 'target/release/shadow-tls').read_bytes())
        temporary.chmod(0o755)
        temporary.replace(adapted)
        metadata.write_text(json.dumps(dict(manifest, binary_sha256=sha(adapted.read_bytes())), indent=2) + '\n')
    provenance = dict(project='ihciah/shadow-tls', version='v0.2.25', url=URL, binary_sha256=SHA256,
                      source_url=SOURCE_URL, client=json.loads(metadata.read_text()),
                      scope='Unmodified external server executable; source-built client adds only a test CA input. Neither linked nor shipped in product.')
    (CACHE / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    print(binary)


if __name__ == '__main__':
    main()
