#!/usr/bin/env python3
"""Unmodified, pinned external plugin processes; never linked into the core."""
import hashlib
import io
import json
import subprocess
import tarfile
import urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]/'.cache/sip003-reference'
ROOT.mkdir(parents=True,exist_ok=True)
ASSETS=[
 ('simple-obfs.deb','https://deb.debian.org/debian/pool/main/s/simple-obfs/simple-obfs_0.0.5-6_amd64.deb','4eb944e0c4899963ccb3eb9e01fa263e39ba00aca857aeed151c0ec003cd884f'),
 ('libev4_4.33-1_amd64.deb','https://deb.debian.org/debian/pool/main/libe/libev/libev4_4.33-1_amd64.deb','1b35aebfabf4f1dba891c9cc0b7352e8402dac4efef1e34a41359ce5bd68aacf'),
 ('libcork16_1.0.0~rc3-4_amd64.deb','https://deb.debian.org/debian/pool/main/libc/libcork/libcork16_1.0.0~rc3-4_amd64.deb','29ba4c208750c858fc21a2dc497bbe4a69dcb541bf5bb4d972353edc2fe88743'),
 ('v2ray-plugin.tar.gz','https://github.com/shadowsocks/v2ray-plugin/releases/download/v1.5.0/v2ray-plugin-linux-amd64-v1.5.0.tar.gz','f326c48a0f91f8ab536a864c6a2dba6b587ea1df537b2c43af0bfb7922ed05c4'),
]
for name,url,digest in ASSETS:
    path=ROOT/name
    if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
        data=urllib.request.urlopen(url,timeout=60).read()
        if hashlib.sha256(data).hexdigest()!=digest: raise SystemExit('Reference checksum mismatch: '+name)
        path.write_bytes(data)
    if name.endswith('.deb'):
        subprocess.run(['dpkg-deb','-x',str(path),str(ROOT/'root')],check=True)
    else:
        with tarfile.open(fileobj=io.BytesIO(path.read_bytes()),mode='r:gz') as archive:
            member=next(m for m in archive.getmembers() if m.isfile() and m.name=='v2ray-plugin_linux_amd64')
            binary=ROOT/member.name
            binary.write_bytes(archive.extractfile(member).read());binary.chmod(0o755)
binaries=[ROOT/'root/usr/bin'/name for name in ('obfs-local','obfs-server')]+[ROOT/'v2ray-plugin_linux_amd64']
(ROOT/'provenance.json').write_text(json.dumps(dict(assets=[dict(name=n,url=u,sha256=s) for n,u,s in ASSETS],binaries={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in binaries},scope='Debian simple-obfs0.0.5-6 and official v2ray-plugin1.5.0, external test-only processes. Dependencies extracted only into this cache directory; no system installation.'),indent=2)+'\n')
print(ROOT)
