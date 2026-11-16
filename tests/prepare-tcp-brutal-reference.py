#!/usr/bin/env python3
"""Build a pinned test-only TCP Brutal module; never install it on the host."""
import hashlib
import os
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
COMMIT = 'd2397ff8bca04a29fd2de01cf7d2d4b825224de8'
FILES = {'brutal.h': '0a3915d3d2a6788ebc6eccf2681893fb1807a9cff5458281f0147f20f6cc8fa4', 'brutal_sockopt.c': '1873e91abe3bc8375157d7abedf869f33b7849808564e06b85c8c929b15d331c', 'brutal_cc.c': '781521f4c875f646b3411f8d4d671d4d200584e7bf052a712e358666661fd60b', 'brutal_rules.c': 'a5bd98f44aceda049f9ab88eb5b304c2123cce03fe0c12a3ebe2c7c0eac9a6ec', 'Makefile': '4328f1eabdb26e12108fcb2f751fe8f554b38fe764aa55d09a37b43f71921374'}
release = os.uname().release
work = ROOT/'.cache/tcp-brutal-reference'/release
work.mkdir(parents=True, exist_ok=True)
for name, digest in FILES.items():
    path = work/name
    if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        data = urllib.request.urlopen(f'https://raw.githubusercontent.com/HyNetworks/tcp-brutal/{COMMIT}/{name}', timeout=60).read()
        if hashlib.sha256(data).hexdigest() != digest:
            raise SystemExit('reference hash mismatch: '+name)
        path.write_bytes(data)
module = work/'brutal.ko'
if not module.exists() or any((work/name).stat().st_mtime > module.stat().st_mtime for name in FILES):
    subprocess.run(['make', '-C', f'/lib/modules/{release}/build', f'M={work}', 'modules'], check=True, stdout=subprocess.DEVNULL)
print(module)
