#!/usr/bin/env python3
"""Pin the external Sudoku oracle; never add its packages to the product module."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / '.cache/sudoku-reference'
MODULE = 'github.com/SUDOKU-ASCII/sudoku'
VERSION = 'v0.5.2-1'
SUM = 'h1:9kZQCcx53vpuNVbyZCbY0tyUPWmJmwMFWE8QkKitBgI='
CACHE.mkdir(parents=True, exist_ok=True)
env = dict(os.environ, GOBIN=str(CACHE / 'bin'))
subprocess.run(['go', 'install', MODULE + '/cmd/sudoku-tunnel@' + VERSION], cwd=CACHE, env=env, check=True)
binary = CACHE / 'bin/sudoku-tunnel'
info = subprocess.check_output(['go', 'version', '-m', str(binary)], text=True)
if '\tmod\t' + MODULE + '\t' + VERSION + '\t' + SUM not in info.splitlines():
    raise SystemExit('Sudoku reference version/checksum mismatch')
(CACHE / 'provenance.json').write_text(json.dumps(dict(
    module=MODULE, version=VERSION, module_sum=SUM,
    commit='b1d1f0e767653d2c70e2ff814a01264c7dedf1f4',
    binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
    scope='Unmodified official test executable, excluded from product dependencies and artifacts.',
), indent=2) + '\n')
print(binary)
