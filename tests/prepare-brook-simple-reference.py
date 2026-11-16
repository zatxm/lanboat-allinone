#!/usr/bin/env python3
"""Build the unmodified upstream revision retaining withoutBrookProtocol."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / '.cache/brook-simple-reference'
VERSION = 'v0.0.0-20260925045830-5ad0c40c3614'
MODULE = 'github.com/txthinking/brook'
SUM = 'h1:ZSPVnOYlRxxFuWW4irKq4xb25yVepbyoq7fGS9On1UM='
CACHE.mkdir(parents=True, exist_ok=True)
(CACHE / 'bin').mkdir(exist_ok=True)
binary = CACHE / 'bin' / ('brook.exe' if os.name == 'nt' else 'brook')
env = dict(os.environ, GOBIN=str(CACHE / 'bin'), GOWORK='off', GO111MODULE='on')
subprocess.run(['go', 'install', MODULE + '/cli/brook@' + VERSION], env=env, cwd=CACHE, check=True)
info = subprocess.check_output(['go', 'version', '-m', str(binary)], text=True)
expected = '\tmod\t' + MODULE + '\t' + VERSION + '\t' + SUM
if expected not in info.splitlines():
    raise SystemExit('Brook reference module version/checksum mismatch')
help_text = subprocess.check_output([str(binary), 'wsserver', '--help'], text=True)
if '--withoutBrookProtocol' not in help_text:
    raise SystemExit('Brook reference does not retain the simple protocol')
(CACHE / 'provenance.json').write_text(json.dumps(dict(
    module=MODULE, version=VERSION, module_sum=SUM,
    revision='5ad0c40c3614',
    source_url='https://github.com/txthinking/brook/tree/5ad0c40c3614',
    binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
    go_version=subprocess.check_output(['go', 'version'], text=True).strip(),
    scope='Unmodified upstream CLI built separately in the test cache. Root module and release artifacts do not import or package Brook.',
), indent=2) + '\n')
print(binary)
