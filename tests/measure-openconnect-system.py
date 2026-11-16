#!/usr/bin/env python3
"""Measure OpenConnect kernel-interface traffic using the shared endpoint probe."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path(__file__).with_name('measure-masque-system.py')
spec = importlib.util.spec_from_file_location('endpoint_probe', PROBE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def main():
    output = ROOT/'.cache/openconnect-system-validation/resources.json'
    if '--namespace' not in sys.argv:
        output.unlink(missing_ok=True)
        subprocess.run(['unshare', '-Urn', sys.executable, __file__, '--namespace'], check=True, cwd=ROOT)
        return
    probe.command('ip', 'link', 'set', 'lo', 'up')
    with tempfile.TemporaryDirectory(prefix='lanboat-openconnect-system-') as directory:
        work = Path(directory)
        probe.command('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
                      '-keyout', str(work/'key.pem'), '-out', str(work/'cert.pem'), '-subj', '/CN=localhost', '-days', '1')
        report = dict(binary_sha256=hashlib.sha256(probe.BINARY.read_bytes()).hexdigest(),
                      source_sha256={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                     for p in [Path(__file__), PROBE]}, platform='linux-amd64',
                      scope='Two release-core processes, real Linux TUN/kernel TCP and automatic pushed routes; origin/tester excluded; not GUI,WAN,Windows/macOS or long-term idle measurements',
                      scenarios=[probe.measure(work, 'openconnect', dtls) for dtls in [False, True]])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
