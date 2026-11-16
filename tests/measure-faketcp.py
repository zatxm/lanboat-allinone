#!/usr/bin/env python3
"""FakeTCP resource checks in an isolated Linux network/user namespace."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
if os.environ.get('LANBOAT_FAKETCP_MEASURE') != '1':
    command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve())]
    raise SystemExit(subprocess.call(command, env=dict(os.environ, LANBOAT_FAKETCP_MEASURE='1')))

subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
spec = importlib.util.spec_from_file_location('measure', ROOT/'scripts/measure-independent.py')
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)
origin = measure.OriginServer(('127.0.0.1', 0), measure.Origin)
threading.Thread(target=origin.serve_forever, daemon=True).start()
try:
    with tempfile.TemporaryDirectory(prefix='lanboat-faketcp-measure-') as directory:
        work = Path(directory)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', str(work/'key.pem'), '-out', str(work/'cert.pem'), '-subj', '/CN=localhost', '-days', '1'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        scenarios = [measure.scenario(name, origin, work) for name in ('hysteria-faketcp', 'hysteria-faketcp-xplus')]
        assert all(s['auxiliary_processes'] == 0 for s in scenarios)
        report = dict(binary_sha256=hashlib.sha256(measure.BINARY.read_bytes()).hexdigest(), platform='linux-amd64', scope='Two independent-core processes; isolated user/network namespace; 128 loopback requests with8workers; origin excluded; no netfilter changes, WAN, GUI or TUN measurement', scenarios=scenarios)
        output = ROOT/'.cache/faketcp-validation/resources.json'
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report, indent=2))
finally:
    origin.shutdown()
    origin.server_close()
