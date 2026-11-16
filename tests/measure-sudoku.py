#!/usr/bin/env python3
"""Reuse the two-process traffic/RSS sampler for Sudoku's supported modes."""
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('measure', ROOT / 'scripts/measure-independent.py')
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)
binary_hash = hashlib.sha256(measure.BINARY.read_bytes()).hexdigest()
origin = measure.OriginServer(('127.0.0.1', 0), measure.Origin)
threading.Thread(target=origin.serve_forever, daemon=True).start()
try:
    with tempfile.TemporaryDirectory(prefix='lanboat-sudoku-resource-') as directory:
        work = Path(directory)
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes',
                        '-keyout',str(work/'key.pem'),'-out',str(work/'cert.pem'),'-subj','/CN=localhost',
                        '-addext','subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1','-days','1'],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
        scenarios = [measure.scenario('sudoku-' + kind, origin, Path(directory))
                     for kind in ('plain', 'aes', 'chacha', 'packed', 'ascii', 'custom', 'mux', 'mux-packed',
                                  'mask-legacy', 'mask-legacy-mux', 'mask-ws', 'mask-ws-mux', 'mask-legacy-tls', 'mask-ws-tls',
                                  'mask-stream', 'mask-stream-mux', 'mask-stream-tls',
                                  'mask-poll', 'mask-poll-mux', 'mask-poll-tls',
                                  'mask-auto', 'mask-auto-mux', 'mask-auto-tls',
                                  'tables', 'tables-mux', 'tables-ws', 'tables-poll', 'tables-auto-mux',
                                  'private-raw-master', 'private-raw', 'private-raw-mux',
                                  'private-legacy', 'private-ws', 'private-stream', 'private-poll', 'private-auto', 'private-auto-tls',
                                  'reverse-raw', 'reverse-legacy', 'reverse-ws', 'reverse-stream', 'reverse-poll', 'reverse-auto-tls',
                                  'reverse-raw-http', 'reverse-legacy-http', 'reverse-ws-http', 'reverse-stream-http', 'reverse-poll-http', 'reverse-auto-http-tls')]
    assert hashlib.sha256(measure.BINARY.read_bytes()).hexdigest() == binary_hash
    assert all(v['requests'] == 128 and v['auxiliary_processes'] == 0 and 0 < v['total_peak_rss_mib'] < 200 for v in scenarios)
    report = dict(binary_sha256=binary_hash, probe_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  scope='Two native core processes;128 real HTTP transfers per mode,8 concurrent;sum of process RSS;no GUI or external protocol engine.',
                  scenarios=scenarios)
    target = ROOT / '.cache/sudoku-validation/resources.json'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
finally:
    origin.shutdown()
    origin.server_close()
