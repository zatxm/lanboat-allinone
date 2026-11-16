#!/usr/bin/env python3
"""Capture loopback QUIC Initials in an isolated temporary browser profile."""
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile

stage = Path(__file__).resolve().parents[1] / '.cache/quic-client'
stage.mkdir(parents=True, exist_ok=True)
chrome = os.environ.get('LANBOAT_TEST_CHROME') or shutil.which('google-chrome') or shutil.which('chromium')
if not chrome:
    raise SystemExit('Set LANBOAT_TEST_CHROME to a Chromium executable for the isolated capture.')
for old in stage.glob('chromium-*.bin'):
    old.unlink()
files = []
with tempfile.TemporaryDirectory(prefix='lanboat-quic-chrome-') as profile:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener, (stage / 'chrome-capture.log').open('w') as log:
        listener.bind(('127.0.0.1', 0))
        listener.settimeout(3)
        port = listener.getsockname()[1]
        process = subprocess.Popen([
            chrome, '--headless=new', '--no-sandbox', '--disable-gpu', '--no-proxy-server',
            '--disable-background-networking', '--disable-component-update', '--no-first-run', '--enable-quic',
            '--origin-to-force-quic-on=quic.test:' + str(port), '--host-resolver-rules=MAP quic.test 127.0.0.1',
            '--user-data-dir=' + profile, '--dump-dom', 'https://quic.test:' + str(port),
        ], stdout=subprocess.DEVNULL, stderr=log, start_new_session=True)
        try:
            for n in range(6):
                try:
                    data = listener.recv(65535)
                except socket.timeout:
                    break
                file = stage / ('chromium-' + str(n) + '.bin')
                file.write_bytes(data)
                files.append({'path': str(file), 'size': len(data)})
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
version = subprocess.check_output([chrome, '--version'], text=True).strip()
(stage / 'capture.json').write_text(json.dumps({'browser': version, 'captures': files}, indent=2) + '\n')
if len(files) < 2:
    raise SystemExit('Chrome produced no fragmented QUIC ClientHello; see chrome-capture.log')
print(stage)
