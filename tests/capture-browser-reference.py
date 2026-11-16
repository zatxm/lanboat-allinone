#!/usr/bin/env python3
"""Capture reference traffic; no reference TLS library enters the root module."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]


def curl_capture(profile):
    from curl_cffi import CurlOpt, requests

    listener = socket.socket()
    listener.settimeout(5)
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    port = listener.getsockname()[1]
    records = []
    errors = []

    def capture():
        try:
            with listener.accept()[0] as conn:
                conn.settimeout(3)
                wire = bytearray()
                size = 5
                while len(wire) < size:
                    part = conn.recv(size - len(wire))
                    if not part:
                        raise RuntimeError('truncated reference record')
                    wire.extend(part)
                    if len(wire) == 5:
                        size = 5 + int.from_bytes(wire[3:5], 'big')
                records.append(bytes(wire))
        except Exception as error:
            errors.append(str(error))
        finally:
            listener.close()

    thread = threading.Thread(target=capture, daemon=True)
    thread.start()
    with requests.Session(trust_env=False, curl_options={
        CurlOpt.RESOLVE: [f'fingerprint.example:{port}:127.0.0.1']
    }) as client:
        try:
            client.get(f'https://fingerprint.example:{port}', impersonate=profile, timeout=3)
        except requests.exceptions.RequestException:
            pass  # The capture listener deliberately stops after ClientHello.
    thread.join(6)
    if thread.is_alive() or errors or len(records) != 1:
        raise RuntimeError(f'reference capture failed: {errors}')
    return {'profile': profile, 'record': base64.b64encode(records[0]).decode()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--curl-capture')
    parser.add_argument('--curl-python', type=Path)
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--output', type=Path, default=ROOT / '.cache/browser-brook/captures')
    args = parser.parse_args()
    if args.curl_capture:
        print(json.dumps(curl_capture(args.curl_capture)))
        return
    if not args.curl_python or not args.reference:
        parser.error('--curl-python and --reference are required')
    args.output.mkdir(parents=True, exist_ok=True)
    for profile in ('safari15_3', 'safari15_5', 'safari16_0', 'safari26_3'):
        command = [str(args.reference.resolve()), profile]
        if profile.startswith('safari15_'):
            command = [str(args.curl_python.absolute()), str(Path(__file__).resolve()), '--curl-capture', profile]
        captured = json.loads(subprocess.check_output(command, cwd=ROOT, timeout=15))
        (args.output / (profile + '.json')).write_text(json.dumps(captured, indent=2) + '\n')
    metadata = {
        'utls_revision': 'a13c59ffe98bb01b2ca14143eb2e887664b1f138',
        'utls_version': 'v1.8.3-0.20261108164504-a13c59ffe98b',
        'reference_binary_sha256': hashlib.sha256(args.reference.read_bytes()).hexdigest(),
        'curl_cffi_version': subprocess.check_output([str(args.curl_python), '-c', 'import curl_cffi; print(curl_cffi.__version__)'], text=True).strip(),
        'scope': 'Independent reference ClientHello traffic, not a claim of native browser or HTTP fingerprint equivalence.',
    }
    (args.output / 'provenance.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(args.output)


if __name__ == '__main__':
    main()
