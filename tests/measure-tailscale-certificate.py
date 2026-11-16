#!/usr/bin/env python3
"""Measure cached Tailscale TLS with two real cores and an official test control."""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = Path(os.environ.get('LANBOAT_TEST_TAILSCALE', ROOT / '.cache/tailscale-reference'))
spec = importlib.util.spec_from_file_location('measure', ROOT / 'scripts/measure-independent.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
origin = m.OriginServer(('127.0.0.1', 0), m.Origin)
threading.Thread(target=origin.serve_forever, daemon=True).start()
write_text, popen = Path.write_text, subprocess.Popen
rows = []

try:
    with tempfile.TemporaryDirectory(prefix='lanboat-tailscale-cert-resource-') as temp:
        work = Path(temp)
        with (work / 'control.log').open('w') as log:
            env = dict(os.environ, LANBOAT_TS_CERTIFICATE='1', LANBOAT_TS_CERTIFICATE_DOMAINS='[]',
                       LANBOAT_TS_CERTIFICATE_CALLBACK='http://127.0.0.1:1', TS_DISABLE_LOGTAIL='true')
            reference = popen([str(REFERENCE)], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=log, text=True)
            try:
                fixture = json.loads(reference.stdout.readline())
                name = 'native.test.ts.net'
                key, ca_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
                now = datetime.datetime.now(datetime.timezone.utc)
                ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Resource CA')])
                ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
                      .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
                      .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=365))
                      .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(ca_key, hashes.SHA256()))
                cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                        .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
                        .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=90))
                        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
                        .sign(ca_key, hashes.SHA256()))
                ca_path = work / 'ca.pem'
                ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

                for kind in ['trojan', 'hysteria2', 'vless-h2']:
                    state = work / kind / 'state'
                    directory = state / 'certificates'
                    directory.mkdir(parents=True, mode=0o700)
                    provider = 'https://acme-v02.api.letsencrypt.org/directory'
                    identity = json.dumps([[name], provider, 'p256', ''], separators=(',', ':')).encode()
                    cache = directory / ('acme-certificate-' + hashlib.sha256(identity).hexdigest() + '.json')
                    cache.write_text(json.dumps(dict(version=1, domains=[name], provider=provider, key_type='p256', profile='',
                                                     certificate=cert.public_bytes(serialization.Encoding.PEM).decode(),
                                                     private_key=key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                                                   serialization.NoEncryption()).decode())))
                    cache.chmod(0o600)
                    cores, peaks = [], [0, 0]
                    stop = threading.Event()

                    def write_config(path, text, *args, **kwargs):
                        if str(path).endswith('-server.json'):
                            doc = json.loads(text)
                            tls = doc['inbounds'][0]['tls']
                            for field in ['certificate_path', 'key_path', 'certificate', 'key']:
                                tls.pop(field, None)
                            tls['certificate_provider'] = 'tailnet-cert'
                            doc['certificate_providers'] = [dict(type='tailscale', tag='tailnet-cert', endpoint='ts')]
                            doc['endpoints'] = [dict(type='tailscale', tag='ts', auth_key='test-only-auth', hostname='native',
                                                     control_url=fixture['control_url'], state_directory=str(state),
                                                     taildrop_directory=str(work / 'drop'), on_demand=True, force_derp=True)]
                            doc.setdefault('outbounds', []).append(dict(type='block', tag='no-issuance'))
                            doc['http_clients'] = [dict(tag='no-issuance', detour='no-issuance')]
                            doc.setdefault('route', {})['default_http_client'] = 'no-issuance'
                            text = json.dumps(doc)
                        elif str(path).endswith('-client.json'):
                            doc = json.loads(text)
                            tls = doc['outbounds'][0]['tls']
                            tls.update(server_name=name, certificate_path=str(ca_path))
                            tls.pop('insecure', None)
                            text = json.dumps(doc)
                        return write_text(path, text, *args, **kwargs)

                    def start_process(args, *pargs, **kwargs):
                        process = popen(args, *pargs, **kwargs)
                        if str(args[0]) == str(m.BINARY):
                            cores.append(process)
                        return process

                    def monitor():
                        while not stop.wait(0.005):
                            try:
                                ref_rss = m.rss(reference.pid)
                                core_rss = sum(m.rss(p.pid) for p in tuple(cores) if p.poll() is None)
                                peaks[0], peaks[1] = max(peaks[0], ref_rss), max(peaks[1], ref_rss + core_rss)
                            except (FileNotFoundError, ProcessLookupError, RuntimeError):
                                pass

                    Path.write_text, subprocess.Popen = write_config, start_process
                    monitor_thread = threading.Thread(target=monitor)
                    monitor_thread.start()
                    try:
                        row = m.scenario(kind, origin, work)
                    finally:
                        stop.set()
                        monitor_thread.join()
                        Path.write_text, subprocess.Popen = write_text, popen
                    row.update(protocol='tailscale-certificate/' + kind,
                               certificate_source='local persisted P-256 fixture;CA HTTP exit rejects network',
                               external_reference_processes=1, external_reference_peak_rss_mib=round(peaks[0] / 2**20, 2),
                               all_process_peak_rss_mib=round(peaks[1] / 2**20, 2))
                    assert reference.poll() is None and peaks[0] > 0 and peaks[1] > 0
                    rows.append(row)
            finally:
                reference.terminate()
                try:
                    reference.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    reference.kill()
                    reference.wait()
                reference.stdin.close()
                reference.stdout.close()
    report = dict(binary_sha256=hashlib.sha256(m.BINARY.read_bytes()).hexdigest(),
                  reference_sha256=hashlib.sha256(REFERENCE.read_bytes()).hexdigest(),
                  fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), platform='linux-amd64',
                  scope='Two real core processes plus official Tailscale control fixture;128 requests,concurrency8;'
                        'cached certificate;not online issuance,public tailnet,GUI,WAN or TUN measurement;CPU counts cores only',
                  scenarios=rows)
    (ROOT / '.cache/tailscale-certificate-resources.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
finally:
    Path.write_text, subprocess.Popen = write_text, popen
    origin.shutdown()
    origin.server_close()
