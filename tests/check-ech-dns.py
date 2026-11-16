"""Compare HTTPS/SVCB wire records with the official1.15 executable."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('dns_wire', Path(__file__).with_name('check-modern-wire.py'))
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)


def query(port, name, typ):
    with socket.create_connection(('127.0.0.1', port), timeout=2) as control:
        control.sendall(b'\x05\x01\x00')
        assert wire.readn(control, 2) == b'\x05\x00'
        control.sendall(b'\x05\x03\x00\x01' + bytes(6))
        assert wire.readn(control, 3) == b'\x05\x00\x00'
        host, relay = wire.address(control)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(3)
            question = b'\x12\x34\x01\x00\x00\x01' + bytes(6) + b''.join(bytes([len(x)])+x.encode() for x in name.split('.')) + b'\0' + struct.pack('!HH', typ, 1)
            udp.sendto(bytes(3) + b'\x01\xc0\x00\x02\x01\x00\x35' + question, (host if host != '0.0.0.0' else '127.0.0.1', relay))
            packet, _ = udp.recvfrom(65535)
            offset = 10 if packet[3] == 1 else 22 if packet[3] == 4 else 7+packet[4]
            data = packet[offset:]
    assert data[:2] == question[:2] and data[3] & 15 == 0
    assert int.from_bytes(data[6:8], 'big') == 1
    pos = len(question)
    if data[pos] & 0xc0 == 0xc0:
        pos += 2
    else:
        while data[pos]:
            pos += data[pos]+1
        pos += 1
    rrtype, cls, ttl, length = struct.unpack_from('!HHIH', data, pos)
    assert rrtype == typ and cls == 1 and ttl == 60
    return data[pos+10:pos+10+length].hex()


def main():
    native = ROOT/'build/lanboat-allinone'
    official = Path(os.environ.get('LANBOAT_TEST_SINGBOX15', ROOT/'.cache/sing-box-1.15.0-alpha.13/sing-box'))
    generated = subprocess.check_output([str(native), 'generate', 'ech-keypair', 'public.test']).decode()
    config = base64.b64decode(generated.split('-----BEGIN ECH CONFIGS-----', 1)[1].split('-----END ECH CONFIGS-----', 1)[0])
    encoded = base64.b64encode(config).decode()
    records = [
        ('https.test', 65, '1 . alpn="h2,h3" ech='+encoded),
        ('svcb.test', 64, '1 target.test. port=8443 mandatory=ech,alpn alpn=h2 ech='+encoded),
        ('hints.test', 65, '1 . ipv6hint=2001:db8::1 ipv4hint=192.0.2.1,192.0.2.2'),
        ('alias.test', 65, '0 target.test.'),
        ('unknown.test', 64, '1 . key123=opaque'),
        ('doh.test', 65, '1 . dohpath="/dns-query{?dns}" alpn=h2 no-default-alpn'),
        ('escape.test', 65, r'1 . alpn="h2\,test,h3" key123="hello\032world"'),
        ('escape-list.test', 65, r'1 . alpn="h2\\,test,h3"'),
    ]
    results = []
    with tempfile.TemporaryDirectory(prefix='lanboat-ech-wire-') as temp:
        work = Path(temp)
        for engine, binary in [('native', native), ('official', official)]:
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            rules = [dict(domain=name, action='predefined', answer=f'{name}. 60 IN '+('HTTPS' if typ == 65 else 'SVCB')+' '+value) for name, typ, value in records]
            cfg = dict(log=dict(disabled=True), inbounds=[dict(type='mixed', tag='in', listen='127.0.0.1', listen_port=port)], outbounds=[dict(type='direct', tag='direct')], route=dict(rules=[dict(port=53, action='hijack-dns')], final='direct'), dns=dict(rules=rules))
            path = work/(engine+'.json')
            path.write_text(json.dumps(cfg))
            with (work/(engine+'.log')).open('w+') as log:
                process = subprocess.Popen([str(binary), 'run', '-c', str(path)], cwd=work, stdout=log, stderr=log)
                try:
                    for _ in range(100):
                        if process.poll() is not None:
                            log.seek(0)
                            raise RuntimeError(log.read())
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.05):
                                break
                        except OSError:
                            time.sleep(.02)
                    results.append(dict(engine=engine, binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), cases={name:query(port, name, typ) for name, typ, _ in records}))
                finally:
                    process.terminate()
                    process.wait(timeout=5)
    assert results[0]['cases'] == results[1]['cases'], results
    (ROOT/'.cache/ech-dns-wire.json').write_text(json.dumps(results, indent=2)+'\n')
    print(f'{len(records)} HTTPS/SVCB wire comparisons passed')


if __name__ == '__main__':
    main()
