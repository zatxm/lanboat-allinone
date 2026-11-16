"""Compare DNS network conditions with official1.15 in a private mount namespace."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('dns_wire', Path(__file__).with_name('check-modern-wire.py'))
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)


def cases():
    for name, condition, hit in [
        ('ipv4', dict(dns_server_address={'local': '192.0.2.0/24'}), True),
        ('ipv6', dict(dns_server_address={'local': '2001:db8::/32'}), True),
        ('list-or', dict(dns_server_address={'local': ['10.0.0.0/8', '192.0.2.53']}), True),
        ('tags-and', dict(dns_server_address={'local': '192.0.2.53', 'local2': '2001:db8::/32'}), True),
        ('tags-miss', dict(dns_server_address={'local': '10.0.0.0/8', 'local2': '2001:db8::/32'}), False),
        ('search', dict(dns_search_domain={'local': 'corp.example'}), True),
        ('search-case-dot', dict(dns_search_domain={'local': 'CORP.EXAMPLE.'}), True),
        ('search-not-suffix', dict(dns_search_domain={'local': 'example'}), False),
        ('search-list-or', dict(dns_search_domain={'local': ['bad.example', 'lab.example']}), True),
        ('search-tags-and', dict(dns_search_domain={'local': 'corp.example', 'local2': 'bad.example'}), False),
        ('fields-and', dict(dns_server_address={'local': '192.0.2.53'}, dns_search_domain={'local': 'bad.example'}), False),
        ('invert', dict(dns_search_domain={'local': 'bad.example'}, invert=True), True),
        ('empty-address', dict(dns_server_address={'ignored': []}), True),
        ('empty-domain', dict(dns_search_domain={'ignored': []}), True),
        ('logical', dict(type='logical', mode='or', rules=[dict(dns_search_domain={'local': 'bad.example'}), dict(dns_server_address={'local': '2001:db8::/32'})]), True),
    ]:
        yield name, condition, hit


def run(binary, name, condition, hit, mode, work, echo_port):
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    config = dict(log=dict(disabled=True), inbounds=[dict(type='mixed', listen='127.0.0.1', listen_port=port)],
                  outbounds=[dict(type='direct', tag='direct')], route=dict(final='direct', default_domain_resolver='hosts'),
                  dns=dict(servers=[dict(type='local', tag='local'), dict(type='local', tag='local2'), dict(type='hosts', tag='hosts', predefined={'network.test': ['192.0.2.8']})], final='hosts'))
    if mode == 'dns':
        config['route']['rules'] = [dict(port=53, action='hijack-dns')]
        config['dns']['rules'] = [dict(condition, action='predefined', answer='network.test. 60 IN A 192.0.2.9')]
    else:
        config['route']['rules'] = [dict(condition, action='reject')]
    path = work / 'config.json'
    path.write_text(json.dumps(config))
    with (work / 'process.log').open('w+') as log:
        process = subprocess.Popen([str(binary), 'run', '-c', str(path)], stdout=log, stderr=log)
        try:
            for _ in range(200):
                if process.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read())
                try:
                    socket.create_connection(('127.0.0.1', port), .05).close()
                    break
                except OSError:
                    time.sleep(.01)
            else:
                raise RuntimeError('DNS network reference did not start')
            if mode == 'dns':
                answer = wire.query(port, 'network.test', 1)
                result = socket.inet_ntoa(bytes.fromhex(answer['last_rdata_hex'])) == '192.0.2.9'
            else:
                with socket.create_connection(('127.0.0.1', port), 2) as s:
                    s.sendall(b'\x05\x01\x00')
                    assert wire.readn(s, 2) == b'\x05\x00'
                    s.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + echo_port.to_bytes(2, 'big'))
                    result = wire.readn(s, 2) != b'\x05\x00'
            assert result == hit, (name, mode, binary.name, result, hit)
            return result
        finally:
            process.terminate()
            process.wait(timeout=5)


def main():
    if '--isolated' not in sys.argv:
        # The resolv.conf fixture is visible only in this child mount namespace.
        subprocess.run(['unshare', '-Urm', sys.executable, str(Path(__file__).resolve()), '--isolated'], check=True)
        return
    binaries = dict(native=ROOT / 'build/lanboat-allinone', reference=Path(os.environ.get('LANBOAT_TEST_SINGBOX15', ROOT / '.cache/sing-box-1.15.0-alpha.13/sing-box')))
    report = dict(binary_sha256=hashlib.sha256(binaries['native'].read_bytes()).hexdigest(), reference_sha256=hashlib.sha256(binaries['reference'].read_bytes()).hexdigest(), scope='Private mount namespace only;system resolv.conf fixture;no host DNS or network settings changed', cases=[])
    with tempfile.TemporaryDirectory(prefix='lanboat-dns-network-') as directory, socket.socket() as echo:
        work = Path(directory)
        resolv = work / 'resolv.conf'
        resolv.write_text('nameserver 192.0.2.53\nnameserver 2001:db8::53\nsearch corp.example lab.example\n')
        subprocess.run(['mount', '--make-rprivate', '/'], check=True)
        subprocess.run(['mount', '--bind', str(resolv), '/etc/resolv.conf'], check=True)
        echo.bind(('127.0.0.1', 0))
        echo.listen(64)
        stopping = threading.Event()
        echo.settimeout(.1)

        def accept():
            while not stopping.is_set():
                try:
                    c, _ = echo.accept()
                    c.close()
                except socket.timeout:
                    continue

        worker = threading.Thread(target=accept)
        worker.start()
        try:
            for name, condition, hit in cases():
                for mode in ('dns', 'route'):
                    row = dict(name=name, mode=mode, condition=condition, expected_match=hit)
                    for engine, binary in binaries.items():
                        row[engine] = run(binary, name, condition, hit, mode, work, echo.getsockname()[1])
                    report['cases'].append(row)
                    print(mode, name, 'passed', flush=True)
        finally:
            stopping.set()
            worker.join()
    (ROOT / '.cache/dns-network-wire.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
