"""Compare independent DNS rule scheduling with an official1.15 executable."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('dns_wire', Path(__file__).with_name('check-modern-wire.py'))
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)


class Upstream:
    def __init__(self, delay, address):
        self.delay, self.address = delay, socket.inet_aton(address)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0))
        self.port = self.socket.getsockname()[1]
        self.calls = []
        threading.Thread(target=self.receive, daemon=True).start()

    def receive(self):
        while True:
            try:
                data, source = self.socket.recvfrom(65535)
            except OSError:
                return
            self.calls.append(time.monotonic())
            threading.Thread(target=self.reply, args=(data, source), daemon=True).start()

    def reply(self, query, source):
        time.sleep(self.delay)
        response = bytearray(query)
        response[2:4], response[6:8] = b'\x81\x80', b'\x00\x01'
        response += b'\xc0\x0c\x00\x01\x00\x01' + struct.pack('!IH', 60, 4) + self.address
        try:
            self.socket.sendto(response, source)
        except OSError:
            pass


def evaluate(server, tag='', speculative=False):
    rule = dict(action='evaluate', server=server)
    if tag:
        rule['tag'] = tag
    if speculative:
        rule['speculative'] = True
    return rule


def respond(tag, race=False, match=None):
    rule = dict(action='respond', match_response=tag)
    if race:
        rule['race'] = True
    if match:
        rule['ip_cidr'] = match
    return rule


def cases():
    for speculative in (False, True):
        prefix = [evaluate('a', 'a'), respond('a', race=True)]
        yield dict(name=f'evaluate-race-{speculative}', rules=prefix + [evaluate('b', 'b', speculative), respond('b', race=True)], ip='192.0.2.2' if speculative else '192.0.2.1')
        yield dict(name=f'ordinary-respond-{speculative}', rules=prefix + [evaluate('b', 'b', speculative), respond('b')], ip='192.0.2.1')
        route = dict(action='route', server='b', speculative=speculative)
        yield dict(name=f'route-held-{speculative}', rules=[evaluate('a', 'a'), respond('a', race=True, match='10.0.0.0/8'), route], ip='192.0.2.2', minimum=.20)
    yield dict(name='untagged-snapshot', rules=[evaluate('a'), respond(True, race=True), evaluate('b', speculative=True), respond(True, race=True)], ip='192.0.2.2')
    yield dict(name='last-untagged', rules=[evaluate('a'), evaluate('b', 'b'), respond(True)], ip='192.0.2.1')
    yield dict(name='failed-match-does-not-select', rules=[evaluate('a', 'a'), evaluate('b'), respond('a', match='10.0.0.0/8'), dict(action='respond')], ip='192.0.2.2')
    for mode in ('or', 'and'):
        terms = [dict(match_response='a', ip_cidr='192.0.2.0/24'), dict(match_response='b', ip_cidr='10.0.0.0/8' if mode == 'or' else '192.0.2.0/24')]
        yield dict(name='logical-' + mode, rules=[evaluate('a', 'a'), evaluate('b', 'b'), dict(type='logical', mode=mode, rules=terms, action='route', server='c')], ip='192.0.2.3')
    yield dict(name='logical-untagged-respond', rules=[evaluate('a'), dict(type='logical', mode='or', rules=[dict(match_response=True, ip_cidr='192.0.2.0/24'),dict(domain='other.test')], action='respond')], ip='192.0.2.1')
    yield dict(name='race-route-new-server', rules=[evaluate('a', 'a'), respond('a', race=True), evaluate('b', 'b', True), dict(match_response='b', race=True, action='route', server='c')], ip='192.0.2.3')
    yield dict(name='race-predefined', rules=[evaluate('a', 'a'), respond('a', race=True), evaluate('b', 'b', True), dict(match_response='b', race=True, action='predefined', answer='parallel.test. 60 IN A 192.0.2.9')], ip='192.0.2.9')


def run_case(binary, case, upstreams):
    with tempfile.TemporaryDirectory(prefix='lanboat-dns-parallel-') as directory:
        work = Path(directory)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        config = dict(log=dict(disabled=True), inbounds=[dict(type='mixed', listen='127.0.0.1', listen_port=port)],
                      outbounds=[dict(type='direct', tag='direct')], route=dict(default_domain_resolver='a', rules=[dict(port=53, action='hijack-dns')]),
                      dns=dict(servers=[dict(type='udp', tag=tag, server='127.0.0.1', server_port=up.port) for tag, up in upstreams.items()], rules=copy.deepcopy(case['rules']), disable_cache=True))
        path = work / 'config.json'
        path.write_text(json.dumps(config))
        with (work / 'process.log').open('w+') as log:
            process = subprocess.Popen([str(binary), 'run', '-c', str(path)], cwd=work, stdout=log, stderr=log)
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
                    raise RuntimeError('DNS reference did not start')
                for up in upstreams.values():
                    up.calls.clear()
                start = time.monotonic()
                answer = wire.query(port, 'parallel.test', 1)
                elapsed = time.monotonic() - start
                address = socket.inet_ntoa(bytes.fromhex(answer['last_rdata_hex']))
                assert address == case['ip'], (case['name'], str(binary), address, case['ip'])
                assert elapsed >= case.get('minimum', 0), (case['name'], elapsed)
                return dict(address=address, elapsed_ms=round(elapsed * 1000, 2), calls={tag: len(up.calls) for tag, up in upstreams.items()})
            finally:
                process.terminate()
                process.wait(timeout=5)


def main():
    binaries = dict(native=ROOT / 'build/lanboat-allinone', reference=Path(os.environ.get('LANBOAT_TEST_SINGBOX15', ROOT / '.cache/sing-box-1.15.0-alpha.13/sing-box')))
    for binary in binaries.values():
        subprocess.run([str(binary), 'check', '-c', str(ROOT / 'examples/independent-dns-parallel.json')], check=True, capture_output=True)
    upstreams = dict(a=Upstream(.25, '192.0.2.1'), b=Upstream(.015, '192.0.2.2'), c=Upstream(.005, '192.0.2.3'))
    report = dict(binary_sha256=hashlib.sha256(binaries['native'].read_bytes()).hexdigest(), reference_sha256=hashlib.sha256(binaries['reference'].read_bytes()).hexdigest(), cases=[])
    try:
        for case in cases():
            result = dict(name=case['name'])
            for engine in ("reference","native"):
                binary=binaries[engine]
                result[engine] = run_case(binary, case, upstreams)
            assert result['native']['address'] == result['reference']['address']
            report['cases'].append(result)
            print(case['name'], 'passed', flush=True)
    finally:
        for up in upstreams.values():
            up.socket.close()
    (ROOT / '.cache/dns-parallel-wire.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
