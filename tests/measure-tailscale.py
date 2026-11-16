#!/usr/bin/env python3
"""Linux client-only RSS/CPU against the isolated official Tailscale reference."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'build/lanboat-allinone'
REFERENCE = Path(os.environ.get('LANBOAT_TEST_TAILSCALE', ROOT / '.cache/tailscale-reference'))


def recv(sock, size):
    result = bytearray()
    while len(result) < size:
        data = sock.recv(size - len(result))
        if not data:
            raise RuntimeError('truncated echo')
        result.extend(data)
    return bytes(result)


def sample(pid):
    rss = next(int(line.split()[1]) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if line.startswith('VmRSS:'))
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return rss * 1024, int(fields[11]) + int(fields[12])


def run(force, fixture, work, dns_kind=None, ref=None):
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    config = dict(log=dict(disabled=True), inbounds=[dict(type='mixed', tag='local', listen='127.0.0.1', listen_port=port)], endpoints=[dict(type='tailscale', tag='ts', hostname='lanboat-measure', auth_key='test-only-auth', control_url=fixture['control_url'], state_directory=str(work / f'state-{force}'), taildrop_directory=str(work / f'drop-{force}'), force_derp=force)], route=dict(final='ts'))
    kind = dns_kind or 'plain'
    state = work / f'state-{force}-{kind}'
    config['endpoints'][0].update(hostname=f'measure-{str(force).lower()}-{kind}', state_directory=str(state))
    dns_port = None
    if dns_kind:
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            dns_port = probe.getsockname()[1]
        config['inbounds'].append(dict(type='dns', tag='dns-in', listen='127.0.0.1', listen_port=dns_port))
        config['dns'] = dict(servers=[dict(type='tailscale', tag='dns', endpoint='ts')], disable_cache=True)
    file = work / f'{force}-{kind}.json'
    file.write_text(json.dumps(config))
    core = subprocess.Popen([str(BINARY), 'run', '-c', str(file)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    stop = threading.Event()
    peak = [0]

    def monitor():
        while not stop.wait(0.005):
            try:
                peak[0] = max(peak[0], sample(core.pid)[0])
            except (FileNotFoundError, StopIteration):
                return

    thread = threading.Thread(target=monitor)
    thread.start()

    def exchange(index):
        if dns_kind:
            name = 'reference.test.ts.net' if dns_kind == 'magic' else 'www.corp.test'
            q = (index % 65536).to_bytes(2, 'big') + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            q += b''.join(bytes([len(label)]) + label.encode() for label in name.split('.')) + b'\x00\x00\x01\x00\x01'
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
                dns.settimeout(15)
                dns.sendto(q, ('127.0.0.1', dns_port))
                reply = dns.recv(65535)
                want = fixture['ip'] if dns_kind == 'magic' else '192.0.2.42'
                assert reply[:2] == q[:2] and reply[3] & 15 == 0 and reply.endswith(socket.inet_aton(want)), reply.hex()
        with socket.create_connection(('127.0.0.1', port), timeout=15) as s:
            s.sendall(b'\x05\x01\x00')
            assert recv(s, 2) == b'\x05\x00'
            s.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(fixture['ip']) + (8080).to_bytes(2, 'big'))
            header = recv(s, 4)
            assert header[:2] == b'\x05\x00', header
            recv(s, {1: 4, 4: 16}[header[3]] + 2)
            payload = (f'lanboat-{index:04d}:'.encode() * 6000)[:70000]
            s.sendall(payload)
            assert recv(s, len(payload)) == payload

    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                    break
            except OSError:
                if core.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('client did not start')
                time.sleep(0.02)
        if dns_kind:
            # Start registration without DNS; the endpoint is normally lazy.
            with socket.create_connection(('127.0.0.1', port), timeout=15) as s:
                s.sendall(b'\x05\x01\x00'); assert recv(s, 2) == b'\x05\x00'
                s.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(fixture['ip']) + (8080).to_bytes(2, 'big'))
                header = recv(s, 4); assert header[:2] == b'\x05\x00', header
                recv(s, {1: 4, 4: 16}[header[3]] + 2)
            pushed = dict(Proxied=True, Routes={'test.ts.net': [], 'corp.test': [dict(Addr=fixture['ip'] + ':5353')]})
            ref.stdin.write(json.dumps(dict(op='dns', hostname=config['endpoints'][0]['hostname'], dns=pushed)) + '\n');ref.stdin.flush()
            assert json.loads(ref.stdout.readline())['ok']
            time.sleep(0.1)
        exchange(0)
        time.sleep(1)
        idle_start = sample(core.pid)[1]
        t0 = time.monotonic()
        time.sleep(2)
        idle_seconds = time.monotonic() - t0
        idle_ticks = sample(core.pid)[1] - idle_start
        cpu0 = sample(core.pid)[1]
        t0 = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(exchange, range(128)))
        elapsed = time.monotonic() - t0
        cpu_ticks = sample(core.pid)[1] - cpu0
        children = Path(f'/proc/{core.pid}/task/{core.pid}/children').read_text().split()
        assert not children, children
        hz = os.sysconf('SC_CLK_TCK')
        return dict(force_derp=force, dns=dns_kind, dns_cache_disabled=bool(dns_kind), requests=128, concurrency=8, payload_bytes_per_request=70000, elapsed_seconds=round(elapsed, 3), client_peak_rss_mib=round(peak[0] / 1048576, 2), client_cpu_seconds=round(cpu_ticks / hz, 3), idle_cpu_percent_one_core=round(idle_ticks / hz / idle_seconds * 100, 2), auxiliary_processes=children)
    finally:
        stop.set()
        thread.join()
        core.terminate()
        try:
            core.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            core.kill()
            core.communicate()


def main():
    with tempfile.TemporaryDirectory(prefix='lanboat-tailscale-') as temp:
        work = Path(temp)
        with (work / 'reference.log').open('w') as log:
            ref = subprocess.Popen([str(REFERENCE)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True, env=dict(os.environ, TS_DISABLE_LOGTAIL='true', LANBOAT_TS_DNS='1'))
            try:
                fixture = json.loads(ref.stdout.readline())
                scenarios = [run(force, fixture, work, kind, ref) for kind in (None, 'magic', 'split') for force in (True, False)]
            finally:
                ref.stdin.close()
                ref.terminate()
                try:
                    ref.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    ref.kill()
                    ref.wait()
        report = dict(binary_sha256=hashlib.sha256(BINARY.read_bytes()).hexdigest(), reference_sha256=hashlib.sha256(REFERENCE.read_bytes()).hexdigest(), reference_version='Tailscale1.104.4', scope='Linux loopback reference control/DERP and official userspace peer. RSS and CPU cover only the independent client process and all its children (none); separate official server fixture is excluded. Not GUI, TUN or WAN performance.', scenarios=scenarios)
        out = ROOT / '.cache/tailscale-validation/resources.json'
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
