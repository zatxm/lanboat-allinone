#!/usr/bin/env python3
"""Measure MASQUE UDP through an addressed proxy in two release processes."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import runpy
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'build/lanboat-allinone'
SUPPORT = runpy.run_path(str(ROOT / 'tests/measure-masque-system.py'))
OUTPUT = ROOT / '.cache/masque-carrier-validation/resources.json'


def measure(work, version, kind):
    name = f'masque-carrier-http{version}-{kind}'
    ports = set()
    while len(ports) < 3:
        ports.add(SUPPORT['port']())
    listen, local, proxy = ports
    target = socket.socket(type=socket.SOCK_DGRAM)
    target.bind(('127.0.0.1', 0))
    target.settimeout(.1)
    stop = threading.Event()
    errors = []

    def echo():
        while not stop.is_set():
            try:
                data, peer = target.recvfrom(65535)
                target.sendto(data, peer)
            except socket.timeout:
                continue
            except OSError as error:
                errors.append(str(error))
                return

    listener = threading.Thread(target=echo)
    listener.start()
    tls = dict(enabled=True, certificate_path=str(work/'cert.pem'), key_path=str(work/'key.pem'))
    inbound = dict(type=kind, tag='carrier-server', listen='127.0.0.1', listen_port=proxy)
    outbound = dict(type=kind, tag='carrier', server='127.0.0.1', server_port=proxy)
    if kind == 'socks':
        inbound['users'] = [dict(username='client', password='measurement-only')]
        outbound.update(username='client', password='measurement-only')
    elif kind == 'shadowsocks':
        psk = 'BwcHBwcHBwcHBwcHBwcHBw=='
        inbound.update(method='2022-blake3-aes-128-gcm', password=psk)
        outbound.update(method=inbound['method'], password=psk)
    else:
        inbound.update(users=[dict(password='measurement-only')], tls=tls)
        outbound.update(password='measurement-only', tls=dict(enabled=True, insecure=True))
    server = dict(log=dict(disabled=True), endpoints=[dict(type='masque-server', tag='server', listen='127.0.0.1',
                  listen_port=listen, version=[version], address=['10.44.0.1/24'], tls=tls,
                  udp_mapping='endpoint_independent', udp_filtering='address_and_port_dependent')],
                  outbounds=[outbound], route=dict(final='carrier'))
    client = dict(log=dict(disabled=True), endpoints=[dict(type='masque-client', tag='proxy', server='127.0.0.1',
                  server_port=listen, version=version, disable_version_fallback=True, tls=dict(enabled=True, insecure=True))],
                  inbounds=[inbound, dict(type='direct', tag='local', network='udp', listen='127.0.0.1',
                  listen_port=local, override_address='127.0.0.1', override_port=target.getsockname()[1])],
                  outbounds=[dict(type='direct', tag='direct')],
                  route=dict(final='proxy', rules=[dict(inbound=['carrier-server'], outbound='direct')]))
    processes, logs = [], []
    peaks, combined = [0, 0], [0]
    sampler = None

    def transfer(_, data=b'N'*1400):
        with socket.socket(type=socket.SOCK_DGRAM) as conn:
            conn.settimeout(8)
            conn.sendto(data, ('127.0.0.1', local))
            reply = conn.recv(65535)
            assert reply == data, len(reply)
            return len(reply)

    def monitor():
        while not stop.wait(.005):
            values = [SUPPORT['sample'](p.pid)[0] for p in processes]
            combined[0] = max(combined[0], sum(values))
            for i, value in enumerate(values):
                peaks[i] = max(peaks[i], value)

    try:
        for i, config in enumerate([server, client]):
            path = work/f'{name}-{i}.json'
            path.write_text(json.dumps(config))
            log = (work/f'{name}-{i}.log').open('w+')
            logs.append(log)
            processes.append(subprocess.Popen([str(BINARY), 'run', '-c', str(path)], stdout=log, stderr=log))
        for _ in range(5):
            try:
                transfer(0)
                break
            except OSError:
                if any(p.poll() is not None for p in processes):
                    raise RuntimeError('core startup failed: '+ '\n'.join(Path(log.name).read_text() for log in logs))
        else:
            raise RuntimeError('UDP core not ready')
        transfer(0, b'L'*60000)
        sampler = threading.Thread(target=monitor)
        sampler.start()
        before = [SUPPORT['sample'](p.pid)[1] for p in processes]
        start = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            amount = sum(pool.map(transfer, range(128)))
        elapsed = time.monotonic()-start
        after = [SUPPORT['sample'](p.pid)[1] for p in processes]
        time.sleep(1)
        idle = [SUPPORT['sample'](p.pid)[1]-tick for p, tick in zip(processes, after)]
        hz = os.sysconf('SC_CLK_TCK')
        for p in processes:
            assert not Path(f'/proc/{p.pid}/task/{p.pid}/children').read_text().strip()
        assert not errors, errors
        return dict(protocol=name, requests=128, concurrency=8, bytes_per_datagram=1400,
                    large_datagram_verified=60000, core_processes=2, auxiliary_processes=0,
                    total_peak_rss_mib=round(combined[0], 2), server_peak_rss_mib=round(peaks[0], 2),
                    client_peak_rss_mib=round(peaks[1], 2), elapsed_seconds=elapsed,
                    throughput_mib_s=amount/1048576/elapsed,
                    transfer_cpu_seconds=[(v-b)/hz for v, b in zip(after, before)],
                    idle_cpu_seconds_1s=[v/hz for v in idle])
    finally:
        stop.set()
        if sampler:
            sampler.join()
        listener.join()
        target.close()
        for p in processes:
            p.terminate()
        for p in processes:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
                raise RuntimeError('core shutdown exceeded5seconds')
        for log in logs:
            log.close()


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix='lanboat-carrier-measure-') as directory:
        work = Path(directory)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                        '-nodes', '-keyout', 'key.pem', '-out', 'cert.pem', '-subj', '/CN=localhost', '-days', '1'],
                       cwd=work, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        report = dict(binary_sha256=hashlib.sha256(BINARY.read_bytes()).hexdigest(), platform='linux-amd64',
                      probe_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      scope='Two release cores;MASQUE IP and SOCKS5/SS2022/HY2 relay;1400byte UDP,128requests/8concurrency,60000byte preflight;origin/tester excluded;not WAN,GUI or target-platform live validation',
                      scenarios=[measure(work, version, kind) for version in [1, 2, 3]
                                 for kind in ['socks', 'shadowsocks', 'hysteria2']])
    OUTPUT.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
