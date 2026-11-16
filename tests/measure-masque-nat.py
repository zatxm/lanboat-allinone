#!/usr/bin/env python3
"""Measure real UDP NAT through two release-core processes on Linux loopback."""
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


def measure(work, version, mapping):
    name = f'masque-nat-http{version}-{mapping}'
    server_port, local = SUPPORT['port'](), SUPPORT['port']()
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
    nat = dict(udp_mapping=mapping, udp_filtering='address_and_port_dependent', udp_timeout='1m', udp_nat_max=256)
    server = dict(log=dict(disabled=True), endpoints=[dict(type='masque-server', tag='server',
                  listen='127.0.0.1', listen_port=server_port, version=[version],
                  address=['10.44.0.1/24'], tls=tls, **nat)], outbounds=[dict(type='direct', tag='direct')], route=dict(final='direct'))
    client = dict(log=dict(disabled=True), endpoints=[dict(type='masque-client', tag='proxy', server='127.0.0.1', server_port=server_port,
                  version=version, disable_version_fallback=True, tls=dict(enabled=True, insecure=True), **nat)],
                  inbounds=[dict(type='direct', tag='local', network='udp', listen='127.0.0.1', listen_port=local,
                                 override_address='127.0.0.1', override_port=target.getsockname()[1])], route=dict(final='proxy'))
    processes, logs = [], []
    peaks, combined = [0, 0], [0]
    sampler = None
    payload = b'N' * 1400
    target.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4<<20)

    def transfer(_, data=payload):
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
        # Retry only readiness; failures during the measured transfer are fatal.
        for _ in range(10):
            try:
                transfer(0)
                break
            except OSError:
                if any(p.poll() is not None for p in processes):
                    raise RuntimeError('core failed to start')
        else:
            raise RuntimeError('UDP core not ready')
        transfer(0,b'L'*60000)
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
        return dict(protocol=name, requests=128, concurrency=8, bytes_per_datagram=len(payload), large_datagram_verified=60000, core_processes=2,
                    auxiliary_processes=0, total_peak_rss_mib=round(combined[0], 2), server_peak_rss_mib=round(peaks[0], 2),
                    client_peak_rss_mib=round(peaks[1], 2), elapsed_seconds=elapsed, throughput_mib_s=amount/1048576/elapsed,
                    transfer_cpu_seconds=[(v-b)/hz for v, b in zip(after, before)], idle_cpu_seconds_1s=[v/hz for v in idle])
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
    with tempfile.TemporaryDirectory(prefix='lanboat-nat-measure-') as directory:
        work = Path(directory)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                        '-nodes', '-keyout', 'key.pem', '-out', 'cert.pem', '-subj', '/CN=localhost', '-days', '1'],
                       cwd=work, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        report = dict(binary_sha256=hashlib.sha256(BINARY.read_bytes()).hexdigest(), platform='linux-amd64',
                      scope='Two release cores;1400byte UDP through a direct inbound and MASQUE IP NAT;60000byte preflight;128requests/8concurrency;origin fixture excluded;not GUI,WAN or cross-platform live validation',
                      scenarios=[measure(work, version, mapping) for version in [1, 2, 3]
                                 for mapping in ['endpoint_independent', 'address_and_port_dependent']])
    target = ROOT/'.cache/masque-nat-validation/resources.json'
    target.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
