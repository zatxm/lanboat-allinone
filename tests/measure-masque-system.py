#!/usr/bin/env python3
"""Measure real MASQUE kernel-interface traffic in a private Linux namespace."""
import concurrent.futures
import hashlib
import http.client
import http.server
import json
import os
import re
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'build/lanboat-allinone'
PAYLOAD = b'Lanboat MASQUE system\n' * 3500


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def log_message(self, *_):
        pass


class OriginServer(http.server.ThreadingHTTPServer):
    request_queue_size = 128


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def port():
    with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        tcp.bind(('127.0.0.1', 0))
        value = tcp.getsockname()[1]
        udp.bind(('127.0.0.1', value))
        return value


def sample(pid):
    rss = next(int(line.split()[1]) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if line.startswith('VmRSS:'))
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return rss / 1024, int(fields[11]) + int(fields[12])


def measure(work, role, version):
    name = ('openconnect-system-dtls' if version else 'openconnect-system-cstp') if role == 'openconnect' else f'masque-system-{role}-http{version}'
    print('Measuring ' + name, file=sys.stderr, flush=True)
    listen, local = port(), port()
    server = dict(type='masque-server', tag='server', listen='127.0.0.1', listen_port=listen,
                  version=[version], users=[dict(username='client', password='measurement-only')],
                  address=['10.44.0.1/24', 'fd44::1/64'],
                  tls=dict(enabled=True, certificate_path=str(work/'cert.pem'), key_path=str(work/'key.pem')))
    client = dict(type='masque-client', tag='proxy', server='127.0.0.1', server_port=listen,
                  username='client', password='measurement-only', version=version, disable_version_fallback=True,
                  tls=dict(enabled=True, insecure=True))
    (server if role == 'server' else client).update(system=True, name='lbmeasure0')
    configs = [dict(log=dict(disabled=True), endpoints=[server], outbounds=[dict(type='direct', tag='direct')],
                    route=dict(final='direct', rules=[dict(ip_cidr=['192.0.2.0/24'], outbound='direct', override_address='127.0.0.1')])),
               dict(log=dict(disabled=True), endpoints=[client], route=dict(final='proxy'),
                    inbounds=[dict(type='mixed', tag='local', listen='127.0.0.1', listen_port=local)])]
    if role == 'openconnect':
        server = dict(type='openconnect', tag='server', listen='127.0.0.1', listen_port=listen,
                      users=[dict(username='client', password='measurement-only')], disable_dtls=not version,
                      split_include=['192.0.2.0/24'],
                      tls=dict(enabled=True, certificate_path=str(work/'cert.pem'), key_path=str(work/'key.pem')))
        client = dict(type='openconnect', tag='proxy', server='127.0.0.1', server_port=listen,
                      username='client', password='measurement-only', disable_dtls=not version,
                      system=True, name='lbmeasure0', tls=dict(enabled=True, insecure=True))
        configs[0].pop('endpoints')
        configs[0]['inbounds'] = [server]
        configs[1].pop('endpoints')
        configs[1]['outbounds'] = [client]
        for config in configs:
            config['log'] = dict(level='debug')
    processes, logs = [], []
    origin = None
    stop = threading.Event()
    sampler = None
    peaks, total = [0, 0], [0]
    started = time.monotonic()
    try:
        for index, config in enumerate(configs):
            path = work/f'{name}-{index}.json'
            path.write_text(json.dumps(config))
            log = (work/f'{name}-{index}.log').open('w')
            logs.append(log)
            processes.append(subprocess.Popen([str(BINARY), 'run', '-c', str(path)], stdout=log, stderr=log))
        for _ in range(400):
            if any(p.poll() is not None for p in processes):
                raise RuntimeError('core exited: ' + '\n'.join(p.read_text() for p in work.glob(f'{name}-*.log')))
            try:
                interface = socket.if_nametoindex('lbmeasure0')
                if role == 'server':
                    with socket.socket() as ready:
                        ready.bind(('10.44.0.1', 0))
                with socket.create_connection(('127.0.0.1', local), timeout=.05):
                    break
            except OSError:
                time.sleep(.005)
        else:
            raise RuntimeError('system interface did not become ready')
        assert interface
        if role == 'openconnect' and version:
            for _ in range(800):
                if all('OpenConnect DTLS channel ready' in Path(log.name).read_text() for log in logs):
                    break
                time.sleep(.005)
            else:
                raise RuntimeError('OpenConnect DTLS was not ready')
        if role == 'client':
            command('ip', 'route', 'add', '192.0.2.0/24', 'dev', 'lbmeasure0')
        origin = OriginServer(('10.44.0.1' if role == 'server' else '127.0.0.1', 0), Origin)
        origin.daemon_threads = True
        origin_job = threading.Thread(target=origin.serve_forever)
        origin_job.start()
        target = '10.44.0.1' if role == 'server' else '192.0.2.42'

        def transfer(_):
            conn = http.client.HTTPConnection('127.0.0.1' if role == 'server' else target,
                                              local if role == 'server' else origin.server_port, timeout=8)
            try:
                conn.request('GET', f'http://{target}:{origin.server_port}/' if role == 'server' else '/')
                response = conn.getresponse()
                body = response.read()
                assert response.status == 200 and body == PAYLOAD, (response.status, len(body))
                return len(body)
            finally:
                conn.close()

        transfer(0)
        startup_ms = (time.monotonic()-started)*1000
        before = [sample(p.pid)[1] for p in processes]
        time.sleep(1)
        idle_ticks = [sample(p.pid)[1]-value for p, value in zip(processes, before)]

        def sampling():
            while not stop.is_set():
                readings = [sample(p.pid)[0] for p in processes]
                for index, value in enumerate(readings):
                    peaks[index] = max(peaks[index], value)
                total[0] = max(total[0], sum(readings))
                stop.wait(.005)

        sampler = threading.Thread(target=sampling)
        sampler.start()
        before = [sample(p.pid)[1] for p in processes]
        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            transferred = sum(pool.map(transfer, range(128)))
        elapsed = time.monotonic()-started
        cpu_ticks = [sample(p.pid)[1]-value for p, value in zip(processes, before)]
        stop.set()
        sampler.join()
        for p in processes:
            assert Path(f'/proc/{p.pid}/task/{p.pid}/children').read_text().strip() == ''
        hz = os.sysconf('SC_CLK_TCK')
        report = dict(protocol=name, http_version=version, system_role=role, core_processes=2, auxiliary_processes=0,
                    requests=128, concurrency=8, bytes_per_request=len(PAYLOAD), total_peak_rss_mib=total[0],
                    server_peak_rss_mib=peaks[0], client_peak_rss_mib=peaks[1], idle_seconds=1,
                    idle_cpu_ticks=idle_ticks, transfer_cpu_seconds=[v/hz for v in cpu_ticks],
                    startup_ms=startup_ms, elapsed_seconds=elapsed, throughput_mib_s=transferred/1048576/elapsed)
        if role == 'openconnect':
            report.pop('http_version')
            report.update(system_role='client', dtls=bool(version))
        return report
    finally:
        stop.set()
        if sampler is not None:
            sampler.join()
        if origin is not None:
            origin.shutdown()
            origin.server_close()
            origin_job.join()
        for p in processes:
            p.terminate()
        for p in processes:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
                raise RuntimeError('core did not shut down cleanly')
        for log in logs:
            log.close()
        if role == 'openconnect' and version:
            assert all(re.search(r'"sent_ip_packets":\s*[1-9]', Path(log.name).read_text()) and
                       re.search(r'"received_ip_packets":\s*[1-9]', Path(log.name).read_text()) for log in logs), 'DTLS did not carry bidirectional IP traffic'
        try:
            socket.if_nametoindex('lbmeasure0')
        except OSError:
            pass
        else:
            raise RuntimeError('system interface leaked after shutdown')


def main():
    if '--namespace' not in sys.argv:
        subprocess.run(['unshare', '-Urn', sys.executable, __file__, '--namespace'], check=True, cwd=ROOT)
        return
    command('ip', 'link', 'set', 'lo', 'up')
    with tempfile.TemporaryDirectory(prefix='lanboat-masque-system-') as directory:
        work = Path(directory)
        command('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
                '-keyout', str(work/'key.pem'), '-out', str(work/'cert.pem'), '-subj', '/CN=localhost', '-days', '1')
        report = dict(binary_sha256=hashlib.sha256(BINARY.read_bytes()).hexdigest(),
                      probe_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), platform='linux-amd64',
                      scope='Two release-core processes, real Linux TUN and kernel TCP; origin/tester excluded from core RSS/CPU; not WAN, GUI, long-term idle or target-platform measurements',
                      scenarios=[measure(work, role, version) for role in ('client', 'server') for version in (1, 2, 3)])
    output = ROOT/'.cache/masque-system-validation/resources.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
