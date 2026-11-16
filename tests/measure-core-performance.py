#!/usr/bin/env python3
"""Compare two core artifacts with identical loopback TCP workloads (no GUI)."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import socket
import socketserver
import statistics
import subprocess
import tempfile
import threading
import time

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while data := self.request.recv(65536):
                self.request.sendall(data)
        except (OSError, ConnectionError):
            pass

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

def unused_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def receive(s, n):
    result = bytearray()
    while len(result) < n:
        data = s.recv(n-len(result))
        if not data:
            raise RuntimeError('unexpected EOF')
        result.extend(data)
    return result

def connect(front, target):
    s = socket.create_connection(('127.0.0.1', front), 10)
    try:
        s.sendall(b'\x05\x01\x00')
        if receive(s, 2) != b'\x05\x00':
            raise RuntimeError('SOCKS negotiation failed')
        s.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+target.to_bytes(2, 'big'))
        response = receive(s, 4)
        if response[:2] != b'\x05\x00':
            raise RuntimeError('SOCKS connect rejected')
        length = {1: 4, 4: 16}.get(response[3])
        if length is None:
            length = receive(s, 1)[0]
        receive(s, length+2)
        return s
    except BaseException:
        s.close()
        raise

def resources(pids):
    rss, ticks, threads, fds = 0, 0, 0, 0
    for pid in pids:
        base = Path(f'/proc/{pid}')
        for line in (base/'status').read_text().splitlines():
            if line.startswith('VmRSS:'):
                rss += int(line.split()[1])*1024
            if line.startswith('Threads:'):
                threads += int(line.split()[1])
        stat = (base/'stat').read_text().rsplit(')', 1)[1].split()
        ticks += int(stat[11])+int(stat[12])
        fds += len(list((base/'fd').iterdir()))
    return dict(rss_bytes=rss, cpu_seconds=ticks/os.sysconf('SC_CLK_TCK'), threads=threads, fds=fds)

def scenario(binary, mode, connections):
    origin = Server(('127.0.0.1', 0), Echo)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    processes, streams = [], []
    with tempfile.TemporaryDirectory(prefix='lanboat-performance-') as folder:
        work = Path(folder)
        port, front = unused_port(), unused_port()
        while front == port:
            front = unused_port()
        inbound = dict(type='shadowsocks', tag='server', listen='127.0.0.1', listen_port=port, method='aes-256-gcm', password='isolated-perf-fixture')
        outbound = dict(type='shadowsocks', tag='proxy', server='127.0.0.1', server_port=port, method=inbound['method'], password=inbound['password'])
        if mode == 'smux':
            inbound['multiplex'] = dict(enabled=True)
            outbound['multiplex'] = dict(enabled=True, protocol='smux', max_streams=1)
        cfgs = [dict(log=dict(disabled=True), inbounds=[inbound]), dict(log=dict(disabled=True), inbounds=[dict(type='socks', tag='local', listen='127.0.0.1', listen_port=front)], outbounds=[outbound])]
        logs = []
        try:
            start = time.perf_counter()
            for i, cfg in enumerate(cfgs):
                path = work/f'{i}.json'
                path.write_text(json.dumps(cfg))
                log = open(work/f'{i}.log', 'w+')
                logs.append(log)
                process = subprocess.Popen([binary, 'run', '-c', str(path)], stdout=log, stderr=log, env={**os.environ, 'GOMAXPROCS':'2'})
                processes.append(process)
                listening = port if i == 0 else front
                for _ in range(500):
                    if process.poll() is not None:
                        raise RuntimeError('core exited before listening')
                    try:
                        with socket.create_connection(('127.0.0.1', listening), .02):
                            break
                    except OSError:
                        time.sleep(.01)
                else:
                    raise RuntimeError('core did not listen')
            startup_ms = (time.perf_counter()-start)*1000
            for _ in range(connections):
                s = connect(front, origin.server_address[1])
                s.sendall(b'warmup')
                if receive(s, 6) != b'warmup':
                    raise RuntimeError('warmup corruption')
                streams.append(s)
            time.sleep(.1)
            pids = [p.pid for p in processes]
            idle_before = resources(pids)
            before = time.perf_counter()
            time.sleep(1)
            idle = resources(pids)
            idle_cpu = (idle['cpu_seconds']-idle_before['cpu_seconds'])/(time.perf_counter()-before)*100
            latencies = []
            def small(s):
                values = []
                for _ in range(100):
                    start = time.perf_counter()
                    s.sendall(b'x'*128)
                    if receive(s, 128) != b'x'*128:
                        raise RuntimeError('small transfer corruption')
                    values.append((time.perf_counter()-start)*1000)
                return values
            load_before = resources(pids)
            start = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                for values in pool.map(small, streams):
                    latencies.extend(values)
            small_elapsed = time.perf_counter()-start
            small_after = resources(pids)
            payload = b'lanboat-bulk\n'*8192
            def bulk(s):
                for _ in range(16):
                    s.sendall(payload)
                    if receive(s, len(payload)) != payload:
                        raise RuntimeError('bulk transfer corruption')
                return len(payload)*16
            start = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                transferred = sum(pool.map(bulk, streams))
            elapsed = time.perf_counter()-start
            after = resources(pids)
            ordered = sorted(latencies)
            result = dict(mode=mode, connections=connections, startup_ms=startup_ms, idle=idle, idle_cpu_percent=idle_cpu, small_qps=len(ordered)/small_elapsed, small_p50_ms=statistics.median(ordered), small_p99_ms=ordered[min(len(ordered)-1, int(len(ordered)*.99))], small_core_cpu_seconds=small_after['cpu_seconds']-load_before['cpu_seconds'], bulk_mib_s=transferred/2**20/elapsed, bulk_core_cpu_seconds=after['cpu_seconds']-small_after['cpu_seconds'], after_load=after)
            for s in streams:
                s.close()
            streams.clear()
            time.sleep(.3)
            result['after_close'] = resources(pids)
            return result
        except BaseException:
            for log in logs:
                log.flush();log.seek(0)
                print(log.read())
            raise
        finally:
            for s in streams:
                s.close()
            for p in reversed(processes):
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill();p.wait()
            for log in logs:
                log.close()
            origin.shutdown();origin.server_close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--current', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--connections', type=int, default=32)
    args = parser.parse_args()
    rows = []
    for iteration in range(args.rounds):
        for mode in ('plain', 'smux'):
            order = ('baseline', 'current') if iteration%2 == 0 else ('current', 'baseline')
            for label in order:
                print(f'{iteration+1} {mode} {label}', flush=True)
                row = scenario(str(Path(getattr(args, label)).resolve()), mode, args.connections)
                row.update(artifact=label, iteration=iteration+1)
                rows.append(row)
                Path(args.output).write_text(json.dumps(dict(scope='Core client+server RSS sum and CPU in loopback; origin/load generator excluded. Identical payloads and GOMAXPROCS=2; not GUI or public-network measurements.', rows=rows), indent=2)+'\n')

if __name__ == '__main__':
    main()
