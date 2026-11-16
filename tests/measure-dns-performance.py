#!/usr/bin/env python3
"""Compare core DNS cache CPU/RSS with verified loopback UDP replies on Linux."""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import statistics
import subprocess
import tempfile
import time

spec = importlib.util.spec_from_file_location('core_measure', Path(__file__).with_name('measure-core-performance.py'))
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)


def query(name, identifier):
    return identifier.to_bytes(2, 'big') + b'\x01\x00\x00\x01' + bytes(6) + b''.join(bytes([len(label)]) + label.encode() for label in name.split('.')) + b'\0\x00\x01\x00\x01'


def exchange(s, packet):
    s.send(packet)
    reply = s.recv(65535)
    assert reply[:2] == packet[:2] and reply[2:12] == b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00', 'DNS header mismatch'
    assert reply[12:len(packet)] == packet[12:] and reply[-4:] == b'\xc0\x00\x02\x01', 'DNS question/answer mismatch'


def scenario(binary, entries, queries, workers, core_cpus):
    names = [f'cache{i}.test' for i in range(entries)]
    port = core.unused_port()
    config = dict(log=dict(disabled=True), inbounds=[dict(type='dns', tag='dns', listen='127.0.0.1', listen_port=port)],
                  dns=dict(cache_capacity=max(1024, entries), servers=[dict(type='hosts', tag='hosts', predefined={name: ['192.0.2.1'] for name in names})]))
    with tempfile.TemporaryDirectory(prefix='lanboat-dns-perf-') as directory:
        work = Path(directory)
        (work/'config.json').write_text(json.dumps(config))
        with (work/'core.log').open('w+') as log:
            process = subprocess.Popen([binary, 'run', '-c', str(work/'config.json')], stdout=log, stderr=log, env={**os.environ, 'GOMAXPROCS': '2'})
            try:
                os.sched_setaffinity(process.pid, core_cpus)
                for _ in range(500):
                    if process.poll() is not None:
                        log.seek(0)
                        raise RuntimeError(log.read())
                    try:
                        socket.create_connection(('127.0.0.1', port), .02).close()
                        break
                    except OSError:
                        time.sleep(.01)
                else:
                    raise RuntimeError('DNS listener did not start')
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(5)
                    s.connect(('127.0.0.1', port))
                    for i, name in enumerate(names):
                        exchange(s, query(name, i % 65536))
                time.sleep(.1)
                before = core.resources([process.pid])

                def load(worker):
                    latencies = []
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(5)
                        s.connect(('127.0.0.1', port))
                        for i in range(worker, queries, workers):
                            packet = query(names[i % entries], i % 65536)
                            start = time.perf_counter()
                            exchange(s, packet)
                            latencies.append((time.perf_counter()-start)*1000)
                    return latencies

                started = time.perf_counter()
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                    latencies = sorted(value for values in pool.map(load, range(workers)) for value in values)
                elapsed = time.perf_counter()-started
                after = core.resources([process.pid])
                assert len(latencies) == queries
                return dict(entries=entries, queries=queries, workers=workers, qps=queries/elapsed,
                            p50_ms=statistics.median(latencies), p99_ms=latencies[min(queries-1, int(queries*.99))],
                            core_cpu_seconds=after['cpu_seconds']-before['cpu_seconds'], before=before, after=after)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--current', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--rounds', type=int, default=5)
    parser.add_argument('--queries', type=int, default=100000)
    parser.add_argument('--workers', type=int, default=8)
    args = parser.parse_args()
    assert args.rounds > 0 and args.queries >= args.workers > 0
    cpus = sorted(os.sched_getaffinity(0))
    assert len(cpus) >= 4, 'measurement needs four available logical CPUs'
    core_cpus, load_cpus = cpus[:2], cpus[2:4]
    os.sched_setaffinity(0, load_cpus)
    binaries = {name: str(Path(getattr(args, name)).resolve()) for name in ('baseline', 'current')}
    report = dict(scope='Linux core process only; loopback UDP DNS, hosts upstream, cache fully warmed; GOMAXPROCS=2; Python load generator excluded; no GUI, TUN or public DNS measurement.',
                  affinity=dict(core_cpus=core_cpus, load_cpus=load_cpus),
                  artifacts={name: hashlib.sha256(Path(path).read_bytes()).hexdigest() for name, path in binaries.items()}, rows=[])
    for iteration in range(args.rounds):
        for entries in (1, 4096):
            for label in (('baseline', 'current') if iteration % 2 == 0 else ('current', 'baseline')):
                print(iteration+1, entries, label, flush=True)
                row = scenario(binaries[label], entries, args.queries, args.workers, core_cpus)
                report['rows'].append(dict(row, artifact=label, iteration=iteration+1))
                Path(args.output).write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
