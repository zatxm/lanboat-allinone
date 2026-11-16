#!/usr/bin/env python3
"""Measure the core's mDNS transport inside a private Linux network namespace."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'build/lanboat-allinone'


def command(*args):
    subprocess.run(args, check=True, capture_output=True)


def responder(ipv6):
    conn = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM)
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if ipv6:
        conn.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        conn.bind(('::', 5353))
        conn.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                        socket.inet_pton(socket.AF_INET6, 'ff02::fb') + struct.pack('@I', socket.if_nametoindex('mdns0')))
    else:
        conn.bind(('0.0.0.0', 5353))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                        socket.inet_aton('224.0.0.251') + socket.inet_aton('192.0.2.1'))
        conn.setsockopt(socket.IPPROTO_IP, 49, 0)  # IP_MULTICAST_ALL
    conn.settimeout(0.1)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                query, peer = conn.recvfrom(65535)
            except socket.timeout:
                continue
            if len(query) < 16 or query[2:4] != b'\0\0':
                continue
            typ = int.from_bytes(query[-4:-2], 'big')
            data = socket.inet_pton(socket.AF_INET if typ == 1 else socket.AF_INET6,
                                    '192.0.2.42' if typ == 1 else '2001:db8::42')
            reply = bytearray(query)
            reply[2:4] = b'\x84\0'
            reply[6:8] = b'\0\x01'
            reply += b'\xc0\x0c' + struct.pack('!HHIH', typ, 1, 10, len(data)) + data
            conn.sendto(reply, peer)

    job = threading.Thread(target=serve)
    job.start()

    def close():
        stop.set()
        job.join()
        conn.close()
    return close


def sample(pid):
    rss = next(int(line.split()[1]) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if line.startswith('VmRSS:'))
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return rss / 1024, int(fields[11]) + int(fields[12])


def measure(work, cached):
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    config = dict(log=dict(disabled=True), inbounds=[dict(type='dns', tag='dns-in', listen='127.0.0.1', listen_port=port)],
                  route=dict(rules=[dict(inbound=['dns-in'], action='hijack-dns')]),
                  dns=dict(disable_cache=not cached, timeout='2s', servers=[dict(type='mdns', tag='lan', interface=['mdns0'])]))
    file = work / f'{cached}.json'
    file.write_text(json.dumps(config))
    core = subprocess.Popen([str(BINARY), 'run', '-c', str(file)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def exchange(index):
        typ = 1 if index % 2 == 0 else 28
        query = os.urandom(2) + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06device\x05local\x00' + struct.pack('!HH', typ, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(3)
            peer.sendto(query, ('127.0.0.1', port))
            reply = peer.recv(65535)
        expected = socket.inet_pton(socket.AF_INET if typ == 1 else socket.AF_INET6, '192.0.2.42' if typ == 1 else '2001:db8::42')
        assert reply[:2] == query[:2] and reply[2] & 128 and reply[3] & 15 == 0 and reply.endswith(expected), reply.hex()

    stop = threading.Event()
    jobs = []
    peak = [0]
    try:
        for attempt in range(200):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.05):
                    break
            except OSError:
                if core.poll() is not None:
                    raise RuntimeError(core.stderr.read().decode())
                time.sleep(0.005)
        else:
            raise RuntimeError('mDNS core did not start')
        exchange(0)
        exchange(1)
        _, before_ticks = sample(core.pid)
        before = time.monotonic()
        time.sleep(1)
        idle_cpu = (sample(core.pid)[1]-before_ticks) / os.sysconf('SC_CLK_TCK') / (time.monotonic()-before)*100

        def monitor():
            while not stop.wait(0.005):
                peak[0] = max(peak[0], sample(core.pid)[0])
        peak[0] = sample(core.pid)[0]
        job = threading.Thread(target=monitor)
        job.start()
        jobs.append(job)
        started = time.monotonic()
        before_ticks = sample(core.pid)[1]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(exchange, range(128)))
        elapsed = time.monotonic()-started
        cpu = (sample(core.pid)[1]-before_ticks) / os.sysconf('SC_CLK_TCK')
        children = Path(f'/proc/{core.pid}/task/{core.pid}/children').read_text().split()
        assert not children, children
        return dict(protocol='dns-mdns-cached' if cached else 'dns-mdns', requests=128, concurrency=8,
                    query_types=['A', 'AAAA'], cached=cached, client_peak_rss_mib=round(peak[0], 2),
                    client_cpu_seconds=round(cpu, 3), elapsed_seconds=round(elapsed, 4),
                    idle_cpu_percent_1s=round(idle_cpu, 2), auxiliary_processes=0)
    finally:
        stop.set()
        for job in jobs:
            job.join()
        core.terminate()
        core.wait(timeout=5)
        core.stderr.close()


def main():
    if '--child' not in sys.argv:
        result = subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--child'], check=True, capture_output=True, text=True)
        report = json.loads(result.stdout)
        path = ROOT / '.cache/mdns-validation/resources.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report, indent=2))
        return
    command('ip', 'link', 'set', 'lo', 'up')
    command('ip', 'link', 'add', 'mdns0', 'type', 'dummy')
    for address in ['192.0.2.1/24', '2001:db8:44::1/64', 'fe80::1/64']:
        command('ip', 'addr', 'add', address, 'dev', 'mdns0', 'nodad')
    command('ip', 'link', 'set', 'mdns0', 'up', 'multicast', 'on')
    close = [responder(False), responder(True)]
    try:
        with tempfile.TemporaryDirectory(prefix='lanboat-mdns-measure-') as directory:
            scenarios = [measure(Path(directory), cached) for cached in [False, True]]
        print(json.dumps(dict(binary_sha256=hashlib.sha256(BINARY.read_bytes()).hexdigest(),
                              probe_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                              platform='linux-amd64', scenarios=scenarios,
                              scope='One native core process,mDNS query and cache paths;real IPv4/IPv6 multicast in a private Linux network namespace;fixture threads excluded;not GUI,WAN,TUN or system Avahi measurements')))
    finally:
        for stop in close:
            stop()


if __name__ == '__main__':
    main()
