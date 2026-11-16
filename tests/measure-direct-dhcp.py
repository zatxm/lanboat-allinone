#!/usr/bin/env python3
"""Single-core CLI measurements in a private Linux network namespace."""
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


def sample(pid):
    status = Path(f'/proc/{pid}/status').read_text().splitlines()
    rss = next(int(line.split()[1]) / 1024 for line in status if line.startswith('VmRSS:'))
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return rss, int(fields[11]) + int(fields[12])


def receiver(conn, respond):
    conn.settimeout(.1)
    stop = threading.Event()
    errors = []

    def run():
        while not stop.is_set():
            try:
                data, peer = conn.recvfrom(65535)
                reply = respond(data)
                if reply is not None:
                    conn.sendto(reply, peer)
            except socket.timeout:
                continue
            except Exception as error:
                errors.append(repr(error))
                return

    worker = threading.Thread(target=run)
    worker.start()

    def close():
        stop.set()
        worker.join()
        conn.close()
        assert not errors, errors
    return close


def measure(work, mode):
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    config = {'log': {'disabled': True}, 'inbounds': [
        {'type': 'direct', 'tag': 'in', 'listen': '127.0.0.1', 'listen_port': port}]}
    dns = mode.startswith('dhcp-')
    tcp = mode == 'direct-tcp'
    if dns:
        config['dns'] = {'servers': [{'type': 'dhcp', 'tag': 'lan', 'interface': 'dhcp0'}],
                         'disable_cache': mode == 'dhcp-uncached'}
        config['route'] = {'rules': [{'action': 'hijack-dns'}]}
    else:
        config['inbounds'][0].update(network='tcp' if tcp else 'udp',
                                    override_address='127.0.0.1', override_port=9000)
    path = work / f'{mode}.json'
    path.write_text(json.dumps(config))
    log = (work / f'{mode}.log').open('w+')
    core = subprocess.Popen([str(BINARY), 'run', '-c', str(path)], stdout=log, stderr=log)
    payload = b'Lanboat direct transfer\n' * 3000 if tcp else b'direct-udp' * 140

    def transfer(index):
        query = payload
        if dns:
            name = b'\x08resource\x04test\0'
            query = struct.pack('!HHHHHH', index, 256, 1, 0, 0, 0) + name + struct.pack('!HH', 1, 1)
        with socket.socket(type=socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            client.connect(('127.0.0.1', port))
            client.sendall(query)
            if tcp:
                reply = bytearray()
                while len(reply) < len(payload):
                    part = client.recv(len(payload) - len(reply))
                    assert part, 'unexpected EOF'
                    reply += part
                assert reply == payload
            else:
                reply = client.recv(65535)
                if dns:
                    assert reply[:2] == query[:2] and reply[3] & 15 == 0
                    assert reply[-4:] == socket.inet_aton('203.0.113.42')
                else:
                    assert reply == payload

    stop = threading.Event()
    peak = [0.0]

    def monitor():
        while not stop.wait(.005):
            try:
                peak[0] = max(peak[0], sample(core.pid)[0])
            except FileNotFoundError:
                return

    watcher = None
    try:
        until = time.monotonic() + 5
        while True:
            try:
                transfer(65535)
                break
            except (OSError, AssertionError):
                if core.poll() is not None or time.monotonic() > until:
                    log.seek(0)
                    raise RuntimeError(log.read())
                time.sleep(.01)
        initial_rss, initial_ticks = sample(core.pid)
        peak[0] = initial_rss
        watcher = threading.Thread(target=monitor)
        watcher.start()
        start = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(transfer, range(128)))
        elapsed = time.monotonic() - start
        _, end_ticks = sample(core.pid)
        idle_ticks = end_ticks
        time.sleep(1)
        _, idle_end = sample(core.pid)
        descendants = Path(f'/proc/{core.pid}/task/{core.pid}/children').read_text().split()
        assert not descendants, descendants
        hz = os.sysconf('SC_CLK_TCK')
        return {'mode': mode, 'requests': 128, 'concurrency': 8, 'core_processes': 1,
                'auxiliary_processes': 0, 'peak_rss_mib': round(peak[0], 2),
                'elapsed_seconds': round(elapsed, 6), 'transfer_cpu_seconds': (end_ticks - initial_ticks) / hz,
                'idle_cpu_seconds_over_1s': (idle_end - idle_ticks) / hz}
    finally:
        stop.set()
        if watcher:
            watcher.join()
        core.terminate()
        try:
            core.wait(timeout=3)
        except subprocess.TimeoutExpired:
            core.kill()
            core.wait()
            raise AssertionError('core shutdown exceeded3seconds')
        log.close()


def main():
    if '--child' not in sys.argv:
        result = subprocess.run(['unshare', '-Urn', sys.executable, __file__, '--child'],
                                check=True, text=True, capture_output=True)
        target = ROOT / '.cache/direct-dhcp-validation/resources.json'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(result.stdout)
        print(result.stdout)
        return
    command('ip', 'link', 'set', 'lo', 'up')
    command('ip', 'link', 'add', 'dhcp0', 'type', 'dummy')
    command('ip', 'addr', 'add', '192.0.2.10/24', 'dev', 'dhcp0')
    command('ip', 'link', 'set', 'dhcp0', 'up')
    command('ip', 'route', 'add', 'default', 'dev', 'dhcp0')
    discovered = [0]

    def dhcp(query):
        assert len(query) >= 240 and query[0] == 1 and query[240:243] == b'5\x01\x01'
        discovered[0] += 1
        reply = bytearray(query[:240])
        reply[0] = 2
        return reply + bytes([53, 1, 2, 54, 4, 192, 0, 2, 10, 6, 4, 192, 0, 2, 10, 255])

    def dns(query):
        reply = bytearray(query)
        reply[2:4] = b'\x81\x80'
        reply[6:8] = b'\0\x01'
        return reply + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('203.0.113.42')

    close = []
    for port, address, respond in [(67, '0.0.0.0', dhcp), (53, '192.0.2.10', dns), (9000, '127.0.0.1', lambda b: b)]:
        conn = socket.socket(type=socket.SOCK_DGRAM)
        conn.bind((address, port))
        close.append(receiver(conn, respond))
    listener = socket.socket()
    listener.bind(('127.0.0.1', 9000))
    listener.listen()
    listener.settimeout(.1)
    ending = threading.Event()

    def echo():
        def flow(conn):
            with conn:
                while True:
                    data = conn.recv(65535)
                    if not data:
                        return
                    conn.sendall(data)
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            while not ending.is_set():
                try:
                    conn, _ = listener.accept()
                    pool.submit(flow, conn)
                except socket.timeout:
                    continue
    worker = threading.Thread(target=echo)
    worker.start()
    try:
        with tempfile.TemporaryDirectory() as directory:
            rows = [measure(Path(directory), mode) for mode in ['direct-tcp', 'direct-udp', 'dhcp-uncached', 'dhcp-cached']]
        assert discovered[0] == 2, discovered
        print(json.dumps({'binary_sha256': hashlib.sha256(BINARY.read_bytes()).hexdigest(),
                          'probe_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                          'scope': 'One native CLI core per scenario;fixture runs outside measured core;private Linux namespace',
                          'dhcp_discoveries': discovered[0], 'scenarios': rows}, indent=2))
    finally:
        ending.set()
        worker.join()
        listener.close()
        for fn in close:
            fn()


if __name__ == '__main__':
    main()
