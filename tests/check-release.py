#!/usr/bin/env python3
"""Run the published executable through real client/server proxy traffic."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

spec = importlib.util.spec_from_file_location('core_measure', Path(__file__).with_name('measure-core-performance.py'))
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)


def main():
    binary = Path(sys.argv[1]).resolve()
    digest, name = Path(str(binary)+'.sha256').read_text().split()
    assert name == binary.name and hashlib.sha256(binary.read_bytes()).hexdigest() == digest
    if os.name != 'nt':
        binary.chmod(binary.stat().st_mode | 0o111)
    with tempfile.TemporaryDirectory(prefix='lanboat-release-check-') as folder:
        work = Path(folder)
        version = subprocess.check_output([str(binary), 'version'], text=True)
        assert version.startswith('lanboat-allinone '), version
        protocols = json.loads(subprocess.check_output([str(binary), 'protocols'], text=True))
        assert any(p['type'] == 'shadowsocks' for p in protocols)
        for name in ('client', 'server'):
            config = Path(__file__).resolve().parents[1]/'examples'/('independent-'+name+'.json')
            subprocess.run([str(binary), 'check', '-c', str(config)], check=True)

        origin = core.Server(('127.0.0.1', 0), core.Echo)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        processes, logs = [], []
        try:
            ports = set()
            while len(ports) < 3:
                ports.add(core.unused_port())
            ss_port, socks_port, local_port = sorted(ports)
            ss = dict(type='shadowsocks', tag='ss', listen='127.0.0.1', listen_port=ss_port,
                      method='aes-256-gcm', password='local-release-fixture')
            server = dict(log=dict(disabled=True), inbounds=[ss, dict(type='socks', tag='socks', listen='127.0.0.1', listen_port=socks_port)])
            client = dict(log=dict(disabled=True), inbounds=[dict(type='mixed', tag='local', listen='127.0.0.1', listen_port=local_port)],
                          outbounds=[dict(type='shadowsocks', tag='proxy', server='127.0.0.1', server_port=ss_port, method=ss['method'], password=ss['password'])], route=dict(final='proxy'))
            for role, config, port in [('server', server, socks_port), ('client', client, local_port)]:
                path = work/(role+'.json')
                path.write_text(json.dumps(config))
                log = (work/(role+'.log')).open('w+')
                logs.append(log)
                process = subprocess.Popen([str(binary), role, '-c', str(path)], stdout=log, stderr=log, cwd=work)
                processes.append(process)
                for _ in range(500):
                    if process.poll() is not None:
                        raise RuntimeError(role+' exited during startup')
                    try:
                        socket.create_connection(('127.0.0.1', port), .02).close()
                        break
                    except OSError:
                        time.sleep(.02)
                else:
                    raise RuntimeError(role+' did not start listening')
            payload = b'lanboat release verification\n'*8192
            for port in (socks_port, local_port):
                with core.connect(port, origin.server_address[1]) as conn:
                    conn.sendall(payload)
                    assert core.receive(conn, len(payload)) == payload
            print('Release executable passed: version, config, multiple inbounds and client/server TCP transfer.')
        except BaseException:
            for log in logs:
                log.flush()
                log.seek(0)
                print(log.read())
            raise
        finally:
            for process in reversed(processes):
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for log in logs:
                log.close()
            origin.shutdown()
            origin.server_close()


if __name__ == '__main__':
    main()
