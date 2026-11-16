#!/usr/bin/env python3
"""Measure the independently implemented core with real client/server processes."""
import concurrent.futures
import base64
from contextlib import closing
import hashlib
import http.client
import http.server
import json
import os
import ssl
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'build/lanboat-allinone'
PAYLOAD = b'Lanboat independent runtime\n' * 2500


def port(reserve=None):
    for _ in range(32):
        tcp, udp = socket.socket(), socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        keep = False
        try:
            tcp.bind(('127.0.0.1', 0))
            value = tcp.getsockname()[1]
            try:
                udp.bind(('127.0.0.1', value))
            except OSError:
                continue
            if reserve is not None:
                reserve.extend((tcp, udp))
                keep = True
            return value
        finally:
            if not keep:
                tcp.close()
                udp.close()
    raise RuntimeError('no free TCP/UDP port pair')


def udp_bound(pid, port):
    sockets = set()
    for fd in Path(f'/proc/{pid}/fd').iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue
        if target.startswith('socket:['):
            sockets.add(target[8:-1])
    for name in ('udp', 'udp6'):
        for line in Path(f'/proc/{pid}/net/{name}').read_text().splitlines()[1:]:
            fields = line.split()
            if int(fields[1].rsplit(':', 1)[1], 16) == port and fields[9] in sockets:
                return True
    return False


def rss(pid):
    for line in Path(f'/proc/{pid}/status').read_text().splitlines():
        if line.startswith('VmRSS:'):
            return int(line.split()[1]) * 1024
    raise RuntimeError('process exited during RSS sampling')


def ticks(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return int(fields[11]) + int(fields[12])


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def log_message(self, *_):
        pass


def scenario(kind, origin, work):
    print(f"Measuring {kind}", file=sys.stderr, flush=True)
    reserved = []
    server_port, client_port = port(reserved), port(reserved)
    while server_port == client_port:
        client_port = port()
    transports = {'vmess-ws': ('vmess', 'ws'), 'vless-httpupgrade': ('vless', 'httpupgrade'), 'vless-h2': ('vless', 'http'), 'vless-h2-mtls': ('vless', 'http'), 'vmess-grpc': ('vmess', 'grpc'), 'vless-ws-early-path': ('vless','ws'), 'vless-ws-early-header': ('vless','ws'), 'trojan-ws-early-small': ('trojan','ws')}
    transports.update({'vless-h2-keepalive': ('vless', 'http'), 'vmess-grpc-keepalive': ('vmess', 'grpc'), 'vmess-grpc-keepalive-idle': ('vmess', 'grpc')})
    transports.update({kind: (kind.removesuffix('-quic'), 'quic') for kind in ('vmess-quic', 'vless-quic', 'trojan-quic', 'relay-quic')})
    transports.update({name:(name.split('-')[0],'xhttp') for name in ('vless-xhttp-packet','vless-xhttp-stream-up','vless-xhttp-stream-one','vless-xhttp-h3','vmess-xhttp','trojan-xhttp','relay-xhttp','shadowsocks-xhttp')})
    transports.update({name:(name.split('-')[0],None) for name in ('vless-shadowtls-3','vmess-shadowtls-3','relay-shadowtls-3')})
    transports.update({'vmess-mux': ('vmess', None), 'vmess-mux-ws': ('vmess', 'ws'), 'vless-mux': ('vless', None), 'vless-mux-h2': ('vless', 'http')})
    transports.update({'trojan-fragment': ('trojan', None), 'vless-h2-fragment': ('vless', 'http'), 'vmess-grpc-fragment': ('vmess', 'grpc'), 'anytls-fragment': ('anytls', None), 'trojan-fragment-combined': ('trojan', None)})
    transports.update({'trojan-record-fragment': ('trojan', None), 'vless-h2-record-fragment': ('vless', 'http'), 'vmess-grpc-record-fragment': ('vmess', 'grpc'), 'anytls-record-fragment': ('anytls', None)})
    transports.update({name:(name.split('-')[0],'mkcp') for name in ('vmess-mkcp','vless-mkcp','trojan-mkcp','relay-mkcp','shadowsocks-mkcp','vless-mkcp-seed','vless-mkcp-dns','vless-mkcp-raw')})
    transports.update({'vless-reality':('vless',None),'vless-reality-vision':('vless',None),'vless-reality-fragment':('vless',None),'vless-reality-h2':('vless','http'),'vmess-reality-grpc':('vmess','grpc'),'vless-reality-xhttp':('vless','xhttp'),'vless-reality-mldsa':('vless',None),'vless-reality-mldsa-vision':('vless',None),'vmess-reality-mldsa-grpc':('vmess','grpc')})
    protocol, transport = transports.get(kind, (kind, None))
    if kind.startswith('vless-vision-'): protocol='vless'
    if kind.startswith('hysteria-faketcp'): protocol='hysteria'
    if kind in ('hysteria-hop','hysteria2-hop'): protocol=kind.removesuffix('-hop')
    if kind in ('hysteria-wechat','hysteria-wechat-xplus','hysteria-wechat-hop'): protocol='hysteria'
    if kind.endswith(('-cubic', '-reno', '-bbr')):
        protocol = kind.rsplit('-', 1)[0]
        if protocol == 'tuic4': protocol = 'tuic'
    if kind.startswith('shadowsocks-obfs-') or kind.startswith('shadowsocks-v2ray-') or kind.startswith('shadowsocks-gost-') or kind.startswith('shadowsocks-shadowtls-') or kind.startswith('shadowsocks-kcptun-') or kind.startswith('shadowsocks-cloak-'):
        protocol = 'shadowsocks'
    elif kind.startswith('ssr-'):
        protocol = 'shadowsocksr'
    elif kind.startswith('brook-'):
        protocol = 'brook'
    elif kind.startswith('mieru-'):
        protocol='mieru'
    elif kind.startswith('masque-'):
        protocol='masque'
    elif kind.startswith('naive-'):
        protocol = 'naive'
    elif kind.startswith('openconnect-'):
        protocol = 'openconnect'
    elif kind.startswith('trusttunnel-'):
        protocol = 'trusttunnel'
    elif kind.startswith('ss2022-'):
        protocol = 'shadowsocks'
    elif kind.startswith('ss-'):
        protocol = 'shadowsocks'
    elif kind.startswith('trojan-ss-'):
        protocol = 'trojan'
    elif kind.startswith('trojan-mux'):
        protocol = 'trojan'
    elif kind == 'relay-bind':
        protocol = 'relay'
    elif kind.startswith('vmess-length-') or kind == 'vmess-legacy':
        protocol = 'vmess'
    elif kind.startswith('wireguard-amnezia-') or kind == 'wireguard-wgobfs':
        protocol = 'wireguard'
    elif kind in ('hysteria2-salamander', 'hysteria2-mtls', 'hysteria2-brutal', 'hysteria2-brutal-no-compensation', 'hysteria2-ignore-bandwidth', 'hysteria2-gecko'):
        protocol = 'hysteria2'
    elif kind.endswith('-ech') or kind.endswith('-ech-dns'):
        protocol = kind.split('-')[0]
    elif kind.endswith('-pkcs12'):
        protocol = kind.removesuffix('-pkcs12')
    elif kind == 'trojan-mtls':
        protocol = 'trojan'
    elif kind in ('tuic-quic','tuic4','tuic4-quic'):
        protocol = 'tuic'
    elif kind.startswith('snell-'):
        protocol = 'snell'
    elif kind == 'route-dns-srs':
        protocol = 'socks'
    elif kind.startswith('route-dns-'):
        protocol = 'socks'
    elif kind == 'ssh-ecdsa-encrypted':
        protocol = 'ssh'
    elif kind.startswith('sudoku-'):
        protocol = 'sudoku'
    inbound = dict(type=protocol, tag='server', listen='127.0.0.1', listen_port=server_port)
    outbound = dict(type=protocol, tag='proxy', server='127.0.0.1', server_port=server_port)
    if kind in ('hysteria-hop','hysteria2-hop','hysteria-wechat-hop'):
        outbound.pop('server_port')
        outbound.update(server_ports=[f'{server_port}:{server_port}'],hop_interval='1s')
    if kind.endswith(('-cubic', '-reno', '-bbr')):
        inbound['congestion_control'] = outbound['congestion_control'] = 'new_reno' if kind.endswith('-reno') else kind.rsplit('-',1)[1]
    if kind in ('hysteria2-brutal', 'hysteria2-brutal-no-compensation', 'hysteria2-ignore-bandwidth'):
        outbound.update(up_mbps=100, down_mbps=100)
        if kind == 'hysteria2-ignore-bandwidth':
            inbound['ignore_client_bandwidth'] = True
        else:
            inbound.update(up_mbps=100, down_mbps=100)
        if kind == 'hysteria2-brutal-no-compensation':
            inbound['disable_loss_compensation'] = outbound['disable_loss_compensation'] = True
    if kind.startswith('hysteria-faketcp'):
        inbound['protocol'] = outbound['protocol'] = 'faketcp'
        if kind.endswith('-xplus'): inbound['obfs'] = outbound['obfs'] = 'faketcp-resource-mask'
    if kind.startswith('hysteria-wechat'):
        inbound['protocol'] = outbound['protocol'] = 'wechat-video'
        if kind != 'hysteria-wechat': inbound['obfs'] = outbound['obfs'] = 'wechat-resource-mask'
    if kind.startswith('shadowsocks-kcptun-'):
        version=2 if '-v2' in kind else 1
        options=f'key=resource-transport-password;version={version};nocomp={str(not kind.endswith("compressed")).lower()};crypt={"aes-256-gcm" if kind.endswith("aead") else "aes"}'
        inbound.update(plugin='kcptun',plugin_opts=options)
        outbound.update(plugin='kcptun',plugin_opts=options)
    if kind.startswith('shadowsocks-cloak-'):
        identity=json.loads(subprocess.check_output([str(BINARY),'generate','cloak-keypair']))
        mode=kind.removeprefix('shadowsocks-cloak-')
        cloak_transport=mode if mode in ('cdn','websocket') else 'direct'
        method={'aes-gcm':'aes-gcm','aes128':'aes-128-gcm','plain':'plain'}.get(mode,'chacha20-poly1305')
        common=f'UID={identity["uid"]};ProxyMethod=shadowsocks;Transport={cloak_transport};EncryptionMethod={method};ServerName=localhost;NumConn=4'
        inbound.update(plugin='cloak',plugin_opts=common+';PrivateKey='+identity['private_key'])
        outbound.update(plugin='cloak',plugin_opts=common+';PublicKey='+identity['public_key'])
        if cloak_transport!='direct':
            inbound['tls']=dict(enabled=True,certificate_path=str(work/'cert.pem'),key_path=str(work/'key.pem'))
            outbound['tls']=dict(enabled=True,server_name='localhost',certificate_path=str(work/'cert.pem'))
    password = 'local-resource-test-not-a-production-password'
    if protocol in ('socks', 'http', 'relay'):
        inbound['users'] = [dict(username='client', password=password)]
        outbound.update(username='client', password=password)
        if kind == 'relay-bind':
            inbound['bind'] = True
    elif protocol == 'sudoku':
        options = dict(key=password, aead='chacha20-poly1305', padding_min=5, padding_max=15, enable_pure_downlink=True)
        if kind == 'sudoku-plain': options['aead'] = 'none'
        if kind == 'sudoku-aes': options['aead'] = 'aes-128-gcm'
        if kind == 'sudoku-packed': options['enable_pure_downlink'] = False
        if kind == 'sudoku-ascii': options['ascii'] = 'prefer_ascii'
        if kind == 'sudoku-custom': options.update(ascii='up_ascii_down_entropy',custom_table='xpxvvpvv')
        if kind in ('sudoku-mux', 'sudoku-mux-packed'):
            outbound['multiplex'] = dict(enabled=True)
            if kind == 'sudoku-mux-packed': options['enable_pure_downlink'] = False
        if kind.startswith('sudoku-mask-'):
            mode = kind.removeprefix('sudoku-mask-').split('-')[0]
            options['httpmask'] = dict(mode=mode,host='localhost',path_root='assets')
            options['enable_pure_downlink'] = mode != 'ws'
            if kind.endswith('-mux'): outbound['multiplex'] = dict(enabled=True)
            if kind.endswith('-tls'):
                inbound['tls'] = dict(enabled=True,certificate_path=str(work/'cert.pem'),key_path=str(work/'key.pem'))
                outbound['tls'] = dict(enabled=True,server_name='localhost',certificate_path=str(work/'cert.pem'))
        if kind.startswith('sudoku-tables'):
            options.update(custom_tables=['xpxvvpvv','ppxvvxvv','vvpxxvvp'],ascii='up_ascii_down_entropy',enable_pure_downlink=False)
            if kind.endswith('-mux'): outbound['multiplex'] = dict(enabled=True)
            if '-ws' in kind: options['httpmask'] = dict(mode='ws',path_root='assets')
            if '-poll' in kind: options['httpmask'] = dict(mode='poll',path_root='assets')
            if '-auto' in kind: options['httpmask'] = dict(mode='auto',path_root='assets')
        inbound['sudoku'] = outbound['sudoku'] = options
        if kind.startswith('sudoku-private-'):
            mode = kind.removeprefix('sudoku-private-').split('-')[0]
            options.update(key='6e5c05c3f7f5d45fcd2f6a5a7f4700f94ff51db376c128c581849feb71ccc58b',
                           custom_tables=['xpxvvpvv','ppxvvxvv','vvpxxvvp'],ascii='up_ascii_down_entropy',enable_pure_downlink=False)
            if mode != 'raw': options['httpmask'] = dict(mode=mode,path_root='assets')
            outbound['sudoku'] = dict(options)
            outbound['sudoku'].pop('key')
            outbound['sudoku']['private_key'] = ('709aab5f030c9b8c322811d5c6545497c2136ce1e43b574e231562303de8f108' if kind.endswith('-master') else
                'b1ec294d5dba60a800e1ef8c3423d5a176093f0d8c432e01bc24895d6828140aac81776fc0b44c3c08e418eb702b5e0a4c0a2dd458f8284d67f0d8d2d4bfdd0e')
            if kind.endswith('-mux'): outbound['multiplex'] = dict(enabled=True)
            if kind.endswith('-tls'):
                inbound['tls'] = dict(enabled=True,certificate_path=str(work/'cert.pem'),key_path=str(work/'key.pem'))
                outbound['tls'] = dict(enabled=True,server_name='localhost',certificate_path=str(work/'cert.pem'))
        if kind.startswith('sudoku-reverse-'):
            mode = kind.removeprefix('sudoku-reverse-').split('-')[0]
            options.update(key='6e5c05c3f7f5d45fcd2f6a5a7f4700f94ff51db376c128c581849feb71ccc58b',
                           custom_tables=['xpxvvpvv','ppxvvxvv','vvpxxvvp'],ascii='up_ascii_down_entropy',enable_pure_downlink=False,
                           reverse=dict(listen=f'127.0.0.1:{client_port}'))
            if mode != 'raw': options['httpmask'] = dict(mode=mode,path_root='assets')
            outbound['sudoku'] = dict(options)
            outbound['sudoku'].pop('key')
            outbound['sudoku'].update(private_key='b1ec294d5dba60a800e1ef8c3423d5a176093f0d8c432e01bc24895d6828140aac81776fc0b44c3c08e418eb702b5e0a4c0a2dd458f8284d67f0d8d2d4bfdd0e',
                                     reverse=dict(routes=[dict(path='/app' if '-http' in kind else '',target=f'127.0.0.1:{origin.server_port}')]))
            if kind.endswith('-tls'):
                inbound['tls'] = dict(enabled=True,certificate_path=str(work/'cert.pem'),key_path=str(work/'key.pem'))
                outbound['tls'] = dict(enabled=True,server_name='localhost',certificate_path=str(work/'cert.pem'))
    elif protocol == 'mieru':
        inbound['users']=[dict(username='client',password=password)]
        inbound['network']=outbound['network']=kind.split('-')[1]
        outbound.update(username='client',password=password,user_hint=True)
        if kind.endswith('-pattern'):
            # Published protobuf: fragment/nonce/padding/low-entropy shaping.
            pattern='GgQIARABIggIARABGAYgCCoFCEAQgAEyBAgBEHA='
            inbound['traffic_pattern']=outbound['traffic_pattern']=pattern
    elif protocol == 'openconnect':
        inbound['disable_dtls'] = outbound['disable_dtls'] = kind not in ('openconnect-dtls','openconnect-dns-dtls')
        inbound['users'] = [dict(username='client',password=password)]
        inbound['tls'] = dict(enabled=True,certificate_path=str(work/'cert.pem'),key_path=str(work/'key.pem'))
        outbound.update(username='client',password=password,tls=dict(enabled=True,insecure=True))
        if kind == 'openconnect-interactive':
            outbound.pop('username');outbound.pop('password')
    elif protocol == 'masque':
        if kind.startswith('masque-dns-'):
            inbound['http_version'] = outbound['http_version'] = int(kind.rsplit('-',1)[1])
            outbound.update(masque_accept_dns=True,masque_accept_pref64=True)
        inbound['users']=[dict(username='client',password=password)]
        inbound['tls']=dict(enabled=True,certificate_path=str(work/'cert.pem'),key_path=str(work/'key.pem'))
        outbound.update(username='client',password=password,masque_mode='ip' if kind.startswith(('masque-endpoint-','masque-dns-','masque-reverse-')) else kind.rsplit('-',1)[1],tls=dict(enabled=True,insecure=True))
        if kind.startswith(('masque-h1-','masque-h2-')):
            inbound['http_version']=outbound['http_version']=int(kind.split('-')[1][1:])
        if kind.startswith('masque-cleartext-'):
            inbound['http_version']=outbound['http_version']=int(kind.split('-')[2][1:])
            inbound.pop('tls');outbound.pop('tls')
    elif protocol == 'naive':
        inbound['users'] = [dict(username='client', password=password)]
        inbound['tls'] = dict(enabled=True, certificate_path=str(work/'cert.pem'), key_path=str(work/'key.pem'))
        outbound.update(username='client', password=password, quic=kind.endswith('h3'), tls=dict(enabled=True, server_name='localhost', insecure=True))
    elif protocol == 'trusttunnel':
        inbound['users'] = [dict(username='client', password=password)]
        inbound['http_version'] = outbound['http_version'] = 3 if kind.endswith('h3') else 2
        inbound['tls'] = dict(enabled=True, certificate_path=str(work/'cert.pem'), key_path=str(work/'key.pem'))
        outbound.update(username='client', password=password, tls=dict(enabled=True, server_name='localhost', insecure=True))
    elif protocol == 'brook':
        inbound['password'] = outbound['password'] = password
        if kind in ('brook-ws', 'brook-wss','brook-simple-ws','brook-simple-wss'):
            inbound['transport'] = outbound['transport'] = dict(type='ws', path='/brook')
        if kind in ('brook-quic','brook-simple-quic'):
            transport = 'quic'
            inbound['transport'] = outbound['transport'] = dict(type='quic')
        if kind.startswith('brook-simple-'):
            inbound['without_brook_protocol']=outbound['without_brook_protocol']=True
        if kind in ('brook-wss', 'brook-quic','brook-simple-wss','brook-simple-quic'):
            inbound['tls'] = dict(enabled=True, certificate_path=str(work/'cert.pem'), key_path=str(work/'key.pem'))
            outbound['tls'] = dict(enabled=True, insecure=True)
    elif protocol == 'shadowsocks':
        method = 'aes-256-gcm'
        if kind.startswith('ss-'):
            method = kind.removeprefix('ss-')
            if method.endswith('-ota'):
                method = method.removesuffix('-ota')
                inbound['ota'] = outbound['ota'] = True
        if kind.startswith('ss2022-'):
            method = '2022-blake3-' + kind.removeprefix('ss2022-').removesuffix('-multi')
            size = 16 if method == '2022-blake3-aes-128-gcm' else 32
            password = base64.b64encode(bytes([7])*size).decode()
        if kind == 'shadowsocks-v2ray-hysteria2-2022':
            method = '2022-blake3-aes-128-gcm'
            password = base64.b64encode(bytes([7])*16).decode()
        inbound.update(method=method, password=password)
        outbound.update(method=method, password=password)
        if kind.startswith('shadowsocks-obfs-'):
            options = 'obfs=' + kind.removeprefix('shadowsocks-obfs-') + ';obfs-host=cdn.example'
            inbound.update(plugin='obfs-local', plugin_opts=options)
            outbound.update(plugin='obfs-local', plugin_opts=options)
        if kind in ('shadowsocks-v2ray-ws', 'shadowsocks-v2ray-wss', 'shadowsocks-v2ray-ws-mux8'):
            options = 'mode=websocket;host=localhost;path=/plugin;mux=' + ('8' if kind.endswith('mux8') else '1')
            inbound.update(plugin='v2ray-plugin', plugin_opts='server;' + options)
            outbound.update(plugin='v2ray-plugin', plugin_opts=options)
            if kind.endswith('wss'):
                inbound['tls'] = dict(enabled=True, certificate_path=str(work/'cert.pem'), key_path=str(work/'key.pem'))
                outbound['tls'] = dict(enabled=True, insecure=True)
        if kind.startswith('shadowsocks-gost-'):
            mode = kind.removeprefix('shadowsocks-gost-')
            options = 'mode=' + mode + (';path=/plugin;host=localhost' if 'ws' in mode else '')
            inbound.update(plugin='gost', plugin_opts=options)
            outbound.update(plugin='gost', plugin_opts=options)
            if mode in ('tls','mtls','wss','mwss'):
                inbound['tls'] = dict(enabled=True, certificate_path=str(work/'cert.pem'), key_path=str(work/'key.pem'))
                outbound['tls'] = dict(enabled=True, insecure=True)
        if kind == 'shadowsocks-v2ray-quic':
            inbound.update(plugin='v2ray-plugin', plugin_opts=f'server;mode=quic;host=localhost;cert={work / "cert.pem"};key={work / "key.pem"}')
            outbound.update(plugin='v2ray-plugin', plugin_opts='mode=quic;host=localhost', tls=dict(enabled=True, insecure=True))
        if kind.startswith('shadowsocks-v2ray-hysteria2'):
            options = 'mode=hysteria2;host=localhost'
            if not kind.endswith('-open'):
                options += ';password=transport-secret'
            inbound.update(plugin='v2ray-plugin', plugin_opts=f'server;{options};cert={work / "cert.pem"};key={work / "key.pem"}')
            outbound.update(plugin='v2ray-plugin', plugin_opts=f'{options};cert={work / "cert.pem"}')
        if kind.endswith('-multi'):
            user = base64.b64encode(bytes([11])*size).decode()
            inbound['users'] = [dict(name='client', password=user)]
            outbound['password'] += ':' + user
    elif protocol in ('trojan', 'anytls', 'hysteria', 'hysteria2', 'tuic', 'juicity'):
        inbound['users'] = [dict(password=password)]
        inbound['tls'] = dict(enabled=True, certificate_path=str(work/'cert.pem'), key_path=str(work/'key.pem'))
        outbound.update(password=password, tls=dict(enabled=True, insecure=True))
        if kind.startswith('trojan-ss-'):
            inner = 'aes-128-gcm' if kind.endswith('aes128') else 'chacha20-ietf-poly1305' if kind.endswith('chacha') else 'aes-256-gcm'
            inbound['shadowsocks'] = outbound['shadowsocks'] = dict(enabled=True, method=inner, password='inner-resource-test-password')
            if kind.endswith('-ws'):
                inbound['transport'] = outbound['transport'] = dict(type='ws', path='/encrypted')
        if kind.startswith('trojan-mux'):
            outbound['multiplex'] = dict(enabled=True,protocol='trojan-go')
            if kind.endswith('-ws'):
                inbound['transport'] = outbound['transport'] = dict(type='ws', path='/mux')
            if kind.endswith('-ss'):
                inbound['shadowsocks'] = outbound['shadowsocks'] = dict(enabled=True, method='aes-128-gcm', password='inner-resource-test-password')
        if protocol in ('tuic', 'juicity'):
            inbound['users'][0]['uuid'] = '2b2d59c9-a4e1-4efa-a694-12b6f063093c'
            outbound['uuid'] = inbound['users'][0]['uuid']
            if kind.startswith('tuic4'):
                inbound['version'] = outbound['version'] = '4'
                inbound['users'] = [dict(token=password)]
                outbound.pop('uuid'); outbound.pop('password'); outbound['token'] = password
            if kind in ('tuic-quic','tuic4-quic'):
                outbound['udp_relay_mode'] = 'quic'
        if kind == 'hysteria2-salamander':
            inbound['obfs'] = outbound['obfs'] = dict(type='salamander', password='resource-measurement-mask')
        if kind == 'hysteria2-gecko':
            inbound['obfs'] = outbound['obfs'] = dict(type='gecko', password='resource-measurement-mask')
            outbound.update(up_mbps=100, down_mbps=100)
    elif protocol == 'ssh':
        inbound['private_key_path'] = str(work/'ssh_key')
        inbound['users'] = [dict(username='client', password=password)]
        outbound.update(username='client', password=password, host_key=[(work/'ssh_key.pub').read_text().strip()])
        if kind == 'ssh-ecdsa-encrypted':
            inbound.update(private_key_path=str(work/'ssh_ecdsa'), private_key_passphrase='measurement-passphrase')
            outbound['host_key'] = [(work/'ssh_ecdsa.pub').read_text().strip()]
    elif protocol == 'wireguard':
        server_key = subprocess.check_output(['wg','genkey']).decode().strip()
        client_key = subprocess.check_output(['wg','genkey']).decode().strip()
        server_pub = subprocess.check_output(['wg','pubkey'], input=(server_key+'\n').encode()).decode().strip()
        client_pub = subprocess.check_output(['wg','pubkey'], input=(client_key+'\n').encode()).decode().strip()
        inbound.update(private_key=server_key, peers=[dict(public_key=client_pub, allowed_ips=['10.29.0.2/32'])])
        outbound.update(private_key=client_key, peer_public_key=server_pub, local_address=['10.29.0.2/32'])
        if kind.startswith('wireguard-amnezia-'):
            obfs=dict(jc=3,jmin=16,jmax=48,s1=31,s2=17,h1='1010',h2='2030',h3='3050',h4='4070')
            if kind.endswith(('-v2','-v3')):
                obfs.update(s3=9,s4=13,h1='1010-1020',h2='2030-2040',h3='3050-3060',h4='4070-4080',i1='<b 0xff010203><rc 8><t><r 7>',i3='<b 0xab010203>')
            if kind.endswith('-v3'):
                obfs.update(s3=19,s4=23,header_protection_key='R0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0c=',content_padding_addition='32-96',random_trailers=True,rekey_after_time='90-120',rekey_timeout='3-5',reject_after_time='180-240',keepalive_timeout='10-15',max_handshake_attempts='5-8',persistent_keepalive_interval='20-30')
            inbound['amnezia']=outbound['amnezia']=obfs
        elif kind == 'wireguard-wgobfs':
            inbound['wgobfs']=outbound['wgobfs']=dict(password='resource-mask-password')
    elif protocol in ('vless', 'vmess'):
        if kind.startswith('vmess-length-'):
            outbound.update(authenticated_length=True, global_padding=kind.endswith('-padding'), security='chacha20-poly1305' if kind.endswith('-chacha') else 'aes-128-gcm')
        if '-mux' in kind: outbound['multiplex'] = dict(enabled=True,protocol='mux.cool')
        identity = '2b2d59c9-a4e1-4efa-a694-12b6f063093c'
        inbound['users'] = [dict(uuid=identity)]
        outbound['uuid'] = identity
        if kind == 'vmess-legacy':
            inbound['users'][0]['alterId'] = 1
            outbound['alter_id'] = 1
    elif protocol == 'shadowsocksr':
        auth = 'auth_chain_a' if kind == 'ssr-chain-a' else 'auth_aes128_sha1'
        obfs = 'tls1.2_ticket_auth' if kind == 'ssr-tls' else 'plain'
        inbound.update(method='aes-256-cfb', password=password, protocol=auth, obfs=obfs)
        outbound.update(method='aes-256-cfb', password=password, protocol=auth, obfs=obfs)
    elif protocol == 'snell':
        inbound.update(password=password, version=kind.split('-')[1])
        outbound.update(password=password, version=kind.split('-')[1])
        if kind.endswith('-mux'):
            outbound['multiplex'] = dict(enabled=True)
        if kind.endswith('-http'):
            inbound['obfs'] = outbound['obfs'] = dict(type='http', host='example.com', path='/')
    if transport:
        inbound['transport'] = outbound['transport'] = dict(type=transport)
        if transport == 'grpc':
            inbound['transport']['service_name'] = 'lanboat'
        elif transport not in ('quic','mkcp'):
            inbound['transport']['path'] = '/proxy'
        if '-ws-early-' in kind:
            inbound['transport']['max_early_data'] = 8 if kind.endswith('-small') else 2048
            if kind.endswith('-header'):
                inbound['transport']['early_data_header_name'] = 'Sec-WebSocket-Protocol'
        if transport in ('http', 'grpc', 'quic'):
            inbound['tls'] = dict(enabled=True, certificate_path=str(work/'cert.pem'), key_path=str(work/'key.pem'))
            outbound['tls'] = dict(enabled=True, insecure=True)
        if '-keepalive' in kind:
            inbound['transport'] = dict(inbound['transport'], idle_timeout='30s')
            outbound['transport'] = dict(outbound['transport'], idle_timeout='200ms', ping_timeout='2s')
            if transport == 'grpc':
                outbound['transport']['permit_without_stream'] = kind.endswith('-idle')
    if transport == 'mkcp':
        options=dict(congestion=True)
        if kind.endswith(('-seed','-dns')): options['seed']='resource-test'
        if kind.endswith('-dns'): options['header']=dict(type='dns',domain='www.example.com')
        if kind.endswith('-raw'): options['packet_encoding']='raw'
        inbound['transport']['kcp']=outbound['transport']['kcp']=options
    if transport == 'xhttp':
        mode = 'packet-up' if kind.endswith(('-packet','-h3')) else 'stream-up' if kind.endswith('-stream-up') else 'stream-one'
        inbound['transport'].update(mode=mode)
        if not kind.endswith('-packet'):
            inbound['tls'] = dict(enabled=True,certificate_path=str(work/'cert.pem'),key_path=str(work/'key.pem'))
            outbound['tls'] = dict(enabled=True,insecure=True)
        if kind.endswith('-h3'):
            inbound['tls']['alpn'] = outbound['tls']['alpn'] = ['h3']
    if kind.endswith('-record-fragment'):
        outbound.setdefault('tls',dict(enabled=True,insecure=True))['record_fragment'] = True
    if kind.endswith('-fragment') or kind == 'trojan-fragment-combined':
        if not kind.endswith('-record-fragment'):
            outbound.setdefault('tls',dict(enabled=True,insecure=True)).update(fragment=True,fragment_fallback_delay='1ms')
            if kind.endswith('-combined'): outbound['tls']['record_fragment'] = True
    if kind.endswith('-mtls'):
        def pin(path):
            return base64.b64encode(hashlib.sha256(ssl.PEM_cert_to_DER_cert(path.read_text())).digest()).decode()
        inbound['tls'].update(client_authentication='require-and-verify', client_certificate_sha256=[pin(work/'client-cert.pem')])
        outbound['tls'].update(insecure=False, certificate_sha256=[pin(work/'cert.pem')], client_certificate_path=str(work/'client-cert.pem'), client_key_path=str(work/'client-key.pem'))
    if kind.endswith('-pkcs12'):
        def pin(path):
            return base64.b64encode(hashlib.sha256(ssl.PEM_cert_to_DER_cert(path.read_text())).digest()).decode()
        inbound['tls'] = dict(enabled=True,pkcs12_path=str(work/'server.p12'),pkcs12_password='measurement-p12',client_authentication='require-and-verify',client_certificate_sha256=[pin(work/'client-cert.pem')])
        outbound['tls'] = dict(enabled=True,certificate_sha256=[pin(work/'cert.pem')],pkcs12_path=str(work/'client.p12'),pkcs12_password='measurement-p12')
    if kind.endswith('-ech') or kind.endswith('-ech-dns'):
        outbound['tls']['server_name']='localhost'
        inbound['tls'].update(ech=dict(enabled=True,key_path=str(work/'ech-keys.pem')))
        outbound['tls'].update(ech=dict(enabled=True,config_path=str(work/'ech-configs.pem')))
    configs = [
        dict(log=dict(disabled=True), inbounds=[inbound], outbounds=[dict(type='direct', tag='direct')]),
        dict(log=dict(disabled=True), inbounds=[dict(type='mixed', tag='local', listen='127.0.0.1', listen_port=client_port)], outbounds=[outbound], route=dict(final='proxy')),
    ]
    if kind.startswith('sudoku-reverse-'):
        configs[1]['inbounds'] = []
    if kind.startswith('masque-endpoint-'):
        version = 1 if kind.endswith('fallback') else int(kind.rsplit('-',1)[1])
        inbound.update(type='masque-server',version=[1,2,3] if version==3 else [version],address=['10.44.0.1/24','fd44::1/64'],path='/vpn/{target}/{ipproto}/')
        inbound.pop('http_version',None)
        outbound.pop('masque_mode')
        outbound.update(type='masque-client',version=3 if kind.endswith('fallback') else version,path='/vpn/{target}/{ipproto}/',headers={'X-Application':'lanboat'})
        if '-tuned-' in kind:
            for endpoint in (inbound, outbound):
                endpoint.update(idle_timeout='1m',keep_alive_period='15s',stream_receive_window='2MB',connection_receive_window='4MB',max_concurrent_streams=32)
        if '-pmtu-' in kind:
            for endpoint in (inbound, outbound):
                endpoint.update(initial_packet_size=1200,disable_path_mtu_discovery='-disabled-' in kind)
        if '-scoped-' in kind:
            inbound['path']='/vpn{?target,ipproto}'
            inbound['advertise_routes']=['127.0.0.1/32']
            outbound['path']='/vpn?target=127.0.0.0%2F8&ipproto=6'
        configs[0]['inbounds']=[]
        configs[0]['endpoints']=[inbound]
        configs[1]['outbounds']=[]
        configs[1]['endpoints']=[outbound]
    if kind.startswith('masque-reverse-'):
        version = int(kind.rsplit('-',1)[1])
        inbound.update(type='masque-server',version=[version],address=['10.44.0.1/24','fd44::1/64'])
        outbound.pop('masque_mode')
        outbound.update(type='masque-client',version=version,disable_version_fallback=True,advertise_routes=['127.0.0.1/32'])
        configs[0].update(inbounds=configs[1]['inbounds'],endpoints=[inbound],route=dict(final='server',rules=[dict(inbound=['server'],outbound='direct')]))
        configs[1].update(inbounds=[],outbounds=[dict(type='direct',tag='direct')],endpoints=[outbound],route=dict(final='direct'))
    if kind.startswith('vless-vision-'):
        inbound['users'][0]['flow']='xtls-rprx-vision'
        inbound['tls']=dict(enabled=True,certificate_path=str(work/'cert.pem'),key_path=str(work/'key.pem'))
        outbound.update(flow='xtls-rprx-vision',tls=dict(enabled=True,insecure=True))
    cover = None
    if '-reality' in kind:
        cover = CoverServer(('127.0.0.1',0),Origin)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(work/('cover-large.pem' if '-mldsa' in kind else 'cert.pem'),work/'key.pem')
        context.set_alpn_protocols(['h2','http/1.1'])
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        cover.tls_context = context
        threading.Thread(target=cover.serve_forever,daemon=True).start()
        keys=json.loads(subprocess.check_output([str(BINARY),'generate','reality-keypair'],text=True))
        inbound['tls']=dict(enabled=True,server_name='localhost',reality=dict(enabled=True,private_key=keys['private_key'],short_id=['0123456789abcdef'],handshake=dict(server='127.0.0.1',server_port=cover.server_port),max_time_difference='1m'))
        outbound['tls']=dict(enabled=True,server_name='localhost',reality=dict(enabled=True,public_key=keys['public_key'],short_id='0123456789abcdef'))
        if '-mldsa' in kind:
            pq=json.loads(subprocess.check_output([str(BINARY),'generate','reality-mldsa65-keypair'],text=True))
            inbound['tls']['reality']['mldsa65_seed']=pq['mldsa65_seed']
            outbound['tls']['reality']['mldsa65_verify']=pq['mldsa65_verify']
        if kind.endswith('-vision'):
            inbound['users'][0]['flow']='xtls-rprx-vision'
            outbound['flow']='xtls-rprx-vision'
        if kind.endswith('-fragment'):
            outbound['tls'].update(fragment=True,record_fragment=True,fragment_fallback_delay='1ms')
    if '-shadowtls-' in kind:
        version = int(kind.rsplit('-',1)[1])
        cover = CoverServer(('127.0.0.1',0),Origin)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(work/'cert.pem',work/'key.pem')
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2 if version == 1 else ssl.TLSVersion.TLSv1_3
        cover.tls_context = context
        threading.Thread(target=cover.serve_forever,daemon=True).start()
        if protocol == 'shadowsocks':
            options = f'version={version}' + (';password=outer-resource-password' if version > 1 else '')
            inbound.update(plugin='shadow-tls',plugin_opts=options+f';handshake=127.0.0.1:{cover.server_port}')
            outbound.update(plugin='shadow-tls',plugin_opts=options+';host=localhost;skip-cert-verify=true')
        else:
            outer_in = dict(type='shadowtls',tag='outer',listen='127.0.0.1',listen_port=server_port,version=version,detour='server',handshake=dict(server='127.0.0.1',server_port=cover.server_port),strict_mode=version==3)
            if version==2: outer_in['password']='outer-resource-password'
            if version==3: outer_in['users']=[dict(name='client',password='outer-resource-password')]
            inbound['listen_port']=0
            configs[0]['inbounds'].append(outer_in)
            outer_out=dict(type='shadowtls',tag='outer',server='127.0.0.1',server_port=server_port,version=version,tls=dict(enabled=True,insecure=True,server_name='localhost'))
            if version>1:outer_out['password']='outer-resource-password'
            outbound['detour']='outer'
            configs[1]['outbounds'].append(outer_out)
    if kind == 'relay-bind':
        configs[1]['inbounds'] = []
    inner_version = ssl.TLSVersion.TLSv1_3 if kind in ('vless-vision-tls13','vless-reality-vision','vless-reality-mldsa-vision') else ssl.TLSVersion.TLSv1_2 if kind=='vless-vision-tls12' else None
    inner_context = None
    if inner_version is not None:
        cover = OriginServer(('127.0.0.1',0),Origin)
        server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(work/'cert.pem',work/'key.pem')
        server_context.minimum_version=server_context.maximum_version=inner_version
        cover.socket=server_context.wrap_socket(cover.socket,server_side=True)
        threading.Thread(target=cover.serve_forever,daemon=True).start()
        origin=cover
        inner_context=ssl._create_unverified_context()
        inner_context.minimum_version=inner_context.maximum_version=inner_version
    origin_host = '127.0.0.1'
    if kind.endswith('-ech-dns'):
        pem=(work/'ech-configs.pem').read_text().split('-----')[2]
        ech=base64.b64encode(base64.b64decode(pem)).decode()
        outbound['tls']['ech']=dict(enabled=True,query_server_name='ech.lanboat.test')
        configs[1]['dns']=dict(rules=[dict(domain='ech.lanboat.test',action='predefined',answer='ech.lanboat.test. 60 IN HTTPS 1 . ech='+ech)])
    if kind == 'route-dns-srs':
        origin_host = 'origin.lanboat.test'
        configs[1]['dns'] = dict(servers=[dict(type='hosts', tag='hosts', predefined={origin_host: ['127.0.0.1']})])
        configs[0]['dns'] = configs[1]['dns']
        source = work/'external-rules.json'
        source.write_text(json.dumps(dict(version=4,rules=[dict(domain_suffix=['lanboat.test']),dict(ip_cidr=['127.0.0.0/8'])])))
        binary_rules=work/'external-rules.srs'
        subprocess.run([str(BINARY),'rule-set','compile','-o',str(binary_rules),str(source)],check=True,capture_output=True)
        configs[1]['route'].update(rule_set=[dict(type='local',tag='external',format='binary',path=str(binary_rules))],rules=[dict(rule_set=['external'],outbound='proxy')])
    elif kind == 'route-dns-network':
        origin_host = 'origin.lanboat.test'
        configs[0]['dns'] = dict(servers=[dict(type='hosts',tag='hosts',predefined={origin_host:['127.0.0.1']})])
        configs[1]['dns'] = dict(servers=[dict(type='local',tag='system'),dict(type='hosts',tag='fallback',predefined={origin_host:['192.0.2.254']})],final='fallback',rules=[dict(dns_server_address={'system':['0.0.0.0/0','::/0']},action='predefined',answer=origin_host+'. 60 IN A 127.0.0.1')])
        configs[1]['route']['rules'] = [dict(action='resolve'),dict(dns_server_address={'system':['0.0.0.0/0','::/0']},outbound='proxy')]
    elif kind in ('route-dns-parallel','route-dns-store'):
        origin_host = 'origin.lanboat.test'
        records = dict(type='hosts', tag='hosts', predefined={origin_host:['127.0.0.1']})
        configs[0]['dns'] = dict(servers=[records])
        if kind == 'route-dns-store':
            configs[1]['dns'] = dict(servers=[records])
            configs[1]['experimental'] = dict(cache_file=dict(enabled=True,store_dns=True,path=str(work/'dns-cache.db'),flush_interval='200ms'))
        else:
            dns_port = port()
            configs[0]['inbounds'].append(dict(type='dns',tag='dns',listen='127.0.0.1',listen_port=dns_port))
            configs[1]['dns'] = dict(servers=[dict(type='udp',tag=tag,server='127.0.0.1',server_port=dns_port,detour='proxy') for tag in ('a','b')],rules=[dict(action='evaluate',server='a',tag='candidate'),dict(match_response='candidate',ip_cidr='127.0.0.0/8',action='respond',race=True),dict(action='route',server='b',speculative=True)])
    elif kind in ('route-dns-quic','route-dns-h3'):
        origin_host = 'origin.lanboat.test'
        dns_kind = kind.removeprefix('route-dns-')
        dns_port = port()
        configs[0]['inbounds'].append(dict(type='dns-'+dns_kind,tag='dns',listen='127.0.0.1',listen_port=dns_port,tls=dict(enabled=True,certificate_path=str(work/'cert.pem'),key_path=str(work/'key.pem'))))
        configs[0]['dns'] = dict(servers=[dict(type='hosts',tag='hosts',predefined={origin_host:['127.0.0.1']})])
        configs[1]['dns'] = dict(servers=[dict(type=dns_kind,tag='secure',server='127.0.0.1',server_port=dns_port,detour='proxy',tls=dict(insecure=True))])
        configs[1]['route']['rules'] = [dict(ip_cidr=['127.0.0.0/8'],outbound='proxy')]
    processes = []
    try:
        started = time.monotonic()
        if kind in ('openconnect-dns','openconnect-dns-dtls'):
            dns_port = port()
            while dns_port in (server_port,client_port):
                dns_port = port()
            inbound.update(dns=['192.0.2.53'],search_domains=['corp.test'],split_dns=['corp.test'])
            origin_host='origin.corp.test'
            configs[0]['inbounds'].append(dict(type='dns',tag='assigned-dns',listen='127.0.0.1',listen_port=dns_port))
            configs[0]['dns']=dict(servers=[dict(type='hosts',tag='hosts',predefined={origin_host:['127.0.0.1']})])
            configs[0]['route']=dict(final='direct',rules=[dict(port=53,override_address='127.0.0.1',override_port=dns_port,outbound='direct')])
            configs[1]['dns']=dict(servers=[dict(type='openconnect',tag='assigned',endpoint='proxy',accept_search_domain=True)],final='assigned',strategy='ipv4_only',rules=[dict(preferred_by='assigned',server='assigned')])
        if kind.startswith('masque-dns-'):
            dns_port = port()
            while dns_port in (server_port,client_port):
                dns_port = port()
            inbound['masque_dns'] = [dict(nameservers=[dict(priority=1,ipv4_addresses=['127.0.0.1'],parameters={'3':base64.b64encode(dns_port.to_bytes(2,'big')).decode()})],internal_domains=[''])]
            inbound['masque_pref64'] = ['64:ff9b::/96']
            configs[0]['inbounds'].append(dict(type='dns',tag='assigned-dns',listen='127.0.0.1',listen_port=dns_port))
            configs[0]['dns'] = dict(servers=[dict(type='hosts',tag='hosts',predefined={'masque-origin.test':['127.0.0.1']})],final='hosts')
            configs[1]['dns'] = dict(servers=[dict(type='masque',tag='assigned',endpoint='proxy')],final='assigned',strategy='ipv4_only')
            origin_host = 'masque-origin.test'
        for role, config in zip(('server', 'client'), configs):
            if kind in ('openconnect-dtls','openconnect-dns-dtls'):
                config['log'] = dict(level='debug')
            path = work/f'{kind}-{role}.json'
            path.write_text(json.dumps(config))
            path.chmod(0o600)
            args = [str(BINARY), role, '-c', str(path)]
            if kind == 'relay-bind' and role == 'client':
                # The reverse client needs the server's authenticated BIND endpoint
                # ready before requesting its remote listening port.
                for attempt in range(200):
                    if processes[0].poll() is not None:
                        raise RuntimeError('Relay BIND server exited during startup')
                    try:
                        socket.create_connection(('127.0.0.1', server_port), timeout=0.05).close()
                        break
                    except OSError:
                        time.sleep(0.005)
                else:
                    raise RuntimeError('Relay BIND server did not start')
                args = [str(BINARY), 'relay-bind', '-c', str(path), '-listen', f'127.0.0.1:{client_port}', '-target', f'127.0.0.1:{origin.server_port}']
            with (work/f'{kind}-{role}.log').open('w') as log:
                interactive = kind == 'openconnect-interactive' and role == 'client'
                if interactive: args.append('--auth-stdio')
                # Cover servers must finish binding before these ports become free.
                for held in reserved:
                    held.close()
                reserved.clear()
                processes.append(subprocess.Popen(args, stdout=log, stderr=log, stdin=subprocess.PIPE if interactive else None))
                if interactive:
                    processes[-1].stdin.write((json.dumps(dict(request_id=1, values=dict(username='client',password=password)))+'\n').encode())
                    processes[-1].stdin.close()
        udp_listener = kind.startswith('shadowsocks-kcptun-') or protocol=='mieru' and inbound['network']=='udp' or transport in ('quic','mkcp') or (kind == 'shadowsocks-v2ray-quic' or kind.startswith('shadowsocks-v2ray-hysteria2')) or protocol in ('hysteria','hysteria2','tuic','juicity','wireguard') or protocol == 'masque' and inbound.get('http_version',3) == 3 or kind == 'trusttunnel-h3' or kind == 'vless-xhttp-h3'
        if kind.startswith(('masque-endpoint-','masque-reverse-')): udp_listener = kind.endswith('-3')
        if kind.startswith('hysteria-faketcp'): udp_listener = False
        if udp_listener:
            for _ in range(200):
                if processes[0].poll() is not None:
                    raise RuntimeError('UDP server exited during startup')
                if udp_bound(processes[0].pid, server_port):
                    break
                time.sleep(0.005)
            else:
                raise RuntimeError('UDP server did not bind its listening port')
        for listen_port in ((client_port,) if udp_listener else (server_port, client_port)):
            for attempt in range(200):
                if any(p.poll() is not None for p in processes):
                    raise RuntimeError('core exited: ' + '\n'.join(p.read_text() for p in work.glob(f'{kind}-*.log')))
                try:
                    socket.create_connection(('127.0.0.1', listen_port), timeout=0.05).close()
                    break
                except OSError:
                    time.sleep(0.005)
            else:
                raise RuntimeError(f'{kind} did not start')
        startup = (time.monotonic()-started)*1000

        def transfer(_, warming=False):
            connection = http.client.HTTPSConnection('127.0.0.1', client_port, timeout=8, context=inner_context) if inner_context else http.client.HTTPConnection('127.0.0.1', client_port, timeout=8)
            with closing(connection):
                if inner_context:
                    connection.set_tunnel(origin_host,origin.server_port)
                    target='/'
                else:
                    target=f'http://{origin_host}:{origin.server_port}/'
                if kind.startswith('sudoku-reverse-') and '-http' in kind:
                    target='/app/'
                connection.request('GET',target)
                response = connection.getresponse()
                data = response.read()
                if warming and response.status in (404,502):
                    raise ConnectionError('MASQUE reverse route not published yet')
                if response.status != 200 or data != PAYLOAD:
                    raise RuntimeError(f'{kind} payload mismatch, status={response.status}, bytes={len(data)}')
                return len(data)

        if kind.startswith(('masque-reverse-', 'sudoku-reverse-')):
            until = time.monotonic()+3
            while True:
                try:
                    transfer(0, warming=True)
                    break
                except (OSError,http.client.HTTPException):
                    if time.monotonic()>=until or any(p.poll() is not None for p in processes): raise
                    time.sleep(0.01)
            startup = (time.monotonic()-started)*1000
        else:
            transfer(0)
        if kind == 'openconnect-interactive':
            prompts=[json.loads(line) for line in (work/f'{kind}-client.log').read_text().splitlines()]
            assert len(prompts)==1 and prompts[0]['type']=='openconnect-auth' and prompts[0]['request_id']==1 and prompts[0]['form']['endpoint']=='proxy',prompts
        if kind in ('openconnect-dtls','openconnect-dns-dtls'):
            for _ in range(200):
                if all('OpenConnect DTLS channel ready' in (work/f'{kind}-{role}.log').read_text() for role in ('server','client')):
                    break
                time.sleep(0.01)
            else:
                raise RuntimeError('DTLS channel not authenticated')
            transfer(0)
        warm_rss = [rss(p.pid) for p in processes]
        before_ticks = sum(ticks(p.pid) for p in processes)
        before = time.monotonic()
        time.sleep(1)
        idle_cpu = (sum(ticks(p.pid) for p in processes)-before_ticks) / os.sysconf('SC_CLK_TCK') / (time.monotonic()-before)*100
        peak = [sum(warm_rss)]
        stop = threading.Event()

        def sample():
            while not stop.wait(0.005):
                peak[0] = max(peak[0], sum(rss(p.pid) for p in processes))

        sampler = threading.Thread(target=sample)
        sampler.start()
        try:
            before = time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                transferred = sum(pool.map(transfer, range(128)))
            elapsed = time.monotonic()-before
        finally:
            stop.set()
            sampler.join()
        result = dict(protocol=kind, startup_ms=round(startup, 2), server_warm_rss_mib=round(warm_rss[0]/2**20, 2), client_warm_rss_mib=round(warm_rss[1]/2**20, 2), total_peak_rss_mib=round(peak[0]/2**20, 2), idle_cpu_percent_1s=round(idle_cpu, 2), throughput_mib_s=round(transferred/2**20/elapsed, 2), requests=128, concurrency=8, bytes_per_request=len(PAYLOAD), auxiliary_processes=sum(len(Path(f'/proc/{p.pid}/task/{p.pid}/children').read_text().split()) for p in processes))
        if kind in ('openconnect-dtls','openconnect-dns-dtls'):
            for p in reversed(processes):
                p.terminate()
                p.wait(timeout=5)
            counts = []
            for role in ('server','client'):
                records = [json.loads(line) for line in (work/f'{kind}-{role}.log').read_text().splitlines()]
                traffic = [record for record in records if record.get('msg') == 'OpenConnect DTLS traffic']
                if len(traffic) != 1 or not all(traffic[0][key] > 128 for key in ('sent_ip_packets','received_ip_packets')):
                    raise RuntimeError('DTLS did not carry measured IP traffic')
                counts.append({key:traffic[0][key] for key in ('sent_ip_packets','received_ip_packets')})
            result['dtls_ip_packet_counts'] = dict(zip(('server','client'), counts))
        return result
    except Exception as error:
        logs = '\n'.join(path.name + ':\n' + path.read_text() for path in work.glob(f'{kind}-*.log'))
        raise RuntimeError(f'{error}\n{logs}') from error
    finally:
        for held in reserved:
            held.close()
        for p in reversed(processes):
            if p.poll() is None:
                p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        if cover is not None:
            cover.shutdown()
            cover.server_close()


class OriginServer(http.server.ThreadingHTTPServer):
    request_queue_size = 128


class CoverServer(OriginServer):
    tls_context = None

    def get_request(self):
        connection, address = super().get_request()
        if self.tls_context is not None:
            connection = self.tls_context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False)
        return connection, address

    def finish_request(self, request, address):
        if self.tls_context is not None:
            request.do_handshake()
        super().finish_request(request, address)

    def handle_error(self, request, address):
        # The proxy intentionally drops the cover connection after its handshake.
        if not isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError)):
            super().handle_error(request, address)


def main():
    origin = OriginServer(('127.0.0.1', 0), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='lanboat-independent-') as temporary:
            work = Path(temporary)
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', str(work/'key.pem'), '-out', str(work/'cert.pem'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1', '-days', '1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', str(work/'client-key.pem'), '-out', str(work/'client-cert.pem'), '-subj', '/CN=resource-client', '-days', '1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            subprocess.run(['openssl','req','-x509','-key',str(work/'key.pem'),'-out',str(work/'cover-large.pem'),'-subj','/CN=localhost','-days','1','-addext','1.3.6.1.4.1.55555.1=ASN1:UTF8String:'+('x'*5000)],check=True,capture_output=True)
            ech=subprocess.check_output([str(BINARY),'generate','ech-keypair','public.test']).decode()
            for label,name in [('ECH CONFIGS','ech-configs.pem'),('ECH KEYS','ech-keys.pem')]:
                begin='-----BEGIN '+label+'-----';end='-----END '+label+'-----'
                path=work/name;path.write_text(begin+ech.split(begin,1)[1].split(end,1)[0]+end+'\n');path.chmod(0o600)
            for role,cert,key in [('server','cert.pem','key.pem'),('client','client-cert.pem','client-key.pem')]:
                subprocess.run(['openssl','pkcs12','-export','-in',str(work/cert),'-inkey',str(work/key),'-out',str(work/(role+'.p12')),'-passout','env:LANBOAT_P12_MEASUREMENT_PASSWORD'],env=dict(os.environ,LANBOAT_P12_MEASUREMENT_PASSWORD='measurement-p12'),check=True,capture_output=True)
            subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(work/'ssh_key')],check=True)
            subprocess.run(['ssh-keygen','-q','-t','ecdsa','-b','256','-a','4','-N','measurement-passphrase','-f',str(work/'ssh_ecdsa')],check=True)
            report = dict(binary_sha256=hashlib.sha256(BINARY.read_bytes()).hexdigest(), binary_bytes=BINARY.stat().st_size, platform='linux-amd64', scope='loopback TCP transfers through two independent-core processes, including external SRS,DNS,ShadowTLS/Reality cover handshakes and Vision TLS1.2/1.3 target traffic (origin/cover fixtures excluded from core RSS); not WAN, GUI or TUN measurements', scenarios=[scenario(kind, origin, work) for kind in ('vless-reality-mldsa','vless-reality-mldsa-vision','vmess-reality-mldsa-grpc','vless-reality','vless-reality-vision','vless-reality-fragment','vless-reality-h2','vmess-reality-grpc','vless-reality-xhttp','masque-endpoint-1','masque-endpoint-2','masque-endpoint-3','masque-endpoint-tuned-2','masque-endpoint-tuned-3','masque-endpoint-pmtu-3','masque-endpoint-pmtu-disabled-3','masque-endpoint-fallback','masque-endpoint-scoped-1','masque-endpoint-scoped-2','masque-endpoint-scoped-3','shadowsocks-cloak-direct','shadowsocks-cloak-aes-gcm','shadowsocks-cloak-aes128','shadowsocks-cloak-plain','shadowsocks-cloak-websocket','shadowsocks-cloak-cdn','shadowsocks-kcptun-v1','shadowsocks-kcptun-v2','shadowsocks-kcptun-v2-compressed','shadowsocks-kcptun-v2-aead','vmess-mkcp','vless-mkcp','trojan-mkcp','relay-mkcp','shadowsocks-mkcp','vless-mkcp-seed','vless-mkcp-dns','vless-mkcp-raw','shadowsocks-shadowtls-1','shadowsocks-shadowtls-2','shadowsocks-shadowtls-3','vless-shadowtls-3','vmess-shadowtls-3','relay-shadowtls-3','vless-xhttp-packet','vless-xhttp-stream-up','vless-xhttp-stream-one','vless-xhttp-h3','vmess-xhttp','trojan-xhttp','relay-xhttp','shadowsocks-xhttp','openconnect','openconnect-interactive','openconnect-dtls','openconnect-dns','openconnect-dns-dtls','masque-dns-1','masque-dns-2','masque-dns-3','hysteria-wechat','hysteria-wechat-xplus','hysteria-wechat-hop','hysteria-hop','hysteria2-hop','trojan-fragment','vless-h2-fragment','vmess-grpc-fragment','anytls-fragment','trojan-fragment-combined','vmess-legacy','hysteria-bbr','hysteria2-bbr','tuic-bbr','tuic4-bbr','juicity-bbr','hysteria2-gecko', 'hysteria2-brutal', 'hysteria2-brutal-no-compensation', 'hysteria2-ignore-bandwidth', 'hysteria-cubic', 'hysteria2-cubic', 'tuic-cubic', 'tuic4-cubic', 'juicity-cubic', 'tuic-reno', 'tuic4-reno', 'shadowsocks-gost-mws', 'shadowsocks-gost-mwss', 'shadowsocks-gost-mtls', 'shadowsocks-gost-ws', 'shadowsocks-gost-wss', 'shadowsocks-gost-tls', 'trojan-record-fragment', 'vless-h2-record-fragment', 'vmess-grpc-record-fragment', 'anytls-record-fragment', 'vmess-mux', 'vmess-mux-ws', 'vless-mux', 'vless-mux-h2', 'shadowsocks-v2ray-ws', 'shadowsocks-v2ray-wss', 'shadowsocks-v2ray-ws-mux8', 'shadowsocks-obfs-http', 'shadowsocks-obfs-tls', 'shadowsocks-v2ray-quic', 'shadowsocks-v2ray-hysteria2', 'shadowsocks-v2ray-hysteria2-open', 'shadowsocks-v2ray-hysteria2-2022', 'vmess-quic', 'vless-quic', 'trojan-quic', 'relay-quic', 'socks', 'http', 'vless-h2-keepalive', 'vmess-grpc-keepalive', 'vmess-grpc-keepalive-idle', 'shadowsocks', 'ss-camellia-128-cfb', 'ss-camellia-192-cfb', 'ss-camellia-256-cfb', 'ss-cast5-cfb', 'ss-idea-cfb', 'ss-rc2-cfb', 'ss-seed-cfb', 'ss-aes-256-cfb-ota', 'ss2022-aes-128-gcm', 'ss2022-aes-256-gcm', 'ss2022-chacha20-poly1305', 'ss2022-aes-128-gcm-multi', 'ss2022-aes-256-gcm-multi', 'brook', 'brook-ws', 'brook-wss', 'brook-quic', 'brook-simple-ws', 'brook-simple-wss', 'brook-simple-quic', 'trojan', 'trojan-mux', 'trojan-mux-ws', 'trojan-mux-ss', 'trojan-ss-aes128', 'trojan-ss-chacha', 'trojan-ss-ws', 'vmess-length-aes-padding', 'vmess-length-chacha', 'trojan-mtls', 'vless-h2-mtls', 'hysteria2-mtls', 'vless', 'vmess', 'anytls', 'relay', 'relay-bind', 'vmess-ws', 'vless-ws-early-path', 'vless-ws-early-header', 'trojan-ws-early-small', 'vless-httpupgrade', 'vless-h2', 'vmess-grpc', 'ssr-aes128', 'ssr-chain-a', 'ssr-tls', 'snell-1', 'snell-4', 'snell-5', 'snell-4-mux', 'snell-4-http', 'hysteria2', 'hysteria2-salamander', 'tuic', 'tuic-quic','hysteria','tuic4','tuic4-quic','ssh','ssh-ecdsa-encrypted','wireguard','wireguard-amnezia-v1','wireguard-amnezia-v2','wireguard-amnezia-v3','wireguard-wgobfs','juicity','trusttunnel-h2','trusttunnel-h3','naive-h2','naive-h3','masque-ip','masque-udp','masque-h1-ip','masque-h1-udp','masque-h2-ip','masque-h2-udp','masque-cleartext-h1-ip','masque-cleartext-h1-udp','masque-cleartext-h2-ip','masque-cleartext-h2-udp','masque-reverse-1','masque-reverse-2','masque-reverse-3','mieru-tcp','mieru-udp','mieru-tcp-pattern','mieru-udp-pattern','vless-vision-plain','vless-vision-tls12','vless-vision-tls13','route-dns-srs','route-dns-quic','route-dns-h3','route-dns-parallel','route-dns-store','route-dns-network','trojan-pkcs12','hysteria2-pkcs12','trojan-ech','hysteria2-ech','trojan-ech-dns')])
        subprocess.run([sys.executable, str(ROOT/'tests/measure-faketcp.py')], check=True)
        raw_report = json.loads((ROOT/'.cache/faketcp-validation/resources.json').read_text())
        assert raw_report['binary_sha256'] == report['binary_sha256']
        report['scenarios'].extend(raw_report['scenarios'])
        report['scope'] += '; FakeTCP scenarios run in an isolated Linux user/network namespace'
        (ROOT/'.cache/independent-validation.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report, indent=2))
    finally:
        origin.shutdown()
        origin.server_close()


if __name__ == '__main__':
    main()
