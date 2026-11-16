#!/usr/bin/env python3
"""Test-only DTLS1.2 PSK rehandshakes through GnuTLS public APIs."""
import ctypes as c
import ctypes.util
import json
import socket
import sys
import time

g = c.CDLL(ctypes.util.find_library('gnutls'))

class Datum(c.Structure):
    _fields_ = [('data', c.c_void_p), ('size', c.c_uint)]

def api(name, result, *args):
    fn = getattr(g, name)
    fn.restype, fn.argtypes = result, list(args)
    return fn

strerror = api('gnutls_strerror', c.c_char_p, c.c_int)
def check(n):
    if n < 0:
        raise RuntimeError(f'{n}: {strerror(n).decode()}')
    return n

def retry(fn, *args):
    end = time.monotonic() + 6
    while True:
        n = fn(*args)
        if n not in (-28, -52) or time.monotonic() >= end:
            return n

request = json.loads(sys.stdin.readline())
server = request['role'] == 'server'
secret = bytes.fromhex(request['psk'])
session, credentials = c.c_void_p(), c.c_void_p()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
check(api('gnutls_global_init', c.c_int)())
try:
    check(api('gnutls_init', c.c_int, c.POINTER(c.c_void_p), c.c_uint)(c.byref(session), (1 if server else 2) | 4))
    if server:
        check(api('gnutls_psk_allocate_server_credentials', c.c_int, c.POINTER(c.c_void_p))(c.byref(credentials)))
        allocate = c.CFUNCTYPE(c.c_void_p, c.c_size_t).in_dll(g, 'gnutls_malloc')
        callback_type = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_char_p, c.POINTER(Datum))
        @callback_type
        def key_callback(_, username, key):
            if username != b'psk':
                return -1
            p = allocate(len(secret))
            if not p:
                return -1
            c.memmove(p, secret, len(secret))
            key.contents.data, key.contents.size = p, len(secret)
            return 0
        api('gnutls_psk_set_server_credentials_function', None, c.c_void_p, callback_type)(credentials, key_callback)
    else:
        check(api('gnutls_psk_allocate_client_credentials', c.c_int, c.POINTER(c.c_void_p))(c.byref(credentials)))
        key = c.create_string_buffer(secret)
        datum = Datum(c.cast(key, c.c_void_p), len(secret))
        check(api('gnutls_psk_set_client_credentials', c.c_int, c.c_void_p, c.c_char_p, c.POINTER(Datum), c.c_uint)(credentials, b'psk', c.byref(datum), 0))
        identity = c.create_string_buffer(bytes.fromhex(request['app_id']))
        datum = Datum(c.cast(identity, c.c_void_p), len(identity)-1)
        check(api('gnutls_session_set_id', c.c_int, c.c_void_p, c.POINTER(Datum))(session, c.byref(datum)))
    check(api('gnutls_credentials_set', c.c_int, c.c_void_p, c.c_uint, c.c_void_p)(session, 4, credentials))
    priority = ('NONE:+VERS-DTLS1.2:+COMP-NULL:+PSK:+' + request['mac'] + ':+SIGN-ALL:+GROUP-ALL:+' + request['cipher'] + (':%NO_ETM' if request.get('disable_etm') else '')).encode()
    check(api('gnutls_priority_set_direct', c.c_int, c.c_void_p, c.c_char_p, c.c_void_p)(session, priority, None))
    if server:
        sock.bind(('127.0.0.1', request['port']))
        print('READY', flush=True)
        _, peer = sock.recvfrom(1, socket.MSG_PEEK)
    else:
        peer = ('127.0.0.1', request['port'])
    sock.connect(peer)
    api('gnutls_transport_set_int2', None, c.c_void_p, c.c_int, c.c_int)(session, sock.fileno(), sock.fileno())
    api('gnutls_dtls_set_mtu', None, c.c_void_p, c.c_uint)(session, 17000)
    api('gnutls_dtls_set_timeouts', None, c.c_void_p, c.c_uint, c.c_uint)(session, 100, 4000)
    api('gnutls_handshake_set_timeout', None, c.c_void_p, c.c_uint)(session, 5000)
    api('gnutls_record_set_timeout', None, c.c_void_p, c.c_uint)(session, 5000)
    handshake = api('gnutls_handshake', c.c_int, c.c_void_p)
    check(retry(handshake, session))
    if not api('gnutls_safe_renegotiation_status', c.c_uint, c.c_void_p)(session):
        raise RuntimeError('secure renegotiation not negotiated')
    print('HANDSHAKE', flush=True)
    send = api('gnutls_record_send', c.c_ssize_t, c.c_void_p, c.c_void_p, c.c_size_t)
    recv = api('gnutls_record_recv', c.c_ssize_t, c.c_void_p, c.c_void_p, c.c_size_t)
    out = c.create_string_buffer(17000)
    for round, size in enumerate([1, 513, 1200]):
        raw = bytes([3]) + bytes((j+round) % 256 for j in range(size))
        assert check(send(session, raw, len(raw))) == len(raw)
        n = check(retry(recv, session, out, len(out)))
        assert out.raw[:n] == bytes([4]) + raw[1:], 'echo mismatch'
        if round == 2:
            break
        if request['initiator'] == 'reference':
            if server:
                check(api('gnutls_rehandshake', c.c_int, c.c_void_p)(session))
            check(retry(handshake, session))
        else:
            n = retry(recv, session, out, len(out))
            assert n == -37, f'expected GNUTLS_E_REHANDSHAKE,got{n}'
            check(retry(handshake, session))
    version = api('gnutls_check_version', c.c_char_p, c.c_void_p)(None).decode()
    print(json.dumps(dict(passed=True, rekeys=2, version=version)), flush=True)
finally:
    if session:
        api('gnutls_deinit', None, c.c_void_p)(session)
    if credentials:
        api('gnutls_psk_free_server_credentials' if server else 'gnutls_psk_free_client_credentials', None, c.c_void_p)(credentials)
    sock.close()
    api('gnutls_global_deinit', None)()
