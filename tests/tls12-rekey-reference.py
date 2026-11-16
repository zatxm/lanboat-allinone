#!/usr/bin/env python3
"""Test-only X509 TLS1.2 rehandshakes through public GnuTLS APIs."""
import ctypes as c
import ctypes.util
import json
import socket
import sys

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

request = json.loads(sys.stdin.readline())
server = request['role'] == 'server'
session, credentials = c.c_void_p(), c.c_void_p()
listener = sock = None
check(api('gnutls_global_init', c.c_int)())
try:
    check(api('gnutls_init', c.c_int, c.POINTER(c.c_void_p), c.c_uint)(c.byref(session), 1 if server else 2))
    check(api('gnutls_certificate_allocate_credentials', c.c_int, c.POINTER(c.c_void_p))(c.byref(credentials)))
    check(api('gnutls_certificate_set_x509_key_file', c.c_int, c.c_void_p, c.c_char_p, c.c_char_p, c.c_int)(credentials, request['cert'].encode(), request['key'].encode(), 1))
    check(api('gnutls_certificate_set_x509_trust_file', c.c_int, c.c_void_p, c.c_char_p, c.c_int)(credentials, request['ca'].encode(), 1))
    check(api('gnutls_credentials_set', c.c_int, c.c_void_p, c.c_uint, c.c_void_p)(session, 1, credentials))
    priority = f"NONE:+VERS-TLS1.2:+COMP-NULL:+{request['kx']}:+{request.get('mac', 'AEAD')}:+SIGN-ALL:+GROUP-ALL:+{request['cipher']}".encode()
    check(api('gnutls_priority_set_direct', c.c_int, c.c_void_p, c.c_char_p, c.c_void_p)(session, priority, None))
    proto = c.create_string_buffer(b'http/1.1')
    datum = Datum(c.cast(proto, c.c_void_p), 8)
    check(api('gnutls_alpn_set_protocols', c.c_int, c.c_void_p, c.POINTER(Datum), c.c_uint, c.c_uint)(session, c.byref(datum), 1, 0))
    if server:
        if request['mutual']:
            api('gnutls_certificate_server_set_request', None, c.c_void_p, c.c_int)(session, 2)
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', request['port']))
        listener.listen(1)
        print('READY', flush=True)
        sock, _ = listener.accept()
    else:
        check(api('gnutls_server_name_set', c.c_int, c.c_void_p, c.c_int, c.c_char_p, c.c_size_t)(session, 1, b'example.com', 11))
        api('gnutls_session_set_verify_cert', None, c.c_void_p, c.c_char_p, c.c_uint)(session, b'example.com', 0)
        sock = socket.create_connection(('127.0.0.1', request['port']))
    api('gnutls_transport_set_int2', None, c.c_void_p, c.c_int, c.c_int)(session, sock.fileno(), sock.fileno())
    api('gnutls_handshake_set_timeout', None, c.c_void_p, c.c_uint)(session, 4000)
    api('gnutls_record_set_timeout', None, c.c_void_p, c.c_uint)(session, 4000)
    handshake = api('gnutls_handshake', c.c_int, c.c_void_p)
    check(handshake(session))
    assert api('gnutls_safe_renegotiation_status', c.c_uint, c.c_void_p)(session)
    print('HANDSHAKE', flush=True)
    send = api('gnutls_record_send', c.c_ssize_t, c.c_void_p, c.c_void_p, c.c_size_t)
    recv = api('gnutls_record_recv', c.c_ssize_t, c.c_void_p, c.c_void_p, c.c_size_t)
    out = c.create_string_buffer(20000)
    exporters = []
    for round, size in enumerate([1, 513, 16000]):
        key = c.create_string_buffer(32)
        label = b'EXPORTER-openconnect-psk'
        check(api('gnutls_prf_rfc5705', c.c_int, c.c_void_p, c.c_size_t, c.c_char_p, c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p)(session, len(label), label, 0, None, 32, key))
        exporters.append(key.raw.hex())
        raw = bytes((j+round) % 256 for j in range(size))
        assert check(send(session, raw, len(raw))) == len(raw)
        reply = b''
        while len(reply) < len(raw):
            n = check(recv(session, out, len(out)))
            assert n > 0
            reply += out.raw[:n]
        assert reply == raw, 'echo mismatch'
        if round == 2:
            break
        if request['initiator'] == 'reference':
            if server:
                check(api('gnutls_rehandshake', c.c_int, c.c_void_p)(session))
            check(handshake(session))
        else:
            n = recv(session, out, len(out))
            assert n == -37, f'expected GNUTLS_E_REHANDSHAKE,got{n}'
            check(handshake(session))
    version = api('gnutls_check_version', c.c_char_p, c.c_void_p)(None).decode()
    print(json.dumps(dict(passed=True, rekeys=2, version=version, exporters=exporters)), flush=True)
finally:
    if session:
        api('gnutls_deinit', None, c.c_void_p)(session)
    if credentials:
        api('gnutls_certificate_free_credentials', None, c.c_void_p)(credentials)
    if sock:
        sock.close()
    if listener:
        listener.close()
    api('gnutls_global_deinit', None)()
