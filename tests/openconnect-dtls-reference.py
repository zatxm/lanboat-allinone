#!/usr/bin/env python3
"""Test-only DTLS1.2 PSK client using unmodified GnuTLS public APIs."""
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


error = api('gnutls_strerror', c.c_char_p, c.c_int)


def check(n):
    if n < 0:
        raise RuntimeError(error(n).decode())
    return n


request = json.load(sys.stdin)
session, credentials = c.c_void_p(), c.c_void_p()
check(api('gnutls_global_init', c.c_int)())
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.connect(('127.0.0.1', request['port']))
    check(api('gnutls_init', c.c_int, c.POINTER(c.c_void_p), c.c_uint)(c.byref(session), 2 | 4))
    check(api('gnutls_psk_allocate_client_credentials', c.c_int, c.POINTER(c.c_void_p))(c.byref(credentials)))
    key = c.create_string_buffer(bytes.fromhex(request['psk']))
    datum = Datum(c.cast(key, c.c_void_p), len(key) - 1)
    check(api('gnutls_psk_set_client_credentials', c.c_int, c.c_void_p, c.c_char_p, c.POINTER(Datum), c.c_uint)(credentials, b'psk', c.byref(datum), 0))
    check(api('gnutls_credentials_set', c.c_int, c.c_void_p, c.c_uint, c.c_void_p)(session, 4, credentials))
    identity = c.create_string_buffer(bytes.fromhex(request['app_id']))
    datum = Datum(c.cast(identity, c.c_void_p), len(identity) - 1)
    check(api('gnutls_session_set_id', c.c_int, c.c_void_p, c.POINTER(Datum))(session, c.byref(datum)))
    priority = ('NONE:+VERS-DTLS1.2:+COMP-NULL:+PSK:+' + request.get('mac', 'AEAD') + ':+SIGN-ALL:+GROUP-ALL:+' + request['cipher'] + (':%NO_ETM' if request.get('disable_etm') else '')).encode()
    check(api('gnutls_priority_set_direct', c.c_int, c.c_void_p, c.c_char_p, c.c_void_p)(session, priority, None))
    api('gnutls_transport_set_int2', None, c.c_void_p, c.c_int, c.c_int)(session, sock.fileno(), sock.fileno())
    api('gnutls_dtls_set_mtu', None, c.c_void_p, c.c_uint)(session, 17000)
    api('gnutls_dtls_set_timeouts', None, c.c_void_p, c.c_uint, c.c_uint)(session, 100, 4000)
    api('gnutls_handshake_set_timeout', None, c.c_void_p, c.c_uint)(session, 5000)
    check(api('gnutls_handshake', c.c_int, c.c_void_p)(session))
    send = api('gnutls_record_send', c.c_ssize_t, c.c_void_p, c.c_void_p, c.c_size_t)
    recv = api('gnutls_record_recv', c.c_ssize_t, c.c_void_p, c.c_void_p, c.c_size_t)
    replies = []
    for packet in request['packets']:
        raw = bytes.fromhex(packet)
        if check(send(session, raw, len(raw))) != len(raw):
            raise RuntimeError('short DTLS send')
        out = c.create_string_buffer(17000)
        n = check(recv(session, out, len(out)))
        replies.append(out.raw[:n].hex())
    cipher = api('gnutls_cipher_get', c.c_int, c.c_void_p)(session)
    name = api('gnutls_cipher_get_name', c.c_char_p, c.c_int)(cipher).decode()
    version = api('gnutls_check_version', c.c_char_p, c.c_void_p)(None).decode()
    mac = api('gnutls_mac_get', c.c_int, c.c_void_p)(session)
    mac_name = api('gnutls_mac_get_name', c.c_char_p, c.c_int)(mac).decode()
    etm = bool(api('gnutls_session_etm_status', c.c_uint, c.c_void_p)(session))
    json.dump(dict(cipher=name, mac=mac_name, etm=etm, version=version, replies=replies), sys.stdout)
finally:
    if session:
        api('gnutls_deinit', None, c.c_void_p)(session)
    if credentials:
        api('gnutls_psk_free_client_credentials', None, c.c_void_p)(credentials)
    sock.close()
    api('gnutls_global_deinit', None)()
