#!/usr/bin/env python3
"""Public GnuTLS API reference; synthetic keys, isolated loopback sockets only."""
import ctypes as c
import ctypes.util
import json
import socket
import sys

lib = c.CDLL(ctypes.util.find_library("gnutls"))
class Datum(c.Structure):
    _fields_ = [("data", c.c_void_p), ("size", c.c_uint)]
def api(name, result, *args):
    f = getattr(lib, name)
    f.restype, f.argtypes = result, list(args)
    return f
error = api("gnutls_strerror", c.c_char_p, c.c_int)
def check(result):
    if result < 0:
        raise RuntimeError(error(result).decode())
    return result
check(api("gnutls_global_init", c.c_int)())
cfg = json.load(sys.stdin)
entity = 2 if cfg["role"] == "client" else 1
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
if entity == 1:
    sock.bind(("127.0.0.1", cfg["port"]))
    print("READY", flush=True)
    _, peer = sock.recvfrom(18432, socket.MSG_PEEK)
    sock.connect(peer)
else:
    sock.connect(("127.0.0.1", cfg["port"]))
session, cred = c.c_void_p(), c.c_void_p()
try:
    check(api("gnutls_init", c.c_int, c.POINTER(c.c_void_p), c.c_uint)(c.byref(session), entity | 4))
    check(api("gnutls_certificate_allocate_credentials", c.c_int, c.POINTER(c.c_void_p))(c.byref(cred)))
    check(api("gnutls_credentials_set", c.c_int, c.c_void_p, c.c_uint, c.c_void_p)(session, 1, cred))
    version, cipher, kx, mac = cfg["version"], cfg["cipher"], cfg["kx"], cfg["mac"]
    priority = f"NONE:+VERS-{version}:+COMP-NULL:+{cipher}:+{mac}:+{kx}:+SIGN-ALL:%COMPAT".encode()
    check(api("gnutls_priority_set_direct", c.c_int, c.c_void_p, c.c_char_p, c.c_void_p)(session, priority, None))
    ids = [api("gnutls_" + kind + "_get_id", c.c_int, c.c_char_p)(value.encode()) for kind, value in [("protocol", version), ("kx", kx), ("cipher", cipher), ("mac", mac)]]
    master, sid = c.create_string_buffer(bytes.fromhex(cfg["master"])), c.create_string_buffer(bytes.fromhex(cfg["id"]))
    m, i = Datum(c.cast(master, c.c_void_p), 48), Datum(c.cast(sid, c.c_void_p), 32)
    check(api("gnutls_session_set_premaster", c.c_int, c.c_void_p, c.c_uint, c.c_int, c.c_int, c.c_int, c.c_int, c.c_int, c.POINTER(Datum), c.POINTER(Datum))(session, entity, *ids, 1, c.byref(m), c.byref(i)))
    sock.settimeout(None)
    api("gnutls_transport_set_int2", None, c.c_void_p, c.c_int, c.c_int)(session, sock.fileno(), sock.fileno())
    api("gnutls_dtls_set_mtu", None, c.c_void_p, c.c_uint)(session, 1500)
    api("gnutls_dtls_set_timeouts", None, c.c_void_p, c.c_uint, c.c_uint)(session, 200, 4000)
    api("gnutls_handshake_set_timeout", None, c.c_void_p, c.c_uint)(session, 5000)
    check(api("gnutls_handshake", c.c_int, c.c_void_p)(session))
    assert api("gnutls_session_is_resumed", c.c_uint, c.c_void_p)(session) == 1
    print("HANDSHAKE", flush=True)
    for size in [1, 513, 1200]:
        payload = bytes(j % 251 for j in range(size))
        wire = b"\x03" + payload
        assert check(api("gnutls_record_send", c.c_ssize_t, c.c_void_p, c.c_void_p, c.c_size_t)(session, wire, len(wire))) == len(wire)
        out = c.create_string_buffer(18432)
        n = check(api("gnutls_record_recv", c.c_ssize_t, c.c_void_p, c.c_void_p, c.c_size_t)(session, out, len(out)))
        assert out.raw[:n] == b"\x04" + payload
    print(json.dumps({"passed": True, "version": api("gnutls_check_version", c.c_char_p, c.c_char_p)(None).decode()}), flush=True)
finally:
    if session:
        api("gnutls_deinit", None, c.c_void_p)(session)
    if cred:
        api("gnutls_certificate_free_credentials", None, c.c_void_p)(cred)
    sock.close()
