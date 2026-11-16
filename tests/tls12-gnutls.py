#!/usr/bin/env python3
"""Test-only TLS1.2/3DES echo endpoint using the public GnuTLS C API."""

import argparse
import ctypes as C
import ctypes.util
import json
import socket


def main():
    args = argparse.ArgumentParser()
    args.add_argument("--cert", required=True)
    args.add_argument("--key", required=True)
    args.add_argument("--kx", choices=["RSA", "ECDHE-RSA", "ECDHE-ECDSA"], required=True)
    opts = args.parse_args()
    lib = C.CDLL(ctypes.util.find_library("gnutls") or "libgnutls.so.30")

    def api(name, result, *parameters):
        fn = getattr(lib, "gnutls_" + name)
        fn.restype, fn.argtypes = result, parameters
        return fn

    error_text = api("strerror", C.c_char_p, C.c_int)

    def check(n):
        if n < 0:
            raise RuntimeError(error_text(n).decode())
        return n

    init = api("init", C.c_int, C.POINTER(C.c_void_p), C.c_uint)
    priority = api("priority_set_direct", C.c_int, C.c_void_p, C.c_char_p, C.POINTER(C.c_char_p))
    allocate = api("certificate_allocate_credentials", C.c_int, C.POINTER(C.c_void_p))
    identity = api("certificate_set_x509_key_file", C.c_int, C.c_void_p, C.c_char_p, C.c_char_p, C.c_int)
    credentials = api("credentials_set", C.c_int, C.c_void_p, C.c_int, C.c_void_p)
    transport = api("transport_set_int2", None, C.c_void_p, C.c_int, C.c_int)
    timeout = api("handshake_set_timeout", None, C.c_void_p, C.c_uint)
    handshake = api("handshake", C.c_int, C.c_void_p)
    recv = api("record_recv", C.c_ssize_t, C.c_void_p, C.c_void_p, C.c_size_t)
    send = api("record_send", C.c_ssize_t, C.c_void_p, C.c_void_p, C.c_size_t)
    bye = api("bye", C.c_int, C.c_void_p, C.c_int)
    deinit = api("deinit", None, C.c_void_p)
    free = api("certificate_free_credentials", None, C.c_void_p)
    cipher = api("cipher_get", C.c_int, C.c_void_p)
    cipher_name = api("cipher_get_name", C.c_char_p, C.c_int)
    version = api("protocol_get_version", C.c_int, C.c_void_p)
    version_name = api("protocol_get_name", C.c_char_p, C.c_int)
    kx = api("kx_get", C.c_int, C.c_void_p)
    kx_name = api("kx_get_name", C.c_char_p, C.c_int)
    library_version = api("check_version", C.c_char_p, C.c_char_p)

    session, creds = C.c_void_p(), C.c_void_p()
    check(init(C.byref(session), 1))  # GNUTLS_SERVER
    try:
        check(allocate(C.byref(creds)))
        check(identity(creds, opts.cert.encode(), opts.key.encode(), 1))  # PEM
        check(credentials(session, 1, creds))  # GNUTLS_CRD_CERTIFICATE
        profile = f"NONE:+VERS-TLS1.2:+COMP-NULL:+{opts.kx}:+3DES-CBC:+SHA1:+SIGN-ALL:+GROUP-ALL"
        at = C.c_char_p()
        check(priority(session, profile.encode(), C.byref(at)))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)
            print(f"127.0.0.1:{listener.getsockname()[1]}", flush=True)
            conn, _ = listener.accept()
            with conn:
                transport(session, conn.fileno(), conn.fileno())
                timeout(session, 5000)
                check(handshake(session))
                print(json.dumps({"library": library_version(None).decode(),
                                  "version": version_name(version(session)).decode(),
                                  "cipher": cipher_name(cipher(session)).decode(),
                                  "kx": kx_name(kx(session)).decode()}), flush=True)
                buf = C.create_string_buffer(16384)
                while n := check(recv(session, buf, len(buf))):
                    pos = 0
                    while pos < n:
                        sent = check(send(session, C.byref(buf, pos), n - pos))
                        if not sent:
                            raise RuntimeError("zero-length TLS write")
                        pos += sent
                check(bye(session, 1))  # GNUTLS_SHUT_WR
    finally:
        deinit(session)
        if creds:
            free(creds)


if __name__ == "__main__":
    main()
