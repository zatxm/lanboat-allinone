#!/usr/bin/env python3
"""Test-only IDEA oracle using the system libgcrypt, never linked into Lanboat."""
import ctypes as c
import ctypes.util
import json
import sys

request = json.load(sys.stdin)
lib = c.CDLL(ctypes.util.find_library('gcrypt') or 'libgcrypt.so.20')
lib.gcry_check_version.argtypes = [c.c_char_p]
lib.gcry_check_version.restype = c.c_char_p
lib.gcry_cipher_map_name.argtypes = [c.c_char_p]
lib.gcry_cipher_map_name.restype = c.c_int
lib.gcry_cipher_open.argtypes = [c.POINTER(c.c_void_p), c.c_int, c.c_int, c.c_uint]
lib.gcry_cipher_setkey.argtypes = [c.c_void_p, c.c_void_p, c.c_size_t]
lib.gcry_cipher_setiv.argtypes = [c.c_void_p, c.c_void_p, c.c_size_t]
lib.gcry_cipher_encrypt.argtypes = [c.c_void_p, c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t]
lib.gcry_cipher_close.argtypes = [c.c_void_p]
if not lib.gcry_check_version(None):
    raise RuntimeError('libgcrypt initialization failed')

def check(result):
    if result:
        raise RuntimeError(f'libgcrypt error {result}')

handle = c.c_void_p()
algorithm = lib.gcry_cipher_map_name(b'IDEA')
if not algorithm:
    raise RuntimeError('system libgcrypt does not provide IDEA')
check(lib.gcry_cipher_open(c.byref(handle), algorithm, 2 if request['mode'] == 'cfb' else 1, 0))
try:
    key, data, iv = (bytes.fromhex(request.get(k, '')) for k in ('key', 'data', 'iv'))
    check(lib.gcry_cipher_setkey(handle, key, len(key)))
    if iv:
        check(lib.gcry_cipher_setiv(handle, iv, len(iv)))
    out = c.create_string_buffer(len(data))
    check(lib.gcry_cipher_encrypt(handle, out, len(data), data, len(data)))
    print(out.raw.hex())
finally:
    lib.gcry_cipher_close(handle)
