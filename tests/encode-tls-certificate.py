#!/usr/bin/env python3
"""Test-only certificate compression using system libbrotli/libzstd or Python zlib."""
import ctypes as c,sys
b=sys.stdin.buffer.read((1<<20)+1)
if len(b)>1<<20:raise ValueError('certificate body exceeds1MiB')
if sys.argv[1]=='zlib':
 import zlib
 sys.stdout.buffer.write(zlib.compress(b));sys.exit(0)
src=c.create_string_buffer(b)
if sys.argv[1]=='brotli':
 lib=c.CDLL('libbrotlienc.so.1');lib.BrotliEncoderMaxCompressedSize.argtypes=[c.c_size_t];lib.BrotliEncoderMaxCompressedSize.restype=c.c_size_t
 size=c.c_size_t(lib.BrotliEncoderMaxCompressedSize(len(b)));out=c.create_string_buffer(size.value)
 lib.BrotliEncoderCompress.argtypes=[c.c_int,c.c_int,c.c_int,c.c_size_t,c.c_void_p,c.POINTER(c.c_size_t),c.c_void_p];lib.BrotliEncoderCompress.restype=c.c_int
 if lib.BrotliEncoderCompress(6,20,0,len(b),src,c.byref(size),out)!=1:raise RuntimeError('Brotli encoder failed')
 n=size.value
else:
 lib=c.CDLL('libzstd.so.1');lib.ZSTD_compressBound.argtypes=[c.c_size_t];lib.ZSTD_compressBound.restype=c.c_size_t
 out=c.create_string_buffer(lib.ZSTD_compressBound(len(b)))
 lib.ZSTD_compress.argtypes=[c.c_void_p,c.c_size_t,c.c_void_p,c.c_size_t,c.c_int];lib.ZSTD_compress.restype=c.c_size_t
 n=lib.ZSTD_compress(out,len(out),src,len(b),6)
 lib.ZSTD_isError.argtypes=[c.c_size_t];lib.ZSTD_isError.restype=c.c_uint
 if lib.ZSTD_isError(n):raise RuntimeError('Zstd encoder failed')
sys.stdout.buffer.write(out.raw[:n])
