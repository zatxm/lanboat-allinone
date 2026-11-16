#!/usr/bin/env python3
"""Independent test-only ECIES producer using Python cryptography/OpenSSL."""
import base64
import os
import struct
import sys
import ssl
import urllib.request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def encrypt(public, token):
    peer = serialization.load_der_public_key(base64.b64decode(public, validate=True))
    assert isinstance(peer, ec.EllipticCurvePublicKey) and isinstance(peer.curve, ec.SECP256R1)
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    shared = ephemeral.exchange(ec.ECDH(), peer)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'AC_ECIES').derive(shared)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    ciphertext = cipher.update(token.encode('ascii')) + cipher.finalize()
    fields = [ephemeral.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo), cipher.tag[:12], ciphertext, nonce]
    return base64.b64encode(b'\0\1' + b''.join(struct.pack('!HH', tag, len(value)) + value for tag, value in enumerate(fields, 1))).decode('ascii')


if __name__ == '__main__':
    if sys.argv[1] == '--browser':
        # Local test gateway only; product and reference CLI still validate its certificate.
        assert sys.argv[2].startswith('https://127.0.0.1:')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
        with opener.open(sys.argv[2], timeout=10) as response:
            assert response.status == 200
    else:
        print(encrypt(sys.argv[1], sys.argv[2]))
