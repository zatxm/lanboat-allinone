package native

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"hash"
	"slices"
)

type browserTLS12Spec struct {
	keySize, macSize               int
	rsaKeyExchange, rsaCertificate bool
}

func browserTLS12Cipher(suite uint16) (browserTLS12Spec, bool) {
	s := browserTLS12Spec{}
	switch suite {
	case 0xc02b, 0xc02c, 0xcca9:
		return s, true
	case 0xc02f, 0xc030, 0xcca8:
		s.rsaCertificate = true
		return s, true
	case 0x009c, 0x009d:
		s.rsaKeyExchange, s.rsaCertificate = true, true
		return s, true
	case 0x002f, 0x0035, 0x003c, 0x003d, 0x000a:
		s.rsaKeyExchange, s.rsaCertificate = true, true
	case 0xc013, 0xc014, 0xc027, 0xc028, 0xc012:
		s.rsaCertificate = true
	case 0xc009, 0xc00a, 0xc023, 0xc024, 0xc008:
	default:
		return s, false
	}
	s.macSize, s.keySize = 20, 16
	switch suite {
	case 0xc008, 0xc012, 0x000a:
		s.keySize = 24
	case 0x0035, 0x003d, 0xc00a, 0xc014, 0xc024, 0xc028:
		s.keySize = 32
	}
	switch suite {
	case 0x003c, 0x003d, 0xc023, 0xc027:
		s.macSize = 32
	case 0xc024, 0xc028:
		s.macSize = 48
	}
	return s, true
}

func browserTLS12RSAExchange(cert *x509.Certificate) ([]byte, []byte, error) {
	key, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < 1024 || key.N.BitLen() > 8192 || cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		return nil, nil, errors.New("invalid browser TLS RSA encryption certificate")
	}
	shared := make([]byte, 48)
	rand.Read(shared)
	shared[0], shared[1] = 3, 3
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, key, shared)
	if err != nil {
		clear(shared)
		return nil, nil, err
	}
	return shared, stVector(ciphertext, 2), nil
}

type browserTLS12CBC struct {
	key    cipher.Block
	mac    hash.Hash
	verify ocCBCMAC
}

func browserTLS12SignatureKey(key any, scheme tls.SignatureScheme) bool {
	switch k := key.(type) {
	case *rsa.PublicKey:
		if scheme == tls.PKCS1WithSHA1 {
			return k.N.BitLen() >= 1024 && k.N.BitLen() <= 8192
		}
	case *ecdsa.PublicKey:
		if scheme == tls.ECDSAWithSHA1 {
			return true
		}
	}
	return ocTLS12SignatureKey(key, scheme)
}

func browserTLS12Verify(key any, scheme tls.SignatureScheme, input, signature []byte) error {
	if scheme != tls.PKCS1WithSHA1 && scheme != tls.ECDSAWithSHA1 {
		return ocTLS12Verify(key, scheme, input, signature)
	}
	if !browserTLS12SignatureKey(key, scheme) {
		return errors.New("invalid browser TLS1.2 signature key")
	}
	digest := sha1.Sum(input)
	switch k := key.(type) {
	case *rsa.PublicKey:
		if scheme == tls.PKCS1WithSHA1 && k.N.BitLen() >= 1024 && k.N.BitLen() <= 8192 {
			return rsa.VerifyPKCS1v15(k, crypto.SHA1, digest[:], signature)
		}
	case *ecdsa.PublicKey:
		if scheme == tls.ECDSAWithSHA1 && ecdsa.VerifyASN1(k, digest[:], signature) {
			return nil
		}
	}
	return errors.New("invalid browser TLS1.2 SHA1 handshake signature")
}

func browserTLS12ClientMatch(cert *tls.Certificate, request *tls.CertificateRequestInfo, allowed []byte) bool {
	if cert == nil || len(cert.Certificate) == 0 {
		return false
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return false
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}
	var kind byte
	switch key := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if !key.Equal(signer.Public()) {
			return false
		}
		kind = 1
	case *ecdsa.PublicKey:
		if !key.Equal(signer.Public()) {
			return false
		}
		kind = 64
	default:
		return false
	}
	if !slices.Contains(allowed, kind) {
		return false
	}
	matched := false
	for _, scheme := range request.SignatureSchemes {
		if browserTLS12SignatureKey(leaf.PublicKey, scheme) && (len(cert.SupportedSignatureAlgorithms) == 0 || slices.Contains(cert.SupportedSignatureAlgorithms, scheme)) {
			matched = true
			break
		}
	}
	if !matched || len(request.AcceptableCAs) == 0 {
		return matched
	}
	for _, der := range cert.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return false
		}
		for _, ca := range request.AcceptableCAs {
			if bytes.Equal(cert.RawIssuer, ca) {
				return true
			}
		}
	}
	return false
}

func browserTLS12Sign(cert *tls.Certificate, schemes []tls.SignatureScheme, transcript []byte) ([]byte, error) {
	key, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("browser TLS client certificate has no signer")
	}
	for _, scheme := range schemes {
		if !browserTLS12SignatureKey(key.Public(), scheme) || len(cert.SupportedSignatureAlgorithms) > 0 && !slices.Contains(cert.SupportedSignatureAlgorithms, scheme) {
			continue
		}
		if scheme != tls.PKCS1WithSHA1 && scheme != tls.ECDSAWithSHA1 {
			return ocTLS12Sign(cert, []tls.SignatureScheme{scheme}, transcript)
		}
		digest := sha1.Sum(transcript)
		signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA1)
		if err != nil {
			return nil, err
		}
		return append(browserWords(uint16(scheme)), stVector(signature, 2)...), nil
	}
	return nil, errors.New("no common browser TLS client signature")
}

func browserTLS12Keys(suite uint16, master, client, server []byte) ([2]*ocTLS12Cipher, error) {
	var out [2]*ocTLS12Cipher
	spec, ok := browserTLS12Cipher(suite)
	if !ok {
		return out, errors.New("unsupported browser TLS1.2 suite")
	}
	if spec.macSize == 0 {
		return ocTLS12Keys(suite, master, client, server)
	}
	newMAC := sha1.New
	if spec.macSize == 32 {
		newMAC = sha256.New
	} else if spec.macSize == 48 {
		newMAC = sha512.New384
	}
	seed := append(bytes.Clone(server), client...)
	keys := ocDTLSPRF(ocTLS12Hash(suite), master, "key expansion", seed, 2*(spec.macSize+spec.keySize))
	defer clear(keys)
	for i := range out {
		mac := keys[i*spec.macSize : (i+1)*spec.macSize]
		key := keys[2*spec.macSize+i*spec.keySize : 2*spec.macSize+(i+1)*spec.keySize]
		var block cipher.Block
		var err error
		limit := uint64(1 << 24)
		if spec.keySize == 24 {
			block, err = des.NewTripleDESCipher(key)
			limit = 1 << 16 // Bound exposure of the legacy64-bit block cipher.
		} else {
			block, err = aes.NewCipher(key)
		}
		if err != nil {
			return out, err
		}
		out[i] = &ocTLS12Cipher{limit: limit, cbc: &browserTLS12CBC{key: block, mac: hmac.New(newMAC, mac), verify: newOCCBCMAC(mac, spec.macSize)}}
	}
	return out, nil
}

func tls12AAD(sequence uint64, kind byte, length int) [13]byte {
	var aad [13]byte
	binary.BigEndian.PutUint64(aad[:8], sequence)
	aad[8], aad[9], aad[10] = kind, 3, 3
	binary.BigEndian.PutUint16(aad[11:], uint16(length))
	return aad
}

func (c *ocTLS12Cipher) sealCBC(kind byte, data []byte) ([]byte, error) {
	b := c.cbc
	size := b.key.BlockSize()
	aad := tls12AAD(c.sequence, kind, len(data))
	b.mac.Reset()
	b.mac.Write(aad[:])
	b.mac.Write(data)
	padding := size - (len(data)+b.mac.Size())%size
	n := size + len(data) + b.mac.Size() + padding
	if cap(c.buffer) < n+5 {
		c.buffer = make([]byte, 0, n+5)
	}
	wire := append(c.buffer[:0], kind, 3, 3, byte(n>>8), byte(n))
	wire = append(wire, make([]byte, size)...)
	rand.Read(wire[5 : 5+size])
	wire = append(wire, data...)
	wire = b.mac.Sum(wire)
	for range padding {
		wire = append(wire, byte(padding-1))
	}
	ocDTLSCBCEncrypt(b.key, wire[5:5+size], wire[5+size:])
	c.buffer = wire
	c.sequence++
	return wire, nil
}

func (c *ocTLS12Cipher) openCBC(frame []byte) ([]byte, error) {
	b := c.cbc
	size, fragment := b.key.BlockSize(), frame[5:]
	if len(fragment) < size*2 || len(fragment) > size+16384+b.mac.Size()+256 || (len(fragment)-size)%size != 0 {
		return nil, errors.New("invalid TLS1.2 CBC record")
	}
	plain := fragment[size:]
	ocDTLSCBCDecrypt(b.key, fragment[:size], plain)
	aad := tls12AAD(c.sequence, frame[0], 0)
	data, ok := ocCBCUnpad(plain, &b.verify, aad[:])
	if !ok {
		return nil, errors.New("invalid TLS1.2 CBC authentication")
	}
	c.sequence++
	return data, nil
}
