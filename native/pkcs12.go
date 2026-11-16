package native

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"unicode/utf16"
	"unicode/utf8"
)

const pkcs12MaxSize = 16 << 20

type p12Content struct {
	Type asn1.ObjectIdentifier
	Data asn1.RawValue `asn1:"explicit,tag:0"`
}

type p12MAC struct {
	Digest struct {
		Algorithm pkix.AlgorithmIdentifier
		Value     []byte
	}
	Salt       []byte
	Iterations int `asn1:"optional,default:1"`
}

type p12Bag struct {
	Type       asn1.ObjectIdentifier
	Value      asn1.RawValue `asn1:"explicit,tag:0"`
	Attributes asn1.RawValue `asn1:"optional,set"`
}

type p12Decoder struct {
	password string
	unicode  []byte
	work     int
	bags     int
	key      crypto.Signer
	certs    []*x509.Certificate
}

func p12ASN1(data []byte, out any) error {
	rest, err := asn1.Unmarshal(data, out)
	if err != nil || len(rest) != 0 {
		return errors.New("invalid PKCS12 DER structure")
	}
	return nil
}

func p12Sequence(data []byte) ([]byte, error) {
	var seq asn1.RawValue
	if err := p12ASN1(data, &seq); err != nil {
		return nil, err
	}
	if seq.Class != 0 || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, errors.New("PKCS12 requires a DER sequence")
	}
	return seq.Bytes, nil
}

func p12Hash(oid string) (func() hash.Hash, error) {
	switch oid {
	case "1.3.14.3.2.26", "1.2.840.113549.2.7", "":
		return sha1.New, nil
	case "2.16.840.1.101.3.4.2.4", "1.2.840.113549.2.8":
		return sha256.New224, nil
	case "2.16.840.1.101.3.4.2.1", "1.2.840.113549.2.9":
		return sha256.New, nil
	case "2.16.840.1.101.3.4.2.2", "1.2.840.113549.2.10":
		return sha512.New384, nil
	case "2.16.840.1.101.3.4.2.3", "1.2.840.113549.2.11":
		return sha512.New, nil
	case "2.16.840.1.101.3.4.2.5", "1.2.840.113549.2.12":
		return sha512.New512_224, nil
	case "2.16.840.1.101.3.4.2.6", "1.2.840.113549.2.13":
		return sha512.New512_256, nil
	}
	return nil, fmt.Errorf("unsupported PKCS12 hash %s", oid)
}

func (d *p12Decoder) charge(salt []byte, iterations, blocks int) error {
	if len(salt) == 0 || len(salt) > 1024 || iterations < 1 || iterations > 1000000 {
		return errors.New("invalid PKCS12 KDF salt or iteration count")
	}
	d.work += iterations * blocks
	if d.work > 10000000 {
		return errors.New("PKCS12 KDF work budget exceeded")
	}
	return nil
}

// RFC7292 diversifies the hash input, then adds each derived block plus one to
// every salt/password block. PBES2 instead uses the original UTF-8 password.
func (d *p12Decoder) derive(hf func() hash.Hash, salt []byte, iterations, id, size int) ([]byte, error) {
	h := hf()
	blocks := (size + h.Size() - 1) / h.Size()
	if err := d.charge(salt, iterations, blocks); err != nil {
		return nil, err
	}
	v := h.BlockSize()
	div := bytes.Repeat([]byte{byte(id)}, v)
	var input []byte
	for _, data := range [][]byte{salt, d.unicode} {
		if len(data) > 0 {
			for i := 0; i < (len(data)+v-1)/v*v; i++ {
				input = append(input, data[i%len(data)])
			}
		}
	}
	defer clear(input)
	out, b := make([]byte, 0, blocks*h.Size()), make([]byte, v)
	defer clear(b)
	for range blocks {
		h.Reset()
		h.Write(div)
		h.Write(input)
		a := h.Sum(nil)
		for i := 1; i < iterations; i++ {
			h.Reset()
			h.Write(a)
			a = h.Sum(a[:0])
		}
		out = append(out, a...)
		for i := range b {
			b[i] = a[i%len(a)]
		}
		clear(a)
		for start := 0; start < len(input); start += v {
			carry := uint16(1)
			for j := v - 1; j >= 0; j-- {
				sum := uint16(input[start+j]) + uint16(b[j]) + carry
				input[start+j], carry = byte(sum), sum>>8
			}
		}
	}
	return out[:size], nil
}

func (d *p12Decoder) pbkdf(algorithm pkix.AlgorithmIdentifier, size int) ([]byte, error) {
	if algorithm.Algorithm.String() != "1.2.840.113549.1.5.12" {
		return nil, errors.New("PKCS12 PBES2/PBMAC1 requires PBKDF2")
	}
	var p struct {
		Salt       []byte
		Iterations int
		KeyLength  int                      `asn1:"optional"`
		PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
	}
	if err := p12ASN1(algorithm.Parameters.FullBytes, &p); err != nil {
		return nil, err
	}
	if size == 0 {
		size = p.KeyLength
	}
	if size < 1 || size > 64 || p.KeyLength != 0 && p.KeyLength != size {
		return nil, errors.New("invalid PKCS12 PBKDF2 key length")
	}
	h, err := p12Hash(p.PRF.Algorithm.String())
	if err != nil {
		return nil, err
	}
	if err = d.charge(p.Salt, p.Iterations, (size+h().Size()-1)/h().Size()); err != nil {
		return nil, err
	}
	return pbkdf2.Key(h, d.password, p.Salt, p.Iterations, size)
}

func (d *p12Decoder) verifyMAC(m p12MAC, data []byte) error {
	var hf func() hash.Hash
	var key []byte
	var err error
	if m.Digest.Algorithm.Algorithm.String() == "1.2.840.113549.1.5.14" {
		var p struct{ KDF, MAC pkix.AlgorithmIdentifier }
		if err = p12ASN1(m.Digest.Algorithm.Parameters.FullBytes, &p); err != nil {
			return err
		}
		hf, err = p12Hash(p.MAC.Algorithm.String())
		if err == nil {
			key, err = d.pbkdf(p.KDF, 0)
		}
		if err == nil && (hf().Size() <= 20 || len(key) < 20) {
			clear(key)
			return errors.New("PKCS12 PBMAC1 requires SHA2 and at least20 key bytes")
		}
	} else {
		hf, err = p12Hash(m.Digest.Algorithm.Algorithm.String())
		if err == nil {
			key, err = d.derive(hf, m.Salt, m.Iterations, 3, hf().Size())
		}
	}
	if err != nil {
		return err
	}
	defer clear(key)
	h := hmac.New(hf, key)
	h.Write(data)
	if !hmac.Equal(h.Sum(nil), m.Digest.Value) {
		return errors.New("PKCS12 password or integrity check failed")
	}
	return nil
}

func (d *p12Decoder) decrypt(algorithm pkix.AlgorithmIdentifier, encrypted []byte) ([]byte, error) {
	var key, iv []byte
	var block cipher.Block
	var err error
	if algorithm.Algorithm.String() == "1.2.840.113549.1.5.13" {
		var p struct{ KDF, Cipher pkix.AlgorithmIdentifier }
		if err = p12ASN1(algorithm.Parameters.FullBytes, &p); err != nil {
			return nil, err
		}
		size := map[string]int{"2.16.840.1.101.3.4.1.2": 16, "2.16.840.1.101.3.4.1.22": 24, "2.16.840.1.101.3.4.1.42": 32}[p.Cipher.Algorithm.String()]
		if size == 0 {
			return nil, errors.New("PKCS12 PBES2 requires AES-CBC")
		}
		key, err = d.pbkdf(p.KDF, size)
		if err != nil {
			return nil, err
		}
		defer clear(key)
		if err = p12ASN1(p.Cipher.Parameters.FullBytes, &iv); err != nil {
			return nil, err
		}
		block, err = aes.NewCipher(key)
	} else {
		sizes := map[string]int{"1.2.840.113549.1.12.1.1": 16, "1.2.840.113549.1.12.1.2": 5, "1.2.840.113549.1.12.1.3": 24, "1.2.840.113549.1.12.1.4": 16, "1.2.840.113549.1.12.1.5": 16, "1.2.840.113549.1.12.1.6": 5}
		size := sizes[algorithm.Algorithm.String()]
		if size == 0 {
			return nil, fmt.Errorf("unsupported PKCS12 encryption %s", algorithm.Algorithm)
		}
		var p struct {
			Salt       []byte
			Iterations int
		}
		if err = p12ASN1(algorithm.Parameters.FullBytes, &p); err != nil {
			return nil, err
		}
		key, err = d.derive(sha1.New, p.Salt, p.Iterations, 1, size)
		if err != nil {
			return nil, err
		}
		defer clear(key)
		switch algorithm.Algorithm[len(algorithm.Algorithm)-1] {
		case 1, 2:
			stream, e := rc4.NewCipher(key)
			if e != nil {
				return nil, e
			}
			plain := make([]byte, len(encrypted))
			stream.XORKeyStream(plain, encrypted)
			stream.Reset()
			return plain, nil
		case 3, 4:
			if len(key) == 16 {
				key = append(key, key[:8]...)
				defer clear(key)
			}
			block, err = des.NewTripleDESCipher(key)
		case 5, 6:
			block = newRC2(key, size*8)
		}
		iv, err = d.derive(sha1.New, p.Salt, p.Iterations, 2, 8)
		defer clear(iv)
	}
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() || len(encrypted) == 0 || len(encrypted)%block.BlockSize() != 0 {
		return nil, errors.New("invalid PKCS12 CBC parameters")
	}
	plain := make([]byte, len(encrypted))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, encrypted)
	n := int(plain[len(plain)-1])
	valid := subtle.ConstantTimeLessOrEq(1, n) & subtle.ConstantTimeLessOrEq(n, block.BlockSize())
	for i := 1; i <= block.BlockSize(); i++ {
		valid &= subtle.ConstantTimeLessOrEq(n+1, i) | subtle.ConstantTimeByteEq(plain[len(plain)-i], byte(n))
	}
	if valid != 1 {
		clear(plain)
		return nil, errors.New("PKCS12 decryption failed")
	}
	return plain[:len(plain)-n], nil
}

func (d *p12Decoder) safe(data []byte, depth int) error {
	if depth > 8 {
		return errors.New("PKCS12 nesting exceeds8 levels")
	}
	bags, err := p12Sequence(data)
	if err != nil {
		return err
	}
	for len(bags) > 0 {
		d.bags++
		if d.bags > 256 {
			return errors.New("PKCS12 exceeds256 bags")
		}
		var bag p12Bag
		bags, err = asn1.Unmarshal(bags, &bag)
		if err != nil {
			return errors.New("invalid PKCS12 bag")
		}
		switch bag.Type.String() {
		case "1.2.840.113549.1.12.10.1.1", "1.2.840.113549.1.12.10.1.2":
			if d.key != nil {
				return errors.New("PKCS12 must contain exactly one private key")
			}
			key := bag.Value.Bytes
			if bag.Type[len(bag.Type)-1] == 2 {
				var info struct {
					Algorithm pkix.AlgorithmIdentifier
					Data      []byte
				}
				if err := p12ASN1(key, &info); err != nil {
					return err
				}
				var err error
				key, err = d.decrypt(info.Algorithm, info.Data)
				if err != nil {
					return err
				}
			}
			parsed, err := x509.ParsePKCS8PrivateKey(key)
			clear(key)
			if err != nil {
				return fmt.Errorf("PKCS12 private key: %w", err)
			}
			var ok bool
			d.key, ok = parsed.(crypto.Signer)
			if !ok {
				return errors.New("PKCS12 private key cannot sign TLS handshakes")
			}
		case "1.2.840.113549.1.12.10.1.3":
			var cert struct {
				Type asn1.ObjectIdentifier
				DER  []byte `asn1:"explicit,tag:0"`
			}
			if err := p12ASN1(bag.Value.Bytes, &cert); err != nil {
				return err
			}
			if cert.Type.String() != "1.2.840.113549.1.9.22.1" {
				return errors.New("PKCS12 requires X509 certificates")
			}
			parsed, err := x509.ParseCertificate(bytes.Clone(cert.DER))
			if err != nil {
				return err
			}
			if len(d.certs) == 64 {
				return errors.New("PKCS12 exceeds64 certificates")
			}
			d.certs = append(d.certs, parsed)
		case "1.2.840.113549.1.12.10.1.6":
			if err := d.safe(bag.Value.Bytes, depth+1); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported PKCS12 bag %s", bag.Type)
		}
	}
	return nil
}

func decodePKCS12(data []byte, password string) (tls.Certificate, error) {
	var result tls.Certificate
	if len(data) == 0 || len(data) > pkcs12MaxSize || len(password) > 4096 || !utf8.ValidString(password) {
		return result, errors.New("invalid PKCS12 size or password encoding")
	}
	var pfx struct {
		Version int
		Safe    p12Content
		MAC     p12MAC `asn1:"optional"`
	}
	if err := p12ASN1(data, &pfx); err != nil {
		return result, err
	}
	if pfx.Version != 3 || pfx.Safe.Type.String() != "1.2.840.113549.1.7.1" || len(pfx.MAC.Digest.Value) == 0 {
		return result, errors.New("PKCS12 requires version3 password-authenticated data with a MAC")
	}
	var safe []byte
	if err := p12ASN1(pfx.Safe.Data.Bytes, &safe); err != nil {
		return result, err
	}
	defer clear(safe)
	d := p12Decoder{password: password}
	for _, c := range append(utf16.Encode([]rune(password)), 0) {
		d.unicode = binary.BigEndian.AppendUint16(d.unicode, c)
	}
	defer clear(d.unicode)
	if err := d.verifyMAC(pfx.MAC, safe); err != nil {
		if password != "" {
			return result, err
		}
		// Older exporters distinguish an empty password from a NULL password.
		d.unicode = nil
		if err = d.verifyMAC(pfx.MAC, safe); err != nil {
			return result, err
		}
	}
	contents, err := p12Sequence(safe)
	if err != nil {
		return result, err
	}
	for count := 0; len(contents) > 0; count++ {
		if count == 64 {
			return result, errors.New("PKCS12 exceeds64 safe contents")
		}
		var content p12Content
		contents, err = asn1.Unmarshal(contents, &content)
		if err != nil {
			return result, errors.New("invalid PKCS12 safe contents")
		}
		var plain []byte
		switch content.Type.String() {
		case "1.2.840.113549.1.7.1":
			if err := p12ASN1(content.Data.Bytes, &plain); err != nil {
				return result, err
			}
		case "1.2.840.113549.1.7.6":
			var encrypted struct {
				Version int
				Info    struct {
					Type      asn1.ObjectIdentifier
					Algorithm pkix.AlgorithmIdentifier
					Data      []byte `asn1:"tag:0"`
				}
			}
			if err := p12ASN1(content.Data.Bytes, &encrypted); err != nil {
				return result, err
			}
			if encrypted.Version != 0 || encrypted.Info.Type.String() != "1.2.840.113549.1.7.1" {
				return result, errors.New("unsupported PKCS12 encrypted content")
			}
			var err error
			plain, err = d.decrypt(encrypted.Info.Algorithm, encrypted.Info.Data)
			if err != nil {
				return result, err
			}
		default:
			return result, fmt.Errorf("unsupported PKCS12 content %s", content.Type)
		}
		err := d.safe(plain, 0)
		clear(plain)
		if err != nil {
			return result, err
		}
	}
	if d.key == nil {
		return result, errors.New("PKCS12 private key is missing")
	}
	public, err := x509.MarshalPKIXPublicKey(d.key.Public())
	if err != nil {
		return result, err
	}
	for _, cert := range d.certs {
		if bytes.Equal(public, cert.RawSubjectPublicKeyInfo) {
			if result.Leaf != nil && !bytes.Equal(result.Leaf.Raw, cert.Raw) {
				return result, errors.New("PKCS12 contains multiple identities for the private key")
			}
			result.Leaf = cert
		}
	}
	if result.Leaf == nil {
		return result, errors.New("PKCS12 certificate does not match private key")
	}
	result.PrivateKey = d.key
	current := result.Leaf
	seen := make(map[string]bool)
	for {
		seen[string(current.Raw)] = true
		result.Certificate = append(result.Certificate, current.Raw)
		var parent *x509.Certificate
		for _, cert := range d.certs {
			if !seen[string(cert.Raw)] && bytes.Equal(current.RawIssuer, cert.RawSubject) && current.CheckSignatureFrom(cert) == nil {
				parent = cert
				break
			}
		}
		if parent == nil {
			break
		}
		current = parent
	}
	return result, nil
}

func (o TLSOptions) pkcs12Identity(server bool) (*tls.Certificate, error) {
	if o.PKCS12 == "" && o.PKCS12Path == "" {
		if o.PKCS12Password != "" {
			return nil, errors.New("pkcs12_password requires pkcs12 or pkcs12_path")
		}
		return nil, nil
	}
	if o.PKCS12 != "" && o.PKCS12Path != "" {
		return nil, errors.New("pkcs12 and pkcs12_path are mutually exclusive")
	}
	if server && (len(o.Certificate)+len(o.Key) != 0 || o.CertificatePath != "" || o.KeyPath != "") ||
		!server && (len(o.ClientCertificate)+len(o.ClientKey)+len(o.ClientCertificatePath) != 0 || o.ClientKeyPath != "") {
		return nil, errors.New("PKCS12 identity conflicts with PEM identity")
	}
	var data []byte
	var err error
	if o.PKCS12Path != "" {
		f, e := os.Open(o.PKCS12Path)
		if e != nil {
			return nil, e
		}
		data, err = io.ReadAll(io.LimitReader(f, pkcs12MaxSize+1))
		f.Close()
	} else {
		if len(o.PKCS12) > base64.StdEncoding.EncodedLen(pkcs12MaxSize) {
			return nil, errors.New("PKCS12 exceeds16MiB")
		}
		data, err = base64.StdEncoding.Strict().DecodeString(o.PKCS12)
	}
	if err != nil {
		return nil, fmt.Errorf("TLS PKCS12: %w", err)
	}
	defer clear(data)
	pair, err := decodePKCS12(data, o.PKCS12Password)
	if err != nil {
		return nil, fmt.Errorf("TLS PKCS12: %w", err)
	}
	return &pair, nil
}
