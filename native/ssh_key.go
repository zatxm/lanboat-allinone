package native

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"hash"
	"strings"
)

func sshDecryptPrivate(name, kdf string, options, encrypted, trailer []byte, password string) ([]byte, error) {
	if kdf != "bcrypt" || password == "" {
		return nil, errors.New("encrypted OpenSSH key requires private_key_passphrase and bcrypt KDF")
	}
	r := sshReader{b: options}
	salt, rounds := r.str(), r.u32()
	if r.err != nil || len(r.b) != 0 || len(salt) < 1 || len(salt) > 1024 {
		return nil, errors.New("invalid OpenSSH bcrypt options")
	}
	keySize, ivSize, blockSize := 0, 16, 16
	switch name {
	case "aes128-ctr", "aes128-cbc", "aes128-gcm@openssh.com":
		keySize = 16
	case "aes192-ctr", "aes192-cbc":
		keySize = 24
	case "aes256-ctr", "aes256-cbc", "aes256-gcm@openssh.com":
		keySize = 32
	case "3des-cbc":
		keySize, ivSize, blockSize = 24, 8, 8
	case "chacha20-poly1305@openssh.com":
		keySize, ivSize, blockSize = 64, 0, 8
	default:
		return nil, errors.New("unsupported OpenSSH private key cipher: " + name)
	}
	gcm := strings.Contains(name, "-gcm@")
	authenticated := gcm || name == "chacha20-poly1305@openssh.com"
	if gcm {
		ivSize = 12
	}
	if len(encrypted) == 0 || len(encrypted)%blockSize != 0 || (!authenticated && len(trailer) != 0) || (authenticated && len(trailer) != 16) {
		return nil, errors.New("invalid encrypted OpenSSH key size")
	}
	material, e := bcryptPBKDF([]byte(password), salt, int(rounds), keySize+ivSize)
	if e != nil {
		return nil, e
	}
	defer clear(material)
	if name == "chacha20-poly1305@openssh.com" {
		var key [32]byte
		copy(key[:], material[:32])
		var nonce [12]byte
		first := chachaBlock(&key, nonce[:], 0)
		mac := newPolyState(first[:32])
		mac.write(encrypted)
		tag := mac.sum()
		if subtle.ConstantTimeCompare(tag[:], trailer) != 1 {
			return nil, errors.New("SSH private key decryption failed")
		}
		plain := append([]byte(nil), encrypted...)
		chachaXOR(plain, &key, nonce[:])
		return plain, nil
	}
	var b cipher.Block
	if name == "3des-cbc" {
		b, e = des.NewTripleDESCipher(material[:keySize])
	} else {
		b, e = aes.NewCipher(material[:keySize])
	}
	if e != nil {
		return nil, e
	}
	iv := material[keySize:]
	plain := make([]byte, len(encrypted))
	switch {
	case gcm:
		a, err := cipher.NewGCM(b)
		if err != nil {
			return nil, err
		}
		plain, e = a.Open(plain[:0], iv, append(append([]byte(nil), encrypted...), trailer...), nil)
		if e != nil {
			return nil, errors.New("SSH private key decryption failed")
		}
	case strings.HasSuffix(name, "-ctr"):
		cipher.NewCTR(b, iv).XORKeyStream(plain, encrypted)
	default:
		cipher.NewCBCDecrypter(b, iv).CryptBlocks(plain, encrypted)
	}
	return plain, nil
}

func sshDecryptPKCS8(raw []byte, password string) ([]byte, error) {
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}
	rest, e := asn1.Unmarshal(raw, &info)
	if e != nil || len(rest) != 0 || !info.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}) {
		return nil, errors.New("SSH encrypted PKCS8 requires PBES2")
	}
	var pbes struct{ KDF, Cipher pkix.AlgorithmIdentifier }
	if rest, e = asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &pbes); e != nil || len(rest) != 0 || !pbes.KDF.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}) {
		return nil, errors.New("SSH encrypted PKCS8 requires PBKDF2")
	}
	var params struct {
		Salt       []byte
		Iterations int
		KeyLength  int                      `asn1:"optional"`
		PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
	}
	if rest, e = asn1.Unmarshal(pbes.KDF.Parameters.FullBytes, &params); e != nil || len(rest) != 0 || len(params.Salt) == 0 || len(params.Salt) > 1024 || params.Iterations < 1 || params.Iterations > 1000000 {
		return nil, errors.New("invalid SSH PKCS8 KDF parameters")
	}
	keySize := 0
	for _, v := range []struct {
		oid  asn1.ObjectIdentifier
		size int
	}{{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}, 16}, {asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}, 24}, {asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}, 32}} {
		if pbes.Cipher.Algorithm.Equal(v.oid) {
			keySize = v.size
		}
	}
	if keySize == 0 || params.KeyLength != 0 && params.KeyLength != keySize {
		return nil, errors.New("SSH PKCS8 requires AES-CBC")
	}
	var iv []byte
	if rest, e = asn1.Unmarshal(pbes.Cipher.Parameters.FullBytes, &iv); e != nil || len(rest) != 0 || len(iv) != 16 || len(info.Data) == 0 || len(info.Data)%16 != 0 {
		return nil, errors.New("invalid SSH PKCS8 cipher parameters")
	}
	var h func() hash.Hash
	switch params.PRF.Algorithm.String() {
	case "", "1.2.840.113549.2.7":
		h = sha1.New
	case "1.2.840.113549.2.9":
		h = sha256.New
	case "1.2.840.113549.2.10":
		h = sha512.New384
	case "1.2.840.113549.2.11":
		h = sha512.New
	default:
		return nil, errors.New("unsupported SSH PKCS8 PRF")
	}
	key, e := pbkdf2.Key(h, password, params.Salt, params.Iterations, keySize)
	if e != nil {
		return nil, e
	}
	defer clear(key)
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	plain := make([]byte, len(info.Data))
	cipher.NewCBCDecrypter(b, iv).CryptBlocks(plain, info.Data)
	n := int(plain[len(plain)-1])
	valid := subtle.ConstantTimeLessOrEq(1, n) & subtle.ConstantTimeLessOrEq(n, 16)
	for i := 1; i <= 16; i++ {
		valid &= subtle.ConstantTimeLessOrEq(n+1, i) | subtle.ConstantTimeByteEq(plain[len(plain)-i], byte(n))
	}
	if valid != 1 {
		clear(plain)
		return nil, errors.New("SSH private key decryption failed")
	}
	return plain[:len(plain)-n], nil
}
