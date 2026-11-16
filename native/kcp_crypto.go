package native

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"hash/crc32"
)

type kcpCrypt struct {
	block  cipher.Block
	aead   cipher.AEAD
	key    [32]byte
	xor    []byte
	method string
}

func newKCPCrypt(method, password string) (*kcpCrypt, error) {
	key, err := pbkdf2.Key(sha1.New, password, []byte("kcp-go"), 4096, 32)
	if err != nil {
		return nil, err
	}
	c := &kcpCrypt{method: method}
	copy(c.key[:], key)
	switch method {
	case "none", "salsa20":
	case "xor":
		c.xor, err = pbkdf2.Key(sha1.New, string(key), []byte("sH3CIVoF#rWLtJo6"), 32, 1500)
	case "aes", "aes-128", "aes-192", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm":
		n := 32
		if method == "aes-128" || method == "aes-128-gcm" {
			n = 16
		}
		if method == "aes-192" || method == "aes-192-gcm" {
			n = 24
		}
		c.block, err = aes.NewCipher(key[:n])
		if err == nil && (method == "aes-128-gcm" || method == "aes-192-gcm" || method == "aes-256-gcm") {
			c.aead, err = cipher.NewGCM(c.block)
		}
	case "blowfish":
		c.block, err = newBlowfish(key)
	case "twofish":
		c.block, err = newTwofish(key)
	case "cast5":
		c.block, err = newCAST5(key[:16])
	case "3des":
		c.block, err = des.NewTripleDESCipher(key[:24])
	case "tea", "xtea":
		t := &kcpTEA{xtea: method == "xtea"}
		for i := range 4 {
			t.key[i] = binary.BigEndian.Uint32(key[4*i:])
		}
		c.block = t
	default:
		return nil, errors.New("unsupported kcptun encryption")
	}
	return c, err
}

func (c *kcpCrypt) overhead() int {
	if c.aead != nil {
		return c.aead.NonceSize() + c.aead.Overhead()
	}
	return 20
}
func (c *kcpCrypt) transform(b []byte, decrypt bool) {
	if c.method == "salsa20" {
		s := salsaStream{key: c.key}
		copy(s.nonce[:], b[:8])
		s.XORKeyStream(b[8:], b[8:])
		return
	}
	if c.method == "xor" {
		for i := range b {
			b[i] ^= c.xor[i]
		}
		return
	}
	if c.block != nil {
		iv := [16]byte{167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107}
		if decrypt {
			cipher.NewCFBDecrypter(c.block, iv[:c.block.BlockSize()]).XORKeyStream(b, b)
		} else {
			cipher.NewCFBEncrypter(c.block, iv[:c.block.BlockSize()]).XORKeyStream(b, b)
		}
	}
}
func (c *kcpCrypt) seal(payload []byte) []byte {
	if c.aead != nil {
		b := make([]byte, c.aead.NonceSize(), len(payload)+c.overhead())
		rand.Read(b)
		return c.aead.Seal(b, b, payload, nil)
	}
	b := make([]byte, 20+len(payload))
	rand.Read(b[:16])
	binary.LittleEndian.PutUint32(b[16:], crc32.ChecksumIEEE(payload))
	copy(b[20:], payload)
	c.transform(b, false)
	return b
}
func (c *kcpCrypt) open(b []byte) ([]byte, error) {
	if len(b) > 1500 || len(b) < c.overhead() {
		return nil, errors.New("invalid kcptun packet size")
	}
	if c.aead != nil {
		return c.aead.Open(b[c.aead.NonceSize():c.aead.NonceSize()], b[:c.aead.NonceSize()], b[c.aead.NonceSize():], nil)
	}
	c.transform(b, true)
	if binary.LittleEndian.Uint32(b[16:]) != crc32.ChecksumIEEE(b[20:]) {
		return nil, errors.New("kcptun checksum mismatch")
	}
	return b[20:], nil
}

type kcpTEA struct {
	key  [4]uint32
	xtea bool
}

func (*kcpTEA) BlockSize() int { return 8 }
func (c *kcpTEA) Encrypt(dst, src []byte) {
	a, b := binary.BigEndian.Uint32(src), binary.BigEndian.Uint32(src[4:])
	var sum uint32
	if c.xtea {
		for range 32 {
			a += ((b<<4 ^ b>>5) + b) ^ (sum + c.key[sum&3])
			sum += 0x9e3779b9
			b += ((a<<4 ^ a>>5) + a) ^ (sum + c.key[sum>>11&3])
		}
	} else {
		for range 8 {
			sum += 0x9e3779b9
			a += (b<<4 + c.key[0]) ^ (b + sum) ^ (b>>5 + c.key[1])
			b += (a<<4 + c.key[2]) ^ (a + sum) ^ (a>>5 + c.key[3])
		}
	}
	binary.BigEndian.PutUint32(dst, a)
	binary.BigEndian.PutUint32(dst[4:], b)
}
func (c *kcpTEA) Decrypt(dst, src []byte) {
	a, b := binary.BigEndian.Uint32(src), binary.BigEndian.Uint32(src[4:])
	delta := uint32(0x9e3779b9)
	if c.xtea {
		sum := delta * 32
		for range 32 {
			b -= ((a<<4 ^ a>>5) + a) ^ (sum + c.key[sum>>11&3])
			sum -= delta
			a -= ((b<<4 ^ b>>5) + b) ^ (sum + c.key[sum&3])
		}
	} else {
		sum := delta * 8
		for range 8 {
			b -= (a<<4 + c.key[2]) ^ (a + sum) ^ (a>>5 + c.key[3])
			a -= (b<<4 + c.key[0]) ^ (b + sum) ^ (b>>5 + c.key[1])
			sum -= delta
		}
	}
	binary.BigEndian.PutUint32(dst, a)
	binary.BigEndian.PutUint32(dst[4:], b)
}
