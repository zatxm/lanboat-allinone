package native

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

type seedCipher [16][2]uint32

func seedG(x uint32) uint32 {
	return seedSS0[byte(x)] ^ seedSS1[byte(x>>8)] ^
		bits.RotateLeft32(seedSS0[byte(x>>16)], 16) ^ bits.RotateLeft32(seedSS1[byte(x>>24)], 16)
}

func newSEED(key []byte) (*seedCipher, error) {
	if len(key) != 16 {
		return nil, errors.New("SEED requires a16-byte key")
	}
	a, b := binary.BigEndian.Uint32(key), binary.BigEndian.Uint32(key[4:])
	c, d := binary.BigEndian.Uint32(key[8:]), binary.BigEndian.Uint32(key[12:])
	k := new(seedCipher)
	for i := range k {
		constant := bits.RotateLeft32(0x9e3779b9, i)
		k[i] = [2]uint32{seedG(a + c - constant), seedG(b - d + constant)}
		if i&1 == 0 {
			a, b = a>>8|b<<24, b>>8|a<<24
		} else {
			c, d = c<<8|d>>24, d<<8|c>>24
		}
	}
	return k, nil
}

func (k *seedCipher) crypt(dst, src []byte, decrypt bool) {
	a, b := binary.BigEndian.Uint32(src), binary.BigEndian.Uint32(src[4:])
	c, d := binary.BigEndian.Uint32(src[8:]), binary.BigEndian.Uint32(src[12:])
	for i := range k {
		p := i
		if decrypt {
			p = 15 - i
		}
		x, y := c^k[p][0], d^k[p][1]
		y = seedG(x ^ y)
		x = seedG(x + y)
		y = seedG(x + y)
		x += y
		a, b, c, d = c, d, a^x, b^y
	}
	binary.BigEndian.PutUint32(dst, c)
	binary.BigEndian.PutUint32(dst[4:], d)
	binary.BigEndian.PutUint32(dst[8:], a)
	binary.BigEndian.PutUint32(dst[12:], b)
}

func (*seedCipher) BlockSize() int            { return 16 }
func (k *seedCipher) Encrypt(dst, src []byte) { k.crypt(dst, src, false) }
func (k *seedCipher) Decrypt(dst, src []byte) { k.crypt(dst, src, true) }
