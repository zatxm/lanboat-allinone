package native

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

type camelliaCipher struct {
	whitening [4]uint64
	round     [24]uint64
	layer     [6]uint64
	rounds    int
}

func rotate128(a, b uint64, n uint) (uint64, uint64) {
	if n >= 64 {
		a, b, n = b, a, n-64
	}
	return a<<n | b>>(64-n), b<<n | a>>(64-n)
}

func newCamellia(key []byte) (*camelliaCipher, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("Camellia requires a16/24/32-byte key")
	}
	kl := [2]uint64{binary.BigEndian.Uint64(key), binary.BigEndian.Uint64(key[8:])}
	var kr [2]uint64
	if len(key) >= 24 {
		kr[0] = binary.BigEndian.Uint64(key[16:])
		kr[1] = ^kr[0]
	}
	if len(key) == 32 {
		kr[1] = binary.BigEndian.Uint64(key[24:])
	}
	a, b := kl[0]^kr[0], kl[1]^kr[1]
	b ^= camelliaF(a, 0xa09e667f3bcc908b)
	a ^= camelliaF(b, 0xb67ae8584caa73b2)
	a, b = a^kl[0], b^kl[1]
	b ^= camelliaF(a, 0xc6ef372fe94f82be)
	a ^= camelliaF(b, 0x54ff53a5f1d36f1c)
	ka := [2]uint64{a, b}
	a, b = a^kr[0], b^kr[1]
	b ^= camelliaF(a, 0x10e527fade682d1d)
	a ^= camelliaF(b, 0xb05688c2b3e6c1fd)
	kb := [2]uint64{a, b}
	c := &camelliaCipher{rounds: 18}
	c.whitening[0], c.whitening[1] = kl[0], kl[1]
	pair := func(dst []uint64, k [2]uint64, shift uint) {
		dst[0], dst[1] = rotate128(k[0], k[1], shift)
	}
	if len(key) == 16 {
		pair(c.round[:], ka, 0)
		pair(c.round[2:], kl, 15)
		pair(c.round[4:], ka, 15)
		pair(c.layer[:], ka, 30)
		pair(c.round[6:], kl, 45)
		c.round[8], _ = rotate128(ka[0], ka[1], 45)
		_, c.round[9] = rotate128(kl[0], kl[1], 60)
		pair(c.round[10:], ka, 60)
		pair(c.layer[2:], kl, 77)
		pair(c.round[12:], kl, 94)
		pair(c.round[14:], ka, 94)
		pair(c.round[16:], kl, 111)
		pair(c.whitening[2:], ka, 111)
	} else {
		c.rounds = 24
		pair(c.round[:], kb, 0)
		pair(c.round[2:], kr, 15)
		pair(c.round[4:], ka, 15)
		pair(c.layer[:], kr, 30)
		pair(c.round[6:], kb, 30)
		pair(c.round[8:], kl, 45)
		pair(c.round[10:], ka, 45)
		pair(c.layer[2:], kl, 60)
		pair(c.round[12:], kr, 60)
		pair(c.round[14:], kb, 60)
		pair(c.round[16:], kl, 77)
		pair(c.layer[4:], ka, 77)
		pair(c.round[18:], kr, 94)
		pair(c.round[20:], ka, 94)
		pair(c.round[22:], kl, 111)
		pair(c.whitening[2:], kb, 111)
	}
	return c, nil
}

func camelliaF(x, key uint64) uint64 {
	x ^= key
	a := camelliaSBox[byte(x>>56)]
	b := bits.RotateLeft8(camelliaSBox[byte(x>>48)], 1)
	c := bits.RotateLeft8(camelliaSBox[byte(x>>40)], -1)
	d := camelliaSBox[bits.RotateLeft8(byte(x>>32), 1)]
	e := bits.RotateLeft8(camelliaSBox[byte(x>>24)], 1)
	f := bits.RotateLeft8(camelliaSBox[byte(x>>16)], -1)
	g := camelliaSBox[bits.RotateLeft8(byte(x>>8), 1)]
	h := camelliaSBox[byte(x)]
	return uint64(a^c^d^f^g^h)<<56 | uint64(a^b^d^e^g^h)<<48 |
		uint64(a^b^c^e^f^h)<<40 | uint64(b^c^d^e^f^g)<<32 |
		uint64(a^b^f^g^h)<<24 | uint64(b^c^e^g^h)<<16 |
		uint64(c^d^e^f^h)<<8 | uint64(a^d^e^f^g)
}

func camelliaLayer(x, key uint64, inverse bool) uint64 {
	a, b, k, l := uint32(x>>32), uint32(x), uint32(key>>32), uint32(key)
	if inverse {
		a ^= b | l
		b ^= bits.RotateLeft32(a&k, 1)
	} else {
		b ^= bits.RotateLeft32(a&k, 1)
		a ^= b | l
	}
	return uint64(a)<<32 | uint64(b)
}

func (c *camelliaCipher) crypt(dst, src []byte, decrypt bool) {
	w := 0
	if decrypt {
		w = 2
	}
	a, b := binary.BigEndian.Uint64(src)^c.whitening[w], binary.BigEndian.Uint64(src[8:])^c.whitening[w+1]
	for i := 0; i < c.rounds; i += 2 {
		p, q := i, i+1
		if decrypt {
			p, q = c.rounds-1-i, c.rounds-2-i
		}
		b ^= camelliaF(a, c.round[p])
		a ^= camelliaF(b, c.round[q])
		if (i+2)%6 == 0 && i+2 < c.rounds {
			p, q = (i+2)/3-2, (i+2)/3-1
			if decrypt {
				p, q = c.rounds/3-3-p, c.rounds/3-3-q
			}
			a, b = camelliaLayer(a, c.layer[p], false), camelliaLayer(b, c.layer[q], true)
		}
	}
	w ^= 2
	binary.BigEndian.PutUint64(dst, b^c.whitening[w])
	binary.BigEndian.PutUint64(dst[8:], a^c.whitening[w+1])
}

func (*camelliaCipher) BlockSize() int            { return 16 }
func (c *camelliaCipher) Encrypt(dst, src []byte) { c.crypt(dst, src, false) }
func (c *camelliaCipher) Decrypt(dst, src []byte) { c.crypt(dst, src, true) }
