package native

import (
	"encoding/binary"
	"errors"
)

// IDEA's CFB mode uses the forward block operation in both directions.
type ideaCipher struct{ encrypt, decrypt [52]uint16 }

func newIDEA(key []byte) (*ideaCipher, error) {
	if len(key) != 16 {
		return nil, errors.New("IDEA requires a16-byte key")
	}
	c := new(ideaCipher)
	for i := range 8 {
		c.encrypt[i] = binary.BigEndian.Uint16(key[2*i:])
	}
	for i := 8; i < 52; i++ {
		a, b := i-7, i-6
		if i&7 == 6 {
			b = i - 14
		} else if i&7 == 7 {
			a, b = i-15, i-14
		}
		c.encrypt[i] = c.encrypt[a]<<9 | c.encrypt[b]>>7
	}
	for r := range 9 {
		p, q := 6*r, 48-6*r
		c.decrypt[p], c.decrypt[p+3] = ideaInverse(c.encrypt[q]), ideaInverse(c.encrypt[q+3])
		if r == 0 || r == 8 {
			c.decrypt[p+1], c.decrypt[p+2] = -c.encrypt[q+1], -c.encrypt[q+2]
		} else {
			c.decrypt[p+1], c.decrypt[p+2] = -c.encrypt[q+2], -c.encrypt[q+1]
		}
		if r < 8 {
			c.decrypt[p+4], c.decrypt[p+5] = c.encrypt[q-2], c.encrypt[q-1]
		}
	}
	return c, nil
}

func ideaMultiply(a, b uint16) uint16 {
	p := uint32(a) * uint32(b)
	if p == 0 {
		return 1 - a - b
	}
	lo, hi := uint16(p), uint16(p>>16)
	r := lo - hi
	if lo < hi {
		r++
	}
	return r
}

func ideaInverse(x uint16) uint16 {
	if x < 2 {
		return x
	}
	a, b, u, v := int64(65537), int64(x), int64(0), int64(1)
	for b != 0 {
		q := a / b
		a, b, u, v = b, a%b, v, u-q*v
	}
	if u < 0 {
		u += 65537
	}
	return uint16(u)
}

func ideaBlock(dst, src []byte, key *[52]uint16) {
	a, b := binary.BigEndian.Uint16(src), binary.BigEndian.Uint16(src[2:])
	c, d := binary.BigEndian.Uint16(src[4:]), binary.BigEndian.Uint16(src[6:])
	for p := 0; p < 48; p += 6 {
		a, b, c, d = ideaMultiply(a, key[p]), b+key[p+1], c+key[p+2], ideaMultiply(d, key[p+3])
		x := ideaMultiply(a^c, key[p+4])
		y := ideaMultiply(x+(b^d), key[p+5])
		a, b, c, d = a^y, c^y, b^(x+y), d^(x+y)
	}
	binary.BigEndian.PutUint16(dst, ideaMultiply(a, key[48]))
	binary.BigEndian.PutUint16(dst[2:], c+key[49])
	binary.BigEndian.PutUint16(dst[4:], b+key[50])
	binary.BigEndian.PutUint16(dst[6:], ideaMultiply(d, key[51]))
}

func (*ideaCipher) BlockSize() int            { return 8 }
func (c *ideaCipher) Encrypt(dst, src []byte) { ideaBlock(dst, src, &c.encrypt) }
func (c *ideaCipher) Decrypt(dst, src []byte) { ideaBlock(dst, src, &c.decrypt) }
