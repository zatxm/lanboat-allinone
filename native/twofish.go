package native

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

type twofishBlock struct {
	keys  [40]uint32
	table [4][256]uint32
}

var twofishNibbles = [2][4][16]byte{
	{{8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4}, {14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13}, {11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1}, {13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10}},
	{{2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5}, {1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8}, {4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15}, {11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10}},
}

func twofishQ(which int, x byte) byte {
	t := &twofishNibbles[which]
	a, b := x>>4, x&15
	a, b = a^b, a^(b>>1|b<<3)&15^(a<<3)&8
	a, b = t[0][a], t[1][b]
	a, b = a^b, a^(b>>1|b<<3)&15^(a<<3)&8
	return t[2][a] | t[3][b]<<4
}

func finiteByte(a, b byte, polynomial uint16) byte {
	var result byte
	for b != 0 {
		if b&1 != 0 {
			result ^= a
		}
		v := uint16(a) << 1
		if v&256 != 0 {
			v ^= polynomial
		}
		a, b = byte(v), b>>1
	}
	return result
}

func twofishSub(x uint32, key []uint32) [4]byte {
	v := [4]byte{byte(x), byte(x >> 8), byte(x >> 16), byte(x >> 24)}
	if len(key) == 4 {
		for i, q := range [4]int{1, 0, 0, 1} {
			v[i] = twofishQ(q, v[i]) ^ byte(key[3]>>uint(8*i))
		}
	}
	if len(key) >= 3 {
		for i, q := range [4]int{1, 1, 0, 0} {
			v[i] = twofishQ(q, v[i]) ^ byte(key[2]>>uint(8*i))
		}
	}
	for i := range 4 {
		inner, middle, outer := [4]int{0, 1, 0, 1}[i], [4]int{0, 0, 1, 1}[i], [4]int{1, 0, 1, 0}[i]
		v[i] = twofishQ(outer, twofishQ(middle, twofishQ(inner, v[i])^byte(key[1]>>uint(8*i)))^byte(key[0]>>uint(8*i)))
	}
	return v
}

func twofishMDS(v [4]byte) uint32 {
	matrix := [4][4]byte{{1, 0xef, 0x5b, 0x5b}, {0x5b, 0xef, 0xef, 1}, {0xef, 0x5b, 1, 0xef}, {0xef, 1, 0xef, 0x5b}}
	var out uint32
	for row := range 4 {
		var b byte
		for col := range 4 {
			b ^= finiteByte(v[col], matrix[row][col], 0x169)
		}
		out |= uint32(b) << uint(8*row)
	}
	return out
}

func newTwofish(key []byte) (*twofishBlock, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("Twofish key must be16,24 or32 bytes")
	}
	var even, odd, s [4]uint32
	k := len(key) / 8
	rs := [4][8]byte{{1, 0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e}, {0xa4, 0x56, 0x82, 0xf3, 0x1e, 0xc6, 0x68, 0xe5}, {2, 0xa1, 0xfc, 0xc1, 0x47, 0xae, 0x3d, 0x19}, {0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e, 3}}
	for i := range k {
		even[i], odd[i] = binary.LittleEndian.Uint32(key[8*i:]), binary.LittleEndian.Uint32(key[8*i+4:])
		for row := range 4 {
			var b byte
			for col := range 8 {
				b ^= finiteByte(rs[row][col], key[8*i+col], 0x14d)
			}
			s[k-i-1] |= uint32(b) << uint(8*row)
		}
	}
	c := new(twofishBlock)
	for i := range 20 {
		a := twofishMDS(twofishSub(uint32(2*i)*0x01010101, even[:k]))
		b := bits.RotateLeft32(twofishMDS(twofishSub(uint32(2*i+1)*0x01010101, odd[:k])), 8)
		c.keys[2*i], c.keys[2*i+1] = a+b, bits.RotateLeft32(a+2*b, 9)
	}
	for i := range 256 {
		v := twofishSub(uint32(i)*0x01010101, s[:k])
		for col := range 4 {
			var one [4]byte
			one[col] = v[col]
			c.table[col][i] = twofishMDS(one)
		}
	}
	return c, nil
}

func (c *twofishBlock) BlockSize() int { return 16 }
func (c *twofishBlock) g(x uint32) uint32 {
	return c.table[0][byte(x)] ^ c.table[1][byte(x>>8)] ^ c.table[2][byte(x>>16)] ^ c.table[3][byte(x>>24)]
}
func (c *twofishBlock) Encrypt(dst, src []byte) {
	a, b, d, e := binary.LittleEndian.Uint32(src)^c.keys[0], binary.LittleEndian.Uint32(src[4:])^c.keys[1], binary.LittleEndian.Uint32(src[8:])^c.keys[2], binary.LittleEndian.Uint32(src[12:])^c.keys[3]
	for r := range 8 {
		x, y := c.g(a), c.g(bits.RotateLeft32(b, 8))
		d = bits.RotateLeft32(d^(x+y+c.keys[8+4*r]), -1)
		e = bits.RotateLeft32(e, 1) ^ (x + 2*y + c.keys[9+4*r])
		x, y = c.g(d), c.g(bits.RotateLeft32(e, 8))
		a = bits.RotateLeft32(a^(x+y+c.keys[10+4*r]), -1)
		b = bits.RotateLeft32(b, 1) ^ (x + 2*y + c.keys[11+4*r])
	}
	for i, v := range [4]uint32{d, e, a, b} {
		binary.LittleEndian.PutUint32(dst[4*i:], v^c.keys[4+i])
	}
}
func (c *twofishBlock) Decrypt(dst, src []byte) {
	d, e, a, b := binary.LittleEndian.Uint32(src)^c.keys[4], binary.LittleEndian.Uint32(src[4:])^c.keys[5], binary.LittleEndian.Uint32(src[8:])^c.keys[6], binary.LittleEndian.Uint32(src[12:])^c.keys[7]
	for r := 7; r >= 0; r-- {
		x, y := c.g(d), c.g(bits.RotateLeft32(e, 8))
		a = bits.RotateLeft32(a, 1) ^ (x + y + c.keys[10+4*r])
		b = bits.RotateLeft32(b^(x+2*y+c.keys[11+4*r]), -1)
		x, y = c.g(a), c.g(bits.RotateLeft32(b, 8))
		d = bits.RotateLeft32(d, 1) ^ (x + y + c.keys[8+4*r])
		e = bits.RotateLeft32(e^(x+2*y+c.keys[9+4*r]), -1)
	}
	for i, v := range [4]uint32{a, b, d, e} {
		binary.LittleEndian.PutUint32(dst[4*i:], v^c.keys[i])
	}
}
