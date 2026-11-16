package native

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

type cast5Cipher struct {
	mask   [16]uint32
	rotate [16]uint8
	rounds int
}

func newCAST5(key []byte) (*cast5Cipher, error) {
	if len(key) < 5 || len(key) > 16 {
		return nil, errors.New("CAST5 requires a5-16-byte key")
	}
	c := &cast5Cipher{rounds: 16}
	if len(key) <= 10 {
		c.rounds = 12
	}
	var x, z [16]byte
	copy(x[:], key)
	// Index rows encode the four subkey equations for each schedule phase.
	indices := [4][4][5]uint8{
		{{8, 9, 7, 6, 2}, {10, 11, 5, 4, 6}, {12, 13, 3, 2, 9}, {14, 15, 1, 0, 12}},
		{{3, 2, 12, 13, 8}, {1, 0, 14, 15, 13}, {7, 6, 8, 9, 3}, {5, 4, 10, 11, 7}},
		{{3, 2, 12, 13, 9}, {1, 0, 14, 15, 12}, {7, 6, 8, 9, 2}, {5, 4, 10, 11, 6}},
		{{8, 9, 7, 6, 3}, {10, 11, 5, 4, 7}, {12, 13, 3, 2, 8}, {14, 15, 1, 0, 13}},
	}
	for half := range 2 {
		for phase := range 4 {
			v := &z
			if phase&1 == 0 {
				binary.BigEndian.PutUint32(z[:], binary.BigEndian.Uint32(x[:])^cast5S[4][x[13]]^cast5S[5][x[15]]^cast5S[6][x[12]]^cast5S[7][x[14]]^cast5S[6][x[8]])
				binary.BigEndian.PutUint32(z[4:], binary.BigEndian.Uint32(x[8:])^cast5S[4][z[0]]^cast5S[5][z[2]]^cast5S[6][z[1]]^cast5S[7][z[3]]^cast5S[7][x[10]])
				binary.BigEndian.PutUint32(z[8:], binary.BigEndian.Uint32(x[12:])^cast5S[4][z[7]]^cast5S[5][z[6]]^cast5S[6][z[5]]^cast5S[7][z[4]]^cast5S[4][x[9]])
				binary.BigEndian.PutUint32(z[12:], binary.BigEndian.Uint32(x[4:])^cast5S[4][z[10]]^cast5S[5][z[9]]^cast5S[6][z[11]]^cast5S[7][z[8]]^cast5S[5][x[11]])
			} else {
				binary.BigEndian.PutUint32(x[:], binary.BigEndian.Uint32(z[8:])^cast5S[4][z[5]]^cast5S[5][z[7]]^cast5S[6][z[4]]^cast5S[7][z[6]]^cast5S[6][z[0]])
				binary.BigEndian.PutUint32(x[4:], binary.BigEndian.Uint32(z[:])^cast5S[4][x[0]]^cast5S[5][x[2]]^cast5S[6][x[1]]^cast5S[7][x[3]]^cast5S[7][z[2]])
				binary.BigEndian.PutUint32(x[8:], binary.BigEndian.Uint32(z[4:])^cast5S[4][x[7]]^cast5S[5][x[6]]^cast5S[6][x[5]]^cast5S[7][x[4]]^cast5S[4][z[1]])
				binary.BigEndian.PutUint32(x[12:], binary.BigEndian.Uint32(z[12:])^cast5S[4][x[10]]^cast5S[5][x[9]]^cast5S[6][x[11]]^cast5S[7][x[8]]^cast5S[5][z[3]])
				v = &x
			}
			for i, row := range indices[phase] {
				k := cast5S[4][v[row[0]]] ^ cast5S[5][v[row[1]]] ^ cast5S[6][v[row[2]]] ^ cast5S[7][v[row[3]]] ^ cast5S[4+i][v[row[4]]]
				if half == 0 {
					c.mask[4*phase+i] = k
				} else {
					c.rotate[4*phase+i] = uint8(k & 31)
				}
			}
		}
	}
	clear(x[:])
	clear(z[:])
	return c, nil
}

func (c *cast5Cipher) crypt(dst, src []byte, decrypt bool) {
	l, r := binary.BigEndian.Uint32(src), binary.BigEndian.Uint32(src[4:])
	for i := range c.rounds {
		p := i
		if decrypt {
			p = c.rounds - 1 - i
		}
		x := c.mask[p]
		switch p % 3 {
		case 0:
			x += r
		case 1:
			x ^= r
		case 2:
			x -= r
		}
		x = bits.RotateLeft32(x, int(c.rotate[p]))
		a, b, d, e := cast5S[0][byte(x>>24)], cast5S[1][byte(x>>16)], cast5S[2][byte(x>>8)], cast5S[3][byte(x)]
		var f uint32
		switch p % 3 {
		case 0:
			f = (a ^ b) - d + e
		case 1:
			f = (a - b + d) ^ e
		case 2:
			f = ((a + b) ^ d) - e
		}
		l, r = r, l^f
	}
	binary.BigEndian.PutUint32(dst, r)
	binary.BigEndian.PutUint32(dst[4:], l)
}

func (*cast5Cipher) BlockSize() int            { return 8 }
func (c *cast5Cipher) Encrypt(dst, src []byte) { c.crypt(dst, src, false) }
func (c *cast5Cipher) Decrypt(dst, src []byte) { c.crypt(dst, src, true) }
