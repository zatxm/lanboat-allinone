package native

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"math/big"
	"math/bits"
)

type browserFFDHEGroup struct{ modulus, r2 []uint64 }
type browserFFDHE struct {
	group           *browserFFDHEGroup
	private, public []byte
}

func browserFFDHEParameters(hex string) *browserFFDHEGroup {
	p, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		panic("invalid FFDHE modulus")
	}
	size := (p.BitLen() + 63) / 64
	r2 := new(big.Int).Lsh(big.NewInt(1), uint(size*128))
	r2.Mod(r2, p)
	return &browserFFDHEGroup{modulus: browserFFDHEWords(p.FillBytes(make([]byte, size*8))), r2: browserFFDHEWords(r2.FillBytes(make([]byte, size*8)))}
}

func browserFFDHEWords(b []byte) []uint64 {
	v := make([]uint64, len(b)/8)
	for i := range v {
		v[i] = binary.BigEndian.Uint64(b[len(b)-(i+1)*8:])
	}
	return v
}

// Fixed loops and masked selection keep private exponents out of big.Int.
func (g *browserFFDHEGroup) multiply(out, a, b, work []uint64) {
	n := len(g.modulus)
	clear(work)
	add := func(start int, word uint64, source []uint64) {
		var carry uint64
		for j := range n {
			hi, lo := bits.Mul64(word, source[j])
			var c uint64
			lo, c = bits.Add64(lo, work[start+j], 0)
			hi += c
			lo, c = bits.Add64(lo, carry, 0)
			hi += c
			work[start+j], carry = lo, hi
		}
		var c uint64
		work[start+n], c = bits.Add64(work[start+n], carry, 0)
		for k := start + n + 1; k < len(work); k++ {
			work[k], c = bits.Add64(work[k], 0, c)
		}
	}
	for i := range n {
		add(i, a[i], b)
	}
	for i := range n {
		add(i, work[i], g.modulus)
	} // -p[0]^-1 mod2^64 is1.
	var borrow uint64
	for i := range n {
		out[i], borrow = bits.Sub64(work[n+i], g.modulus[i], borrow)
	}
	_, borrow = bits.Sub64(work[2*n], 0, borrow)
	mask := uint64(0) - borrow
	for i := range n {
		out[i] = out[i]&^mask | work[n+i]&mask
	}
}

func (g *browserFFDHEGroup) power(base, exponent []byte) []byte {
	n := len(g.modulus)
	work := make([]uint64, 2*n+2)
	one := make([]uint64, n)
	one[0] = 1
	a, b, square, product := make([]uint64, n), make([]uint64, n), make([]uint64, n), make([]uint64, n)
	g.multiply(a, one, g.r2, work)
	g.multiply(b, browserFFDHEWords(base), g.r2, work)
	for _, v := range exponent {
		for bit := 7; bit >= 0; bit-- {
			g.multiply(square, a, a, work)
			g.multiply(product, square, b, work)
			mask := uint64(0) - uint64(v>>uint(bit)&1)
			for i := range n {
				a[i] = product[i]&mask | square[i]&^mask
			}
		}
	}
	g.multiply(a, a, one, work)
	out := make([]byte, n*8)
	for i, v := range a {
		binary.BigEndian.PutUint64(out[len(out)-(i+1)*8:], v)
	}
	clear(a)
	clear(b)
	clear(square)
	clear(product)
	clear(work)
	return out
}

func newBrowserFFDHE(id tls.CurveID) (*browserFFDHE, error) {
	g := browserFFDHEGroups[id]
	if g == nil {
		return nil, errors.New("unsupported FFDHE group")
	}
	private := make([]byte, len(g.modulus))
	rand.Read(private)
	private[0] |= 0x80
	base := make([]byte, len(g.modulus)*8)
	base[len(base)-1] = 2
	return &browserFFDHE{group: g, private: private, public: g.power(base, private)}, nil
}

func (k *browserFFDHE) shared(peer []byte) ([]byte, error) {
	defer clear(k.private)
	n := len(k.group.modulus)
	if len(peer) != n*8 {
		return nil, errors.New("invalid FFDHE public key length")
	}
	words := browserFFDHEWords(peer)
	var borrow, nonzero uint64
	for i := range n {
		_, borrow = bits.Sub64(words[i], k.group.modulus[i], borrow)
		nonzero |= words[i]
	}
	small := nonzero == 0
	if words[0] <= 1 {
		small = true
		for _, v := range words[1:] {
			if v != 0 {
				small = false
			}
		}
	}
	minusOne := true
	for i, v := range k.group.modulus {
		want := v
		if i == 0 {
			want--
		}
		minusOne = minusOne && words[i] == want
	}
	if small || borrow == 0 || minusOne {
		return nil, errors.New("invalid FFDHE public key")
	}
	return k.group.power(peer, k.private), nil
}
