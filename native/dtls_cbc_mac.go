package native

import (
	"crypto/subtle"
	"encoding/binary"
	"math/bits"
)

// MtE hides the padding-derived message length: all hash blocks and MAC reads
// depend only on the public record size (FIPS180-4, RFC5246 section6.2.3.2).
type ocCBCMAC struct {
	size         int
	inner, outer ocCBCDigest
}

type ocCBCDigest [8]uint64

func ocCBCUnpad(plain []byte, mac *ocCBCMAC, prefix []byte) ([]byte, bool) {
	if len(plain) == 0 {
		return nil, false
	}
	size := 0
	if mac != nil {
		size = mac.size
	}
	pad := int(plain[len(plain)-1])
	good := subtle.ConstantTimeLessOrEq(pad+1, len(plain))
	for i := range min(256, len(plain)) {
		x := subtle.ConstantTimeByteEq(plain[len(plain)-1-i], byte(pad))
		good &= subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(i, pad), x, 1)
	}
	n := len(plain) - pad - 1 - size
	valid := 1 ^ int(uint32(n)>>31)
	good &= valid
	n = subtle.ConstantTimeSelect(valid, n, 0)
	if mac != nil {
		var aad [13]byte
		copy(aad[:], prefix)
		binary.BigEndian.PutUint16(aad[11:], uint16(n))
		expected := mac.sum(aad[:], plain, n)
		var tag [48]byte
		for p := range max(0, min(256, len(plain)-size)) {
			mask := byte(-subtle.ConstantTimeEq(int32(p), int32(pad)))
			for j := range size {
				tag[j] |= plain[len(plain)-size-1-p+j] & mask
			}
		}
		good &= subtle.ConstantTimeCompare(expected[:size], tag[:size])
	}
	good &= subtle.ConstantTimeLessOrEq(n, 16384)
	if good != 1 {
		clear(plain)
		return nil, false
	}
	return plain[:n], true
}

func newOCCBCMAC(key []byte, size int) ocCBCMAC {
	m := ocCBCMAC{size: size}
	switch size {
	case 20:
		m.inner = ocCBCDigest{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}
	case 32:
		m.inner = ocCBCDigest{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
	case 48:
		m.inner = ocCBCDigest{0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4}
	}
	m.outer = m.inner
	var block [128]byte
	n := m.blockSize()
	for i := range n {
		block[i] = 0x36
		if i < len(key) {
			block[i] ^= key[i]
		}
	}
	m.inner.block(block[:n], size)
	for i := range n {
		block[i] ^= 0x36 ^ 0x5c
	}
	m.outer.block(block[:n], size)
	clear(block[:])
	return m
}

func (m *ocCBCMAC) blockSize() int {
	if m.size == 48 {
		return 128
	}
	return 64
}

func (m *ocCBCMAC) sum(aad, plain []byte, contentLen int) [48]byte {
	n, lengthBytes, shift := m.blockSize(), 8, 6
	if m.size == 48 {
		lengthBytes, shift = 16, 7
	}
	end := len(aad) + contentLen
	last := ((end + 1 + lengthBytes + n - 1) >> shift) - 1
	blocks := (len(aad) + len(plain) + 1 + lengthBytes + n - 1) >> shift
	h, selected := m.inner, ocCBCDigest{}
	var block [128]byte
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(n+end)*8)
	for k := range blocks {
		final := subtle.ConstantTimeEq(int32(k), int32(last))
		for j := range n {
			i, value := k*n+j, byte(0)
			if i < len(aad) {
				value = aad[i]
			} else if i-len(aad) < len(plain) {
				value = plain[i-len(aad)]
			}
			value &= byte(-subtle.ConstantTimeLessOrEq(i+1, end))
			value |= byte(0x80 * subtle.ConstantTimeEq(int32(i), int32(end)))
			if j >= n-8 {
				value |= length[j-(n-8)] & byte(-final)
			}
			block[j] = value
		}
		h.block(block[:n], m.size)
		mask := uint64(0) - uint64(final)
		for j := range selected {
			selected[j] = selected[j]&^mask | h[j]&mask
		}
	}
	var digest [48]byte
	selected.put(digest[:], m.size)
	clear(block[:])
	copy(block[:], digest[:m.size])
	block[m.size] = 0x80
	binary.BigEndian.PutUint64(block[n-8:n], uint64(n+m.size)*8)
	h = m.outer
	h.block(block[:n], m.size)
	h.put(digest[:], m.size)
	return digest
}

func (h *ocCBCDigest) put(b []byte, size int) {
	if size == 48 {
		for i := range 6 {
			binary.BigEndian.PutUint64(b[i*8:], h[i])
		}
	} else {
		for i := range size / 4 {
			binary.BigEndian.PutUint32(b[i*4:], uint32(h[i]))
		}
	}
}

func (h *ocCBCDigest) block(b []byte, size int) {
	switch size {
	case 20:
		var w [80]uint32
		for i := range 16 {
			w[i] = binary.BigEndian.Uint32(b[i*4:])
		}
		for i := 16; i < 80; i++ {
			w[i] = bits.RotateLeft32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)
		}
		a, b, c, d, e := uint32(h[0]), uint32(h[1]), uint32(h[2]), uint32(h[3]), uint32(h[4])
		for i := range 80 {
			var f, k uint32
			switch {
			case i < 20:
				f, k = (b&c)|(^b&d), 0x5a827999
			case i < 40:
				f, k = b^c^d, 0x6ed9eba1
			case i < 60:
				f, k = (b&c)|(b&d)|(c&d), 0x8f1bbcdc
			default:
				f, k = b^c^d, 0xca62c1d6
			}
			a, b, c, d, e = bits.RotateLeft32(a, 5)+f+e+k+w[i], a, bits.RotateLeft32(b, 30), c, d
		}
		for i, v := range [5]uint32{a, b, c, d, e} {
			h[i] = uint64(uint32(h[i]) + v)
		}
	case 32:
		var w [64]uint32
		for i := range 16 {
			w[i] = binary.BigEndian.Uint32(b[i*4:])
		}
		for i := 16; i < 64; i++ {
			x, y := w[i-15], w[i-2]
			w[i] = w[i-16] + (bits.RotateLeft32(x, -7) ^ bits.RotateLeft32(x, -18) ^ x>>3) + w[i-7] + (bits.RotateLeft32(y, -17) ^ bits.RotateLeft32(y, -19) ^ y>>10)
		}
		a, b, c, d, e, f, g, v := uint32(h[0]), uint32(h[1]), uint32(h[2]), uint32(h[3]), uint32(h[4]), uint32(h[5]), uint32(h[6]), uint32(h[7])
		for i := range 64 {
			t1 := v + (bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)) + (e&f ^ ^e&g) + ocCBCSHA256K[i] + w[i]
			t2 := (bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)) + (a&b ^ a&c ^ b&c)
			a, b, c, d, e, f, g, v = t1+t2, a, b, c, d+t1, e, f, g
		}
		for i, v := range [8]uint32{a, b, c, d, e, f, g, v} {
			h[i] = uint64(uint32(h[i]) + v)
		}
	case 48:
		var w [80]uint64
		for i := range 16 {
			w[i] = binary.BigEndian.Uint64(b[i*8:])
		}
		for i := 16; i < 80; i++ {
			x, y := w[i-15], w[i-2]
			w[i] = w[i-16] + (bits.RotateLeft64(x, -1) ^ bits.RotateLeft64(x, -8) ^ x>>7) + w[i-7] + (bits.RotateLeft64(y, -19) ^ bits.RotateLeft64(y, -61) ^ y>>6)
		}
		a, b, c, d, e, f, g, v := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
		for i := range 80 {
			t1 := v + (bits.RotateLeft64(e, -14) ^ bits.RotateLeft64(e, -18) ^ bits.RotateLeft64(e, -41)) + (e&f ^ ^e&g) + ocCBCSHA512K[i] + w[i]
			t2 := (bits.RotateLeft64(a, -28) ^ bits.RotateLeft64(a, -34) ^ bits.RotateLeft64(a, -39)) + (a&b ^ a&c ^ b&c)
			a, b, c, d, e, f, g, v = t1+t2, a, b, c, d+t1, e, f, g
		}
		for i, v := range [8]uint64{a, b, c, d, e, f, g, v} {
			h[i] += v
		}
	}
}

var ocCBCSHA256K = [...]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

var ocCBCSHA512K = [...]uint64{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
}
