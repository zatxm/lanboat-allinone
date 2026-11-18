package native

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"
)

type chachaAEAD struct {
	key      [32]byte
	extended bool
}

func newChaChaAEAD(key []byte, extended bool) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("ChaCha20 requires a 32-byte key")
	}
	c := &chachaAEAD{extended: extended}
	copy(c.key[:], key)
	return c, nil
}
func (c *chachaAEAD) NonceSize() int {
	if c.extended {
		return 24
	}
	return 12
}
func (*chachaAEAD) Overhead() int { return 16 }

func chachaState(key *[32]byte) [16]uint32 {
	s := [16]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}
	for i := range 8 {
		s[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	return s
}

func chachaQuarter(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d = bits.RotateLeft32(d^a, 16)
	c += d
	b = bits.RotateLeft32(b^c, 12)
	a += b
	d = bits.RotateLeft32(d^a, 8)
	c += d
	b = bits.RotateLeft32(b^c, 7)
	return a, b, c, d
}

// chachaRounds keeps the state in locals so the compiler can hold it in registers.
func chachaRounds(s *[16]uint32, doubleRounds int) {
	x0, x1, x2, x3 := s[0], s[1], s[2], s[3]
	x4, x5, x6, x7 := s[4], s[5], s[6], s[7]
	x8, x9, x10, x11 := s[8], s[9], s[10], s[11]
	x12, x13, x14, x15 := s[12], s[13], s[14], s[15]
	for range doubleRounds {
		x0, x4, x8, x12 = chachaQuarter(x0, x4, x8, x12)
		x1, x5, x9, x13 = chachaQuarter(x1, x5, x9, x13)
		x2, x6, x10, x14 = chachaQuarter(x2, x6, x10, x14)
		x3, x7, x11, x15 = chachaQuarter(x3, x7, x11, x15)
		x0, x5, x10, x15 = chachaQuarter(x0, x5, x10, x15)
		x1, x6, x11, x12 = chachaQuarter(x1, x6, x11, x12)
		x2, x7, x8, x13 = chachaQuarter(x2, x7, x8, x13)
		x3, x4, x9, x14 = chachaQuarter(x3, x4, x9, x14)
	}
	s[0], s[1], s[2], s[3] = x0, x1, x2, x3
	s[4], s[5], s[6], s[7] = x4, x5, x6, x7
	s[8], s[9], s[10], s[11] = x8, x9, x10, x11
	s[12], s[13], s[14], s[15] = x12, x13, x14, x15
}

func chachaBlock(key *[32]byte, nonce []byte, counter uint32) [64]byte {
	s := chachaState(key)
	s[12] = counter
	for i := range 3 {
		s[13+i] = binary.LittleEndian.Uint32(nonce[i*4:])
	}
	working := s
	chachaRounds(&working, 10)
	var block [64]byte
	for i := range s {
		binary.LittleEndian.PutUint32(block[i*4:], working[i]+s[i])
	}
	return block
}

func hchacha(key *[32]byte, nonce []byte) [32]byte {
	s := chachaState(key)
	for i := range 4 {
		s[12+i] = binary.LittleEndian.Uint32(nonce[i*4:])
	}
	chachaRounds(&s, 10)
	var subkey [32]byte
	for i, word := range []uint32{s[0], s[1], s[2], s[3], s[12], s[13], s[14], s[15]} {
		binary.LittleEndian.PutUint32(subkey[i*4:], word)
	}
	return subkey
}

func chachaXOR(data []byte, key *[32]byte, nonce []byte) {
	s := chachaState(key)
	for i := range 3 {
		s[13+i] = binary.LittleEndian.Uint32(nonce[i*4:])
	}
	counter := uint32(1)
	// Whole blocks are XORed a word at a time.
	for len(data) >= 64 {
		s[12] = counter
		counter++
		working := s
		chachaRounds(&working, 10)
		block := (*[64]byte)(data)
		for i := range 16 {
			word := binary.LittleEndian.Uint32(block[i*4:]) ^ (working[i] + s[i])
			binary.LittleEndian.PutUint32(block[i*4:], word)
		}
		data = data[64:]
	}
	if len(data) > 0 {
		block := chachaBlock(key, nonce, counter)
		for i := range data {
			data[i] ^= block[i]
		}
	}
}

func (c *chachaAEAD) parameters(nonce []byte) ([32]byte, [12]byte) {
	if len(nonce) != c.NonceSize() {
		panic("invalid ChaCha20-Poly1305 nonce size")
	}
	key := c.key
	var iv [12]byte
	if c.extended {
		key = hchacha(&key, nonce[:16])
		copy(iv[4:], nonce[16:])
	} else {
		copy(iv[:], nonce)
	}
	return key, iv
}

func (c *chachaAEAD) Seal(dst, nonce, plaintext, aad []byte) []byte {
	if uint64(len(plaintext)) > (uint64(1)<<38)-64 {
		panic("ChaCha20 message exceeds counter limit")
	}
	key, iv := c.parameters(nonce)
	start := len(dst)
	dst = append(dst, plaintext...)
	chachaXOR(dst[start:], &key, iv[:])
	block := chachaBlock(&key, iv[:], 0)
	tag := chachaTag(dst[start:], aad, block[:32])
	return append(dst, tag[:]...)
}

func (c *chachaAEAD) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	key, iv := c.parameters(nonce)
	if len(ciphertext) < 16 || uint64(len(ciphertext)-16) > (uint64(1)<<38)-64 {
		return nil, errors.New("invalid ChaCha20 ciphertext size")
	}
	message := ciphertext[:len(ciphertext)-16]
	block := chachaBlock(&key, iv[:], 0)
	tag := chachaTag(message, aad, block[:32])
	if subtle.ConstantTimeCompare(tag[:], ciphertext[len(message):]) != 1 {
		return nil, errors.New("ChaCha20-Poly1305 authentication failed")
	}
	start := len(dst)
	dst = append(dst, message...)
	chachaXOR(dst[start:], &key, iv[:])
	return dst, nil
}

// polyState is Poly1305 over 2^130-5 with the accumulator in three 64-bit
// limbs (h2 holds the bits above 2^128) and the clamped r in two limbs.
type polyState struct {
	r0, r1     uint64
	s0, s1     uint64
	h0, h1, h2 uint64
	buffer     [16]byte
	used       int
}

func newPolyState(key []byte) polyState {
	return polyState{
		r0: binary.LittleEndian.Uint64(key[0:8]) & 0x0ffffffc0fffffff,
		r1: binary.LittleEndian.Uint64(key[8:16]) & 0x0ffffffc0ffffffc,
		s0: binary.LittleEndian.Uint64(key[16:24]),
		s1: binary.LittleEndian.Uint64(key[24:32]),
	}
}

// blocks absorbs whole 16-byte blocks. high is the 2^128 marker bit: 1 for
// full blocks, 0 for the final partial block whose marker is already padded in.
func (p *polyState) blocks(data []byte, high uint64) {
	h0, h1, h2 := p.h0, p.h1, p.h2
	r0, r1 := p.r0, p.r1
	for len(data) >= 16 {
		var c uint64
		h0, c = bits.Add64(h0, binary.LittleEndian.Uint64(data[0:8]), 0)
		h1, c = bits.Add64(h1, binary.LittleEndian.Uint64(data[8:16]), c)
		h2 += c + high
		data = data[16:]

		// h*r as 64-bit columns. Clamping keeps r below 2^60 and h2 stays at most
		// 7, so h2*r fits one limb and the column sums cannot overflow 128 bits.
		hi00, lo00 := bits.Mul64(h0, r0)
		hi10, lo10 := bits.Mul64(h1, r0)
		hi01, lo01 := bits.Mul64(h0, r1)
		hi11, lo11 := bits.Mul64(h1, r1)
		m1lo, c := bits.Add64(lo10, lo01, 0)
		m1hi := hi10 + hi01 + c
		m2lo, c := bits.Add64(h2*r0, lo11, 0)
		m2hi := hi11 + c

		t1, c := bits.Add64(m1lo, hi00, 0)
		t2, c := bits.Add64(m2lo, m1hi, c)
		t3 := h2*r1 + m2hi + c

		// Partial reduction with 2^130 = 5: fold the bits above 2^130 back in as
		// 4x (still shifted by two) plus x.
		h0, h1, h2 = lo00, t1, t2&3
		cLo, cHi := t2&^3, t3
		h0, c = bits.Add64(h0, cLo, 0)
		h1, c = bits.Add64(h1, cHi, c)
		h2 += c
		cLo, cHi = cLo>>2|cHi<<62, cHi>>2
		h0, c = bits.Add64(h0, cLo, 0)
		h1, c = bits.Add64(h1, cHi, c)
		h2 += c
	}
	p.h0, p.h1, p.h2 = h0, h1, h2
}

func (p *polyState) write(data []byte) {
	if p.used > 0 {
		n := copy(p.buffer[p.used:], data)
		p.used += n
		data = data[n:]
		if p.used < 16 {
			return
		}
		p.blocks(p.buffer[:], 1)
		p.used = 0
	}
	if full := len(data) &^ 15; full > 0 {
		p.blocks(data[:full], 1)
		data = data[full:]
	}
	if len(data) > 0 {
		p.used = copy(p.buffer[:], data)
	}
}

func (p *polyState) sum() [16]byte {
	if p.used > 0 {
		var last [16]byte
		copy(last[:], p.buffer[:p.used])
		last[p.used] = 1
		p.blocks(last[:], 0)
	}
	// h is below 2(2^130-5); subtract the prime once in constant time.
	t0, b := bits.Sub64(p.h0, 0xfffffffffffffffb, 0)
	t1, b := bits.Sub64(p.h1, 0xffffffffffffffff, b)
	_, b = bits.Sub64(p.h2, 3, b)
	keep := -b
	h0 := p.h0&keep | t0&^keep
	h1 := p.h1&keep | t1&^keep
	h0, c := bits.Add64(h0, p.s0, 0)
	h1, _ = bits.Add64(h1, p.s1, c)
	var tag [16]byte
	binary.LittleEndian.PutUint64(tag[:8], h0)
	binary.LittleEndian.PutUint64(tag[8:], h1)
	return tag
}

func chachaTag(ciphertext, aad, key []byte) [16]byte {
	p := newPolyState(key)
	var zeros [16]byte
	p.write(aad)
	p.write(zeros[:(-len(aad))&15])
	p.write(ciphertext)
	p.write(zeros[:(-len(ciphertext))&15])
	var sizes [16]byte
	binary.LittleEndian.PutUint64(sizes[:8], uint64(len(aad)))
	binary.LittleEndian.PutUint64(sizes[8:], uint64(len(ciphertext)))
	p.write(sizes[:])
	return p.sum()
}
