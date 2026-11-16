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

func chachaRounds(s *[16]uint32, doubleRounds int) {
	quarter := func(a, b, c, d int) {
		s[a] += s[b]
		s[d] = bits.RotateLeft32(s[d]^s[a], 16)
		s[c] += s[d]
		s[b] = bits.RotateLeft32(s[b]^s[c], 12)
		s[a] += s[b]
		s[d] = bits.RotateLeft32(s[d]^s[a], 8)
		s[c] += s[d]
		s[b] = bits.RotateLeft32(s[b]^s[c], 7)
	}
	for range doubleRounds {
		quarter(0, 4, 8, 12)
		quarter(1, 5, 9, 13)
		quarter(2, 6, 10, 14)
		quarter(3, 7, 11, 15)
		quarter(0, 5, 10, 15)
		quarter(1, 6, 11, 12)
		quarter(2, 7, 8, 13)
		quarter(3, 4, 9, 14)
	}
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
	counter := uint32(1)
	for len(data) > 0 {
		block := chachaBlock(key, nonce, counter)
		counter++
		n := min(64, len(data))
		for i := range n {
			data[i] ^= block[i]
		}
		data = data[n:]
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

type polyState struct {
	r, h   [5]uint64
	pad    [16]byte
	buffer [16]byte
	used   int
}

func newPolyState(key []byte) polyState {
	var p polyState
	var clamped [24]byte
	copy(clamped[:16], key[:16])
	copy(p.pad[:], key[16:])
	for _, i := range []int{3, 7, 11, 15} {
		clamped[i] &= 15
	}
	for _, i := range []int{4, 8, 12} {
		clamped[i] &= 252
	}
	for i := range 5 {
		offset := i * 26
		p.r[i] = binary.LittleEndian.Uint64(clamped[offset/8:]) >> uint(offset%8) & 0x3ffffff
	}
	return p
}

func (p *polyState) block(data []byte) {
	var padded [24]byte
	copy(padded[:], data)
	padded[len(data)] = 1
	for i := range 5 {
		offset := i * 26
		p.h[i] += binary.LittleEndian.Uint64(padded[offset/8:]) >> uint(offset%8) & 0x3ffffff
	}
	var product [5]uint64
	for i := range 5 {
		for j := range 5 {
			k := i + j
			coefficient := uint64(1)
			if k >= 5 {
				k -= 5
				coefficient = 5
			}
			product[k] += p.h[i] * p.r[j] * coefficient
		}
	}
	for i := 0; i < 4; i++ {
		product[i+1] += product[i] >> 26
		p.h[i] = product[i] & 0x3ffffff
	}
	p.h[4] = product[4] & 0x3ffffff
	p.h[0] += (product[4] >> 26) * 5
	p.h[1] += p.h[0] >> 26
	p.h[0] &= 0x3ffffff
}

func (p *polyState) write(data []byte) {
	if p.used > 0 {
		n := copy(p.buffer[p.used:], data)
		p.used += n
		data = data[n:]
		if p.used == 16 {
			p.block(p.buffer[:])
			p.used = 0
		}
	}
	for len(data) >= 16 {
		p.block(data[:16])
		data = data[16:]
	}
	if len(data) > 0 {
		p.used = copy(p.buffer[:], data)
	}
}

func (p *polyState) sum() [16]byte {
	if p.used > 0 {
		p.block(p.buffer[:p.used])
	}
	for range 2 {
		for i := 0; i < 4; i++ {
			p.h[i+1] += p.h[i] >> 26
			p.h[i] &= 0x3ffffff
		}
		p.h[0] += (p.h[4] >> 26) * 5
		p.h[4] &= 0x3ffffff
	}
	var reduced [5]uint64
	carry := uint64(5)
	for i := range 5 {
		value := p.h[i] + carry
		reduced[i] = value & 0x3ffffff
		carry = value >> 26
	}
	mask := uint64(0) - carry
	for i := range 5 {
		p.h[i] = p.h[i]&^mask | reduced[i]&mask
	}
	lo := p.h[0] | p.h[1]<<26 | p.h[2]<<52
	hi := p.h[2]>>12 | p.h[3]<<14 | p.h[4]<<40
	lo, carry = bits.Add64(lo, binary.LittleEndian.Uint64(p.pad[:8]), 0)
	hi, _ = bits.Add64(hi, binary.LittleEndian.Uint64(p.pad[8:]), carry)
	var tag [16]byte
	binary.LittleEndian.PutUint64(tag[:8], lo)
	binary.LittleEndian.PutUint64(tag[8:], hi)
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
