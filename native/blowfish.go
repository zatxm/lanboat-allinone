package native

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
)

type blowfishBlock struct {
	p [18]uint32
	s [4][256]uint32
}

func (b *blowfishBlock) reset() {
	copy(b.p[:], blowfishInitial[:18])
	for i := range b.s {
		copy(b.s[i][:], blowfishInitial[18+i*256:18+(i+1)*256])
	}
}
func newBlowfish(key []byte) (*blowfishBlock, error) {
	if len(key) < 1 || len(key) > 56 {
		return nil, errors.New("Blowfish key must contain 1-56 bytes")
	}
	b := new(blowfishBlock)
	b.reset()
	b.expand(key, nil)
	return b, nil
}
func (b *blowfishBlock) f(v uint32) uint32 {
	return ((b.s[0][byte(v>>24)] + b.s[1][byte(v>>16)]) ^ b.s[2][byte(v>>8)]) + b.s[3][byte(v)]
}
func (b *blowfishBlock) enc(l, r uint32) (uint32, uint32) {
	for i := 0; i < 16; i += 2 {
		l ^= b.p[i]
		r ^= b.f(l) ^ b.p[i+1]
		l ^= b.f(r)
	}
	return r ^ b.p[17], l ^ b.p[16]
}
func (b *blowfishBlock) BlockSize() int { return 8 }
func (b *blowfishBlock) Encrypt(dst, src []byte) {
	l, r := b.enc(binary.BigEndian.Uint32(src[:4]), binary.BigEndian.Uint32(src[4:8]))
	binary.BigEndian.PutUint32(dst[:4], l)
	binary.BigEndian.PutUint32(dst[4:8], r)
}
func (b *blowfishBlock) Decrypt(dst, src []byte) {
	l, r := binary.BigEndian.Uint32(src[:4]), binary.BigEndian.Uint32(src[4:8])
	for i := 17; i > 1; i -= 2 {
		l ^= b.p[i]
		r ^= b.f(l) ^ b.p[i-1]
		l ^= b.f(r)
	}
	binary.BigEndian.PutUint32(dst[:4], r^b.p[0])
	binary.BigEndian.PutUint32(dst[4:8], l^b.p[1])
}
func blowfishWord(key []byte, pos *int) uint32 {
	var v uint32
	for range 4 {
		v = v<<8 | uint32(key[*pos])
		*pos = (*pos + 1) % len(key)
	}
	return v
}
func (b *blowfishBlock) expand(key, salt []byte) {
	pos := 0
	for i := range b.p {
		b.p[i] ^= blowfishWord(key, &pos)
	}
	l, r, pos := uint32(0), uint32(0), 0
	step := func() {
		if len(salt) != 0 {
			l ^= blowfishWord(salt, &pos)
			r ^= blowfishWord(salt, &pos)
		}
		l, r = b.enc(l, r)
	}
	for i := 0; i < len(b.p); i += 2 {
		step()
		b.p[i], b.p[i+1] = l, r
	}
	for i := range b.s {
		for j := 0; j < 256; j += 2 {
			step()
			b.s[i][j], b.s[i][j+1] = l, r
		}
	}
}
func bcryptHash(password, salt []byte) [32]byte {
	var b blowfishBlock
	b.reset()
	b.expand(password, salt)
	for range 64 {
		b.expand(salt, nil)
		b.expand(password, nil)
	}
	out := [32]byte{}
	copy(out[:], "OxychromaticBlowfishSwatDynamite")
	for i := 0; i < 32; i += 8 {
		l, r := binary.BigEndian.Uint32(out[i:i+4]), binary.BigEndian.Uint32(out[i+4:i+8])
		for range 64 {
			l, r = b.enc(l, r)
		}
		binary.LittleEndian.PutUint32(out[i:i+4], l)
		binary.LittleEndian.PutUint32(out[i+4:i+8], r)
	}
	return out
}

// OpenSSH bcrypt_pbkdf interleaves its output blocks rather than concatenating them.
func bcryptPBKDF(password, salt []byte, rounds, size int) ([]byte, error) {
	if len(password) == 0 || len(salt) == 0 || len(salt) > 1<<20 || rounds < 1 || rounds > 65536 || size < 1 || size > 1024 {
		return nil, errors.New("invalid OpenSSH bcrypt parameters")
	}
	p := sha512.Sum512(password)
	out := make([]byte, size)
	stride := (size + 31) / 32
	amt := (size + stride - 1) / stride
	for count := 1; count <= stride; count++ {
		h := sha512.New()
		h.Write(salt)
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(count)))
		u := bcryptHash(p[:], h.Sum(nil))
		v := u
		for i := 1; i < rounds; i++ {
			s := sha512.Sum512(u[:])
			u = bcryptHash(p[:], s[:])
			for j := range v {
				v[j] ^= u[j]
			}
		}
		for i := 0; i < amt; i++ {
			if pos := i*stride + count - 1; pos < size {
				out[pos] = v[i]
			}
		}
	}
	return out, nil
}
