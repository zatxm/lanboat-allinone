package native

import (
	"encoding/binary"
	"math/bits"
)

var blake32IV = [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
var blake3Permutation = [16]byte{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}

func blake32Compress(h [8]uint32, m [16]uint32, counter uint64, size, flags uint32, three bool) [16]uint32 {
	var v [16]uint32
	copy(v[:8], h[:])
	copy(v[8:], blake32IV[:])
	rounds := 10
	if three {
		rounds = 7
		v[12], v[13], v[14], v[15] = uint32(counter), uint32(counter>>32), size, flags
	} else {
		v[12] ^= uint32(counter)
		v[13] ^= uint32(counter >> 32)
		v[14] ^= flags
	}
	mix := func(a, b, c, d int, x, y uint32) {
		v[a] += v[b] + x
		v[d] = bits.RotateLeft32(v[d]^v[a], -16)
		v[c] += v[d]
		v[b] = bits.RotateLeft32(v[b]^v[c], -12)
		v[a] += v[b] + y
		v[d] = bits.RotateLeft32(v[d]^v[a], -8)
		v[c] += v[d]
		v[b] = bits.RotateLeft32(v[b]^v[c], -7)
	}
	for r := 0; r < rounds; r++ {
		var words [16]uint32
		if three {
			words = m
		} else {
			for i, n := range blakeSchedule[r] {
				words[i] = m[n]
			}
		}
		for i := 0; i < 4; i++ {
			mix(i, i+4, i+8, i+12, words[2*i], words[2*i+1])
		}
		for i := 0; i < 4; i++ {
			mix(i, (i+1)%4+4, (i+2)%4+8, (i+3)%4+12, words[8+2*i], words[9+2*i])
		}
		if three {
			var next [16]uint32
			for i, n := range blake3Permutation {
				next[i] = m[n]
			}
			m = next
		}
	}
	for i := 0; i < 8; i++ {
		v[i] ^= v[i+8]
		v[i+8] ^= h[i]
		if !three {
			v[i] ^= h[i]
		}
	}
	return v
}
func blake32Words(b []byte) [16]uint32 {
	var block [64]byte
	copy(block[:], b)
	var m [16]uint32
	for i := range m {
		m[i] = binary.LittleEndian.Uint32(block[i*4:])
	}
	return m
}
func blake2s(data, key []byte, size int) []byte {
	if size < 1 || size > 32 || len(key) > 32 {
		panic("invalid BLAKE2s parameters")
	}
	h := blake32IV
	h[0] ^= 0x01010000 | uint32(len(key))<<8 | uint32(size)
	if len(key) > 0 {
		block := make([]byte, 64, len(data)+64)
		copy(block, key)
		data = append(block, data...)
	}
	var counter uint64
	for {
		n := min(64, len(data))
		counter += uint64(n)
		flags := uint32(0)
		if n == len(data) {
			flags = ^uint32(0)
		}
		out := blake32Compress(h, blake32Words(data[:n]), counter, 0, flags, false)
		copy(h[:], out[:8])
		data = data[n:]
		if len(data) == 0 {
			break
		}
	}
	var out [32]byte
	for i, v := range h {
		binary.LittleEndian.PutUint32(out[i*4:], v)
	}
	return out[:size]
}

type blake3Output struct {
	cv            [8]uint32
	words         [16]uint32
	counter       uint64
	length, flags uint32
}

func (o blake3Output) chain() [8]uint32 {
	v := blake32Compress(o.cv, o.words, o.counter, o.length, o.flags, true)
	var h [8]uint32
	copy(h[:], v[:8])
	return h
}
func blake3Chunk(data []byte, counter uint64, key [8]uint32, mode uint32) blake3Output {
	cv := key
	first := true
	for {
		n := min(64, len(data))
		flags := mode
		if first {
			flags |= 1
		}
		if n == len(data) {
			flags |= 2
		}
		o := blake3Output{cv: cv, words: blake32Words(data[:n]), counter: counter, length: uint32(n), flags: flags}
		if n == len(data) {
			return o
		}
		cv = o.chain()
		first = false
		data = data[n:]
	}
}
func blake3Parent(left, right, key [8]uint32, mode uint32) blake3Output {
	var words [16]uint32
	copy(words[:8], left[:])
	copy(words[8:], right[:])
	return blake3Output{cv: key, words: words, length: 64, flags: mode | 4}
}
func blake3Sum(data []byte) [32]byte {
	return blake3Hash(data, blake32IV, 0)
}

func blake3Derive(context string, material []byte) [32]byte {
	contextKey := blake3Hash([]byte(context), blake32IV, 32)
	var key [8]uint32
	for i := range key {
		key[i] = binary.LittleEndian.Uint32(contextKey[i*4:])
	}
	return blake3Hash(material, key, 64)
}

func blake3Hash(data []byte, key [8]uint32, mode uint32) [32]byte {
	var stack [64][8]uint32
	depth := 0
	counter := uint64(0)
	for len(data) > 1024 {
		cv := blake3Chunk(data[:1024], counter, key, mode).chain()
		counter++
		for n := counter; n&1 == 0; n >>= 1 {
			depth--
			cv = blake3Parent(stack[depth], cv, key, mode).chain()
		}
		stack[depth] = cv
		depth++
		data = data[1024:]
	}
	out := blake3Chunk(data, counter, key, mode)
	for depth > 0 {
		depth--
		out = blake3Parent(stack[depth], out.chain(), key, mode)
	}
	words := blake32Compress(out.cv, out.words, 0, out.length, out.flags|8, true)
	var sum [32]byte
	for i, v := range words[:8] {
		binary.LittleEndian.PutUint32(sum[i*4:], v)
	}
	return sum
}
