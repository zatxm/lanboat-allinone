package native

import (
	"encoding/binary"
	"math/bits"
)

var blakeIV = [8]uint64{0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179}
var blakeSchedule = [10][16]byte{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

func blake2b(data []byte, size int) []byte {
	state := blakeIV
	state[0] ^= 0x01010000 | uint64(size)
	var count uint64
	for {
		n := min(len(data), 128)
		var block [128]byte
		copy(block[:], data[:n])
		data = data[n:]
		count += uint64(n)
		last := len(data) == 0
		var work [16]uint64
		copy(work[:8], state[:])
		copy(work[8:], blakeIV[:])
		work[12] ^= count
		if last {
			work[14] = ^work[14]
		}
		var words [16]uint64
		for i := range words {
			words[i] = binary.LittleEndian.Uint64(block[i*8:])
		}
		mix := func(a, b, c, d int, x, y uint64) {
			work[a] += work[b] + x
			work[d] = bits.RotateLeft64(work[d]^work[a], -32)
			work[c] += work[d]
			work[b] = bits.RotateLeft64(work[b]^work[c], -24)
			work[a] += work[b] + y
			work[d] = bits.RotateLeft64(work[d]^work[a], -16)
			work[c] += work[d]
			work[b] = bits.RotateLeft64(work[b]^work[c], -63)
		}
		for round := range 12 {
			s := blakeSchedule[round%10]
			for column := range 4 {
				mix(column, column+4, column+8, column+12, words[s[column*2]], words[s[column*2+1]])
			}
			for column := range 4 {
				mix(column, (column+1)%4+4, (column+2)%4+8, (column+3)%4+12, words[s[8+column*2]], words[s[9+column*2]])
			}
		}
		for i := range state {
			state[i] ^= work[i] ^ work[i+8]
		}
		if last {
			break
		}
	}
	out := make([]byte, 64)
	for i, value := range state {
		binary.LittleEndian.PutUint64(out[i*8:], value)
	}
	return out[:size]
}
func argonHash(data []byte, size int) []byte {
	input := binary.LittleEndian.AppendUint32(nil, uint32(size))
	input = append(input, data...)
	if size <= 64 {
		return blake2b(input, size)
	}
	value := blake2b(input, 64)
	out := make([]byte, 0, size)
	for size-len(out) > 64 {
		out = append(out, value[:32]...)
		if size-len(out) > 64 {
			value = blake2b(value, 64)
		}
	}
	return append(out, blake2b(value, size-len(out))...)
}

type argonBlock [128]uint64

func argonCompress(a, b argonBlock) argonBlock {
	var original, work argonBlock
	for i := range work {
		work[i] = a[i] ^ b[i]
	}
	original = work
	mix := func(a, b, c, d int) {
		add := func(x, y uint64) uint64 { return x + y + 2*uint64(uint32(x))*uint64(uint32(y)) }
		work[a] = add(work[a], work[b])
		work[d] = bits.RotateLeft64(work[d]^work[a], -32)
		work[c] = add(work[c], work[d])
		work[b] = bits.RotateLeft64(work[b]^work[c], -24)
		work[a] = add(work[a], work[b])
		work[d] = bits.RotateLeft64(work[d]^work[a], -16)
		work[c] = add(work[c], work[d])
		work[b] = bits.RotateLeft64(work[b]^work[c], -63)
	}
	round := func(index [16]int) {
		for i := range 4 {
			mix(index[i], index[i+4], index[i+8], index[i+12])
		}
		for i := range 4 {
			mix(index[i], index[(i+1)%4+4], index[(i+2)%4+8], index[(i+3)%4+12])
		}
	}
	for row := range 8 {
		var index [16]int
		for i := range index {
			index[i] = row*16 + i
		}
		round(index)
	}
	for column := range 8 {
		var index [16]int
		for i := range 8 {
			index[i*2] = i*16 + column*2
			index[i*2+1] = i*16 + column*2 + 1
		}
		round(index)
	}
	for i := range work {
		work[i] ^= original[i]
	}
	return work
}

// Snell fixes Argon2id v1.3 to t=3, m=8KiB, p=1 and a 32-byte result.
func snellKey(password, salt []byte) []byte {
	var input []byte
	for _, value := range []uint32{1, 32, 8, 3, 0x13, 2, uint32(len(password))} {
		input = binary.LittleEndian.AppendUint32(input, value)
	}
	input = append(input, password...)
	input = binary.LittleEndian.AppendUint32(input, uint32(len(salt)))
	input = append(input, salt...)
	input = append(input, make([]byte, 8)...)
	h0 := blake2b(input, 64)
	var memory [8]argonBlock
	for i := range 2 {
		data := binary.LittleEndian.AppendUint32(append([]byte(nil), h0...), uint32(i))
		data = binary.LittleEndian.AppendUint32(data, 0)
		expanded := argonHash(data, 1024)
		for j := range 128 {
			memory[i][j] = binary.LittleEndian.Uint64(expanded[j*8:])
		}
	}
	for pass := range 3 {
		for slice := range 4 {
			independent := pass == 0 && slice < 2
			var addressInput, addresses argonBlock
			addressInput[0] = uint64(pass)
			addressInput[2] = uint64(slice)
			addressInput[3] = 8
			addressInput[4] = 3
			addressInput[5] = 2
			start := 0
			if pass == 0 && slice == 0 {
				start = 2
			}
			for index := start; index < 2; index++ {
				position := slice*2 + index
				previous := (position + 7) % 8
				random := memory[previous][0]
				if independent {
					if index%128 == 0 {
						addressInput[6]++
						addresses = argonCompress(argonBlock{}, argonCompress(argonBlock{}, addressInput))
					}
					random = addresses[index%128]
				}
				area := slice*2 + index - 1
				base := 0
				if pass > 0 {
					area = 8 - 2 + index - 1
					base = (slice + 1) * 2 % 8
				}
				relative := uint64(uint32(random))
				relative = relative * relative >> 32
				relative = uint64(area-1) - (uint64(area) * relative >> 32)
				reference := (base + int(relative)) % 8
				mixed := argonCompress(memory[previous], memory[reference])
				if pass > 0 {
					for j := range mixed {
						mixed[j] ^= memory[position][j]
					}
				}
				memory[position] = mixed
			}
		}
	}
	data := make([]byte, 1024)
	for i, value := range memory[7] {
		binary.LittleEndian.PutUint64(data[i*8:], value)
	}
	return argonHash(data, 32)
}
