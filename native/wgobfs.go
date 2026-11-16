package native

import "encoding/binary"

type WGObfsOptions struct {
	Password string `json:"password,omitempty"`
}

type wgMask struct{ key [32]byte }

func newWGMask(password string) *wgMask {
	m := new(wgMask)
	if password != "" {
		for i := range m.key {
			m.key[i] = password[i%len(password)]
		}
	}
	return m
}

func (m *wgMask) hash(input []byte) [32]byte {
	state := chachaState(&m.key)
	for i := range 4 {
		state[12+i] = binary.LittleEndian.Uint32(input[i*4:])
	}
	work := state
	chachaRounds(&work, 3)
	var result [32]byte
	for i := range 8 {
		binary.LittleEndian.PutUint32(result[i*4:], work[i]+state[i])
	}
	return result
}

// encode owns packet; the handshake caller copies its cached authenticated bytes first.
func (m *wgMask) encode(packet []byte) []byte {
	if len(packet) < 32 || len(packet) > 65499 {
		return nil
	}
	kind := binary.LittleEndian.Uint32(packet)
	var seed [16]byte
	copy(seed[:], packet[16:32])
	seed[0] += 42
	if kind == 4 && len(packet) == 32 {
		seed[0]++
		if value := m.hash(seed[:]); value[0] > 50 {
			return nil
		}
	}
	if kind == 1 && len(packet) == 148 || kind == 2 && len(packet) == 92 {
		tail := packet[len(packet)-16:]
		if [16]byte(tail) == ([16]byte{}) {
			seed[0]++
			value := m.hash(seed[:])
			copy(tail, value[:16])
			packet[0] |= 0x10
		}
	}
	maximum := byte(32)
	if len(packet) > 200 {
		maximum = 8
	}
	for range 256 {
		seed[0]++
		padding := m.hash(seed[:])
		for _, size := range padding {
			if size < 4 || size > maximum {
				continue
			}
			mask := m.hash(packet[16:32])
			packet = append(packet, padding[:size]...)
			packet[len(packet)-1] = size ^ mask[16]
			for i := range 16 {
				packet[i] ^= mask[i]
			}
			return packet
		}
	}
	return nil
}

func (m *wgMask) decode(packet []byte) ([]byte, uint32) {
	if len(packet) < 36 || len(packet) > 65507 {
		return nil, 0
	}
	mask := m.hash(packet[16:32])
	padding := int(packet[len(packet)-1] ^ mask[16])
	size := len(packet) - padding
	if padding < 4 || padding > 32 || size < 32 || size > 200 && padding > 8 {
		return nil, 0
	}
	for i := range 16 {
		packet[i] ^= mask[i]
	}
	packet = packet[:size]
	kind := binary.LittleEndian.Uint32(packet)
	switch kind {
	case 1, 0x11:
		if size != 148 {
			return nil, 0
		}
	case 2, 0x12:
		if size != 92 {
			return nil, 0
		}
	case 3:
		if size != 64 {
			return nil, 0
		}
	case 4:
		// Kernel WireGuard may stop padding at the MTU rather than a16-byte boundary.
	default:
		return nil, 0
	}
	if kind == 0x11 || kind == 0x12 {
		clear(packet[size-16:])
		packet[0] &^= 0x10
	}
	return packet, kind & 15
}
