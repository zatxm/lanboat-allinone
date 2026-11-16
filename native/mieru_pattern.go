package native

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// Only the published protobuf wire schema is needed; no protobuf runtime is linked.
type mieruPattern struct {
	fragment, allPackets                   bool
	sleepMS, nonceType, minNonce, maxNonce int
	middle, end                            int
	mode, rotation                         byte
	prefixes                               [][]byte
}

type mieruField struct {
	number, wire int
	value        uint64
	bytes        []byte
}

func mieruFields(b []byte, visit func(mieruField) error) error {
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 || key>>3 == 0 || key>>3 > 1<<29-1 {
			return errors.New("invalid Mieru traffic pattern field")
		}
		b = b[n:]
		f := mieruField{number: int(key >> 3), wire: int(key & 7)}
		switch f.wire {
		case 0:
			f.value, n = binary.Uvarint(b)
			if n <= 0 {
				return errors.New("truncated Mieru traffic pattern integer")
			}
			b = b[n:]
		case 1, 5:
			n = 8
			if f.wire == 5 {
				n = 4
			}
			if len(b) < n {
				return errors.New("truncated Mieru traffic pattern fixed value")
			}
			f.bytes, b = b[:n], b[n:]
		case 2:
			length, k := binary.Uvarint(b)
			if k <= 0 || length > uint64(len(b)-k) {
				return errors.New("truncated Mieru traffic pattern message")
			}
			b = b[k:]
			f.bytes, b = b[:int(length)], b[int(length):]
		default:
			return errors.New("invalid Mieru traffic pattern wire type")
		}
		if e := visit(f); e != nil {
			return e
		}
	}
	return nil
}
func mieruInteger(f mieruField, maximum int) (int, error) {
	if f.wire != 0 || f.value > uint64(maximum) {
		return 0, errors.New("invalid Mieru traffic pattern value")
	}
	return int(f.value), nil
}
func parseMieruPattern(encoded string, mode byte) (*mieruPattern, error) {
	p := &mieruPattern{middle: 15, end: 31, mode: mode}
	if encoded == "" {
		return p, nil
	}
	if len(encoded) > 8192 {
		return nil, errors.New("Mieru traffic_pattern exceeds8192 bytes")
	}
	b, e := base64.StdEncoding.DecodeString(encoded)
	if e != nil {
		b, e = base64.RawStdEncoding.DecodeString(encoded)
	}
	if e != nil {
		b, e = base64.RawURLEncoding.DecodeString(encoded)
	}
	if e != nil {
		return nil, fmt.Errorf("Mieru traffic_pattern: %w", e)
	}
	var seed uint64
	var unlock bool
	e = mieruFields(b, func(f mieruField) error {
		switch f.number {
		case 1:
			if f.wire != 0 || uint64(int64(int32(f.value))) != f.value {
				return errors.New("invalid Mieru traffic pattern seed")
			}
			seed = f.value
		case 2:
			n, e := mieruInteger(f, 1)
			unlock = n == 1
			return e
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	// Implicit shaping is stable, without imitating upstream host fingerprints.
	profile := binary.BigEndian.AppendUint64([]byte("Lanboat Mieru pattern"), seed)
	if unlock {
		profile = append(profile, 1)
	}
	h := sha256.Sum256(profile)
	p.middle = int(h[0] & 31)
	p.end = int(h[1] & 63)
	if unlock {
		p.middle = int(h[0])
		p.end = int(h[1])
	}
	e = mieruFields(b, func(f mieruField) error {
		if f.number == 1 {
			if f.wire != 0 || uint64(int64(int32(f.value))) != f.value {
				return errors.New("invalid Mieru traffic pattern seed")
			}
			return nil
		}
		if f.number == 2 {
			_, e := mieruInteger(f, 1)
			return e
		}
		if f.number < 3 || f.number > 6 {
			return nil
		}
		if f.wire != 2 {
			return errors.New("Mieru traffic pattern requires message")
		}
		return mieruFields(f.bytes, func(v mieruField) error {
			var target *int
			limit := 0
			switch f.number {
			case 3:
				switch v.number {
				case 1:
					n, e := mieruInteger(v, 1)
					p.fragment = n == 1
					return e
				case 2:
					target, limit = &p.sleepMS, 100
				}
			case 4:
				switch v.number {
				case 1:
					target, limit = &p.nonceType, 3
				case 2:
					n, e := mieruInteger(v, 1)
					p.allPackets = n == 1
					return e
				case 3:
					target, limit = &p.minNonce, 12
				case 4:
					target, limit = &p.maxNonce, 12
				case 5:
					if v.wire != 2 || len(p.prefixes) >= 32 || len(v.bytes) > 24 {
						return errors.New("invalid Mieru nonce prefix")
					}
					prefix, e := hex.DecodeString(string(v.bytes))
					if e != nil {
						return e
					}
					p.prefixes = append(p.prefixes, prefix)
					return nil
				}
			case 5:
				switch v.number {
				case 1:
					target, limit = &p.middle, 255
				case 2:
					target, limit = &p.end, 255
				}
			case 6:
				switch v.number {
				case 1:
					n, e := mieruInteger(v, 4)
					p.mode = byte(n)
					return e
				case 2:
					n, e := mieruInteger(v, 240)
					if n&15 != 0 && n&240 != 0 {
						return errors.New("invalid Mieru mask rotation")
					}
					p.rotation = byte(n)
					return e
				}
			}
			if target != nil {
				n, e := mieruInteger(v, limit)
				*target = n
				return e
			}
			return nil
		})
	})
	if e != nil {
		return nil, e
	}
	if p.minNonce > p.maxNonce {
		return nil, errors.New("Mieru nonce minLen exceeds maxLen")
	}
	return p, nil
}
func mieruRandom(n int) int {
	if n < 2 {
		return 0
	}
	var b [4]byte
	rand.Read(b[:])
	return int(binary.BigEndian.Uint32(b[:]) % uint32(n))
}
func (p *mieruPattern) nonce(n *[24]byte) {
	switch p.nonceType {
	case 1, 2:
		length := p.minNonce + mieruRandom(p.maxNonce-p.minNonce+1)
		const subset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		for i := range length {
			if p.nonceType == 1 {
				n[i] = byte(32 + mieruRandom(95))
			} else {
				n[i] = subset[mieruRandom(len(subset))]
			}
		}
	case 3:
		if len(p.prefixes) > 0 {
			copy(n[:], p.prefixes[mieruRandom(len(p.prefixes))])
		}
	}
}
