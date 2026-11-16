package native

import (
	"encoding/binary"
	"math/bits"
	"slices"
)

type masqueDerivedField struct {
	kind   uint16
	offset int
}
type masquePacketLayout struct{ version, header, transport, protocol int }

func masqueTransportOffset(b []byte, l *masquePacketLayout) bool {
	if l.version == 4 {
		if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
			return false
		}
		l.protocol = int(b[9])
		l.transport = l.header
	} else {
		l.protocol = int(b[6])
		l.transport = 40
		for l.protocol != 6 && l.protocol != 17 {
			at := l.transport
			if at+8 > len(b) {
				return false
			}
			n := 0
			switch l.protocol {
			case 0, 43, 60, 135, 139, 140:
				n = (int(b[at+1]) + 1) * 8
			case 51:
				n = (int(b[at+1]) + 2) * 4
			default:
				return false
			}
			l.protocol = int(b[at])
			l.transport += n
		}
	}
	if l.protocol == 17 {
		return l.transport+8 <= len(b)
	}
	if l.protocol != 6 || l.transport+20 > len(b) {
		return false
	}
	n := int(b[l.transport+12]>>4) * 4
	return n >= 20 && l.transport+n <= len(b)
}

func masquePacketFields(b []byte, mask uint16) (masquePacketLayout, []masqueDerivedField, bool) {
	var l masquePacketLayout
	if len(b) < 20 || len(b) > 65535 || mask&^uint16(511) != 0 {
		return l, nil, false
	}
	l.version = int(b[0] >> 4)
	allowed := uint16(1<<0 | 1<<2 | 1<<4 | 1<<5 | 1<<7)
	l.header = int(b[0]&15) * 4
	if l.version == 6 {
		allowed = 1<<1 | 1<<3 | 1<<6 | 1<<8
		l.header = 40
	} else if l.version != 4 {
		return l, nil, false
	}
	if mask&^allowed != 0 || l.header < 20 || l.header > len(b) {
		return l, nil, false
	}
	fields := make([]masqueDerivedField, 0, bits.OnesCount16(mask))
	for _, v := range []masqueDerivedField{{0, 2}, {1, 4}, {4, 10}} {
		if mask&(1<<v.kind) != 0 {
			fields = append(fields, v)
		}
	}
	transportMask := mask &^ (uint16(1<<0 | 1<<1 | 1<<4))
	if transportMask != 0 {
		if !masqueTransportOffset(b, &l) {
			return l, nil, false
		}
		for _, v := range []masqueDerivedField{{2, 4}, {3, 4}, {5, 16}, {6, 16}, {7, 6}, {8, 6}} {
			if mask&(1<<v.kind) == 0 {
				continue
			}
			if (v.kind == 5 || v.kind == 6) != (l.protocol == 6) {
				return l, nil, false
			}
			v.offset += l.transport
			fields = append(fields, v)
		}
	}
	slices.SortFunc(fields, func(a, b masqueDerivedField) int { return a.offset - b.offset })
	return l, fields, true
}

func masqueFieldValue(b []byte, l masquePacketLayout, f masqueDerivedField) (uint16, bool) {
	switch f.kind {
	case 0:
		return uint16(len(b)), true
	case 1:
		if len(b) <= 40 {
			return 0, false
		}
		return uint16(len(b) - 40), true
	case 2, 3:
		return uint16(len(b) - l.transport), true
	case 4:
		old := binary.BigEndian.Uint16(b[10:])
		return checksum(b[:l.header], uint32(^old)), true
	case 5, 6, 7, 8:
		segment := b[l.transport:]
		n := len(segment)
		if l.protocol == 17 {
			n = int(binary.BigEndian.Uint16(segment[4:6]))
			if n < 8 || n > len(segment) {
				return 0, false
			}
			segment = segment[:n]
		}
		initial := uint32(^binary.BigEndian.Uint16(b[f.offset:]))
		sum := uint32(l.protocol) + uint32(n&65535) + uint32(n>>16) + initial
		addresses := b[12:20]
		if l.version == 6 {
			addresses = b[8:40]
		}
		for i := 0; i < len(addresses); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(addresses[i:]))
		}
		value := checksum(segment, sum)
		if l.protocol == 17 && value == 0 {
			value = 65535
		}
		return value, true
	}
	return 0, false
}

func masqueRemoveDerived(b []byte, allowed uint16) ([]byte, uint16, []masqueDerivedField) {
	l, _, ok := masquePacketFields(b, 0)
	if !ok {
		return b, 0, nil
	}
	candidate := uint16(1<<0 | 1<<4)
	if l.version == 6 {
		candidate = 1 << 1
	}
	if masqueTransportOffset(b, &l) {
		if l.protocol == 17 {
			if l.version == 4 {
				candidate |= 1<<2 | 1<<7
			} else {
				candidate |= 1<<3 | 1<<8
			}
		} else {
			if l.version == 4 {
				candidate |= 1 << 5
			} else {
				candidate |= 1 << 6
			}
		}
	}
	candidate &= allowed
	if candidate == 0 {
		return b, 0, nil
	}
	l, fs, ok := masquePacketFields(b, candidate)
	if !ok {
		return b, 0, nil
	}
	mask := uint16(0)
	keep := fs[:0]
	for _, f := range fs {
		value, ok := masqueFieldValue(b, l, f)
		if ok && value == binary.BigEndian.Uint16(b[f.offset:]) {
			mask |= 1 << f.kind
			keep = append(keep, f)
		}
	}
	fs = keep
	if mask == 0 {
		return b, 0, nil
	}
	out := make([]byte, 0, len(b)-2*len(fs))
	at := 0
	for _, f := range fs {
		out = append(out, b[at:f.offset]...)
		at = f.offset + 2
	}
	out = append(out, b[at:]...)
	return out, mask, fs
}

func masqueInsertDerived(compact []byte, mask uint16, mtu int) ([]byte, bool) {
	if mask == 0 {
		return compact, len(compact) <= mtu
	}
	n := len(compact) + 2*bits.OnesCount16(mask)
	if len(compact) == 0 || n > mtu || n > 65535 {
		return nil, false
	}
	version := int(compact[0] >> 4)
	header := int(compact[0]&15) * 4
	allowed := uint16(1<<0 | 1<<2 | 1<<4 | 1<<5 | 1<<7)
	if version == 6 {
		header = 40
		allowed = 1<<1 | 1<<3 | 1<<6 | 1<<8
	} else if version != 4 {
		return nil, false
	}
	if mask&^allowed != 0 || header < 20 || header > n {
		return nil, false
	}
	out := make([]byte, n)
	fields := make([]masqueDerivedField, 0, bits.OnesCount16(mask))
	for _, f := range []masqueDerivedField{{0, 2}, {1, 4}, {4, 10}} {
		if mask&(1<<f.kind) != 0 {
			fields = append(fields, f)
		}
	}
	input, position, field := 0, 0, 0
	fill := func(end int) bool {
		if end > len(out) || end < position {
			return false
		}
		for field < len(fields) && fields[field].offset < end {
			at := fields[field].offset
			gap := at - position
			if gap < 0 || at+2 > end || input+gap > len(compact) {
				return false
			}
			copy(out[position:at], compact[input:input+gap])
			input += gap
			position = at + 2
			field++
		}
		gap := end - position
		if input+gap > len(compact) {
			return false
		}
		copy(out[position:end], compact[input:input+gap])
		input += gap
		position = end
		return true
	}
	if !fill(header) {
		return nil, false
	}
	if mask&^uint16(1<<0|1<<1|1<<4) != 0 {
		at, protocol := header, int(out[9])
		if version == 6 {
			at, protocol = 40, int(out[6])
		} else if binary.BigEndian.Uint16(out[6:8])&0x3fff != 0 {
			return nil, false
		}
		if version == 6 {
			for protocol != 6 && protocol != 17 {
				if !fill(at + 8) {
					return nil, false
				}
				step := 0
				switch protocol {
				case 0, 43, 60, 135, 139, 140:
					step = (int(out[at+1]) + 1) * 8
				case 51:
					step = (int(out[at+1]) + 2) * 4
				default:
					return nil, false
				}
				protocol = int(out[at])
				at += step
				if !fill(at) {
					return nil, false
				}
			}
		}
		for _, f := range []masqueDerivedField{{2, 4}, {3, 4}, {5, 16}, {6, 16}, {7, 6}, {8, 6}} {
			if mask&(1<<f.kind) == 0 {
				continue
			}
			if (f.kind == 5 || f.kind == 6) != (protocol == 6) {
				return nil, false
			}
			f.offset += at
			fields = append(fields, f)
		}
		slices.SortFunc(fields, func(a, b masqueDerivedField) int { return a.offset - b.offset })
	}
	if !fill(len(out)) || input != len(compact) {
		return nil, false
	}
	l, fs, ok := masquePacketFields(out, mask)
	if !ok {
		return nil, false
	}
	// Lengths must be written before checksums, regardless of declaration order.
	for _, f := range fs {
		if f.kind > 3 {
			continue
		}
		value, ok := masqueFieldValue(out, l, f)
		if !ok {
			return nil, false
		}
		binary.BigEndian.PutUint16(out[f.offset:], value)
	}
	for _, f := range fs {
		if f.kind < 4 {
			continue
		}
		value, ok := masqueFieldValue(out, l, f)
		if !ok {
			return nil, false
		}
		binary.BigEndian.PutUint16(out[f.offset:], value)
	}
	return out, true
}

func masqueCompleteChecksum(b []byte, field, start int, ip bool) bool {
	if start <= 0 || start > len(b) || field < 0 || field > len(b)-2 {
		return false
	}
	sum := uint32(binary.BigEndian.Uint16(b[field:]))
	clear(b[field : field+2])
	value := checksum(b[start:], sum)
	if ip && value == 0 {
		l, _, ok := masquePacketFields(b, 0)
		if ok && masqueTransportOffset(b, &l) && l.protocol == 17 && field == l.transport+6 {
			value = 65535
		}
	}
	binary.BigEndian.PutUint16(b[field:], value)
	return true
}

func masquePartialChecksum(b []byte) (field, start int, partial uint16, ok bool) {
	l, _, valid := masquePacketFields(b, 0)
	if !valid || !masqueTransportOffset(b, &l) {
		return 0, 0, 0, false
	}
	start = l.transport
	field = start + 16
	kind := uint16(5)
	if l.version == 6 {
		kind = 6
	}
	if l.protocol == 17 {
		field = start + 6
		kind = 7
		if l.version == 6 {
			kind = 8
		}
		if int(binary.BigEndian.Uint16(b[start+4:])) != len(b)-start {
			return 0, 0, 0, false
		}
	}
	value, valid := masqueFieldValue(b, l, masqueDerivedField{kind, field})
	if !valid || value != binary.BigEndian.Uint16(b[field:]) {
		return 0, 0, 0, false
	}
	n := len(b) - start
	sum := uint32(l.protocol) + uint32(n&65535) + uint32(n>>16)
	addresses := b[12:20]
	if l.version == 6 {
		addresses = b[8:40]
	}
	for i := 0; i < len(addresses); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(addresses[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return field, start, uint16(sum), true
}
