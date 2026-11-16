package native

import (
	"errors"
)

type chromiumQPACKEntry struct {
	number uint64
	field  [2]string
}
type chromiumQPACKTable struct {
	entries        []chromiumQPACKEntry
	inserted       uint64
	size, capacity int
}

func (t *chromiumQPACKTable) at(number uint64) ([2]string, error) {
	if len(t.entries) == 0 || number < t.entries[0].number || number >= t.inserted {
		return [2]string{}, errors.New("QPACK reference was evicted or not inserted")
	}
	return t.entries[number-t.entries[0].number].field, nil
}
func (t *chromiumQPACKTable) trim(n int) {
	for len(t.entries) > 0 && t.size+n > t.capacity {
		field := t.entries[0].field
		t.size -= 32 + len(field[0]) + len(field[1])
		copy(t.entries, t.entries[1:])
		t.entries[len(t.entries)-1] = chromiumQPACKEntry{}
		t.entries = t.entries[:len(t.entries)-1]
	}
}
func (t *chromiumQPACKTable) insert(field [2]string) error {
	if t.inserted >= 1<<62 {
		return errors.New("QPACK absolute index exhausted")
	}
	size := 32 + len(field[0]) + len(field[1])
	if size > t.capacity {
		return errors.New("QPACK insertion exceeds capacity")
	}
	t.trim(size)
	t.entries = append(t.entries, chromiumQPACKEntry{t.inserted, field})
	t.inserted++
	t.size += size
	return nil
}
func qpackRequired(encoded, count, maximum uint64) (uint64, error) {
	if encoded == 0 {
		return 0, nil
	}
	entries := maximum / 32
	full := 2 * entries
	if entries == 0 || encoded > full {
		return 0, errors.New("invalid QPACK required insert count")
	}
	maxValue := count + entries
	required := maxValue/full*full + encoded - 1
	if required > maxValue {
		if required <= full {
			return 0, errors.New("invalid wrapped QPACK insert count")
		}
		required -= full
	}
	if required == 0 {
		return 0, errors.New("QPACK insert count cannot decode to zero")
	}
	return required, nil
}
func qpackBase(raw []byte, count, maximum uint64) (required, base uint64, fields []byte, err error) {
	r := quicReader(raw)
	encoded, e := h3ReadInt(&r, 8)
	if e != nil {
		err = e
		return
	}
	required, e = qpackRequired(encoded, count, maximum)
	if e != nil {
		err = e
		return
	}
	if len(r) == 0 {
		err = errors.New("missing QPACK delta base")
		return
	}
	negative := r[0]&0x80 != 0
	delta, e := h3ReadInt(&r, 7)
	if e != nil {
		err = e
		return
	}
	if negative {
		if delta >= required {
			err = errors.New("negative QPACK base")
			return
		}
		base = required - delta - 1
	} else {
		base = required + delta
		if base < required {
			err = errors.New("QPACK base overflow")
			return
		}
	}
	fields = r
	if required == 0 && base != 0 {
		err = errors.New("QPACK zero insert count requires zero base")
	}
	return
}

func (t *chromiumQPACKTable) decode(fields []byte, base, required uint64) ([][2]string, error) {
	r := quicReader(fields)
	var out [][2]string
	total := 0
	dynamic := func(index uint64, post bool) ([2]string, error) {
		var number uint64
		if post {
			number = base + index
			if number < base {
				return [2]string{}, errors.New("QPACK post-base overflow")
			}
		} else {
			if index >= base {
				return [2]string{}, errors.New("QPACK relative index outside base")
			}
			number = base - index - 1
		}
		if number >= required {
			return [2]string{}, errors.New("QPACK reference exceeds required insert count")
		}
		return t.at(number)
	}
	static := func(index uint64) ([2]string, error) {
		if index >= uint64(len(h3Static)) {
			return [2]string{}, errors.New("QPACK static index outside table")
		}
		return h3Static[index], nil
	}
	for len(r) > 0 {
		first := r[0]
		var field [2]string
		var err error
		switch {
		case first&0x80 != 0:
			var index uint64
			index, err = h3ReadInt(&r, 6)
			if err == nil {
				if first&0x40 != 0 {
					field, err = static(index)
				} else {
					field, err = dynamic(index, false)
				}
			}
		case first&0xc0 == 0x40:
			var index uint64
			index, err = h3ReadInt(&r, 4)
			if err == nil {
				if first&0x10 != 0 {
					field, err = static(index)
				} else {
					field, err = dynamic(index, false)
				}
			}
			if err == nil {
				field[1], err = h3ReadText(&r, 7, 0x80)
			}
		case first&0xe0 == 0x20:
			field[0], err = h3ReadText(&r, 3, 8)
			if err == nil {
				field[1], err = h3ReadText(&r, 7, 0x80)
			}
		case first&0xf0 == 0x10:
			var index uint64
			index, err = h3ReadInt(&r, 4)
			if err == nil {
				field, err = dynamic(index, true)
			}
		default:
			var index uint64
			index, err = h3ReadInt(&r, 3)
			if err == nil {
				field, err = dynamic(index, true)
			}
			if err == nil {
				field[1], err = h3ReadText(&r, 7, 0x80)
			}
		}
		if err != nil {
			return nil, err
		}
		total += 32 + len(field[0]) + len(field[1])
		if total > 262144 || len(out) >= 1024 {
			return nil, errors.New("QPACK header list exceeds limit")
		}
		out = append(out, field)
	}
	return out, nil
}

type chromiumQPACKSection struct{ required, minimum uint64 }
type chromiumQPACKEncoder struct {
	table                   chromiumQPACKTable
	maximum, blocked, known uint64
	started                 bool
	sections                map[uint64]chromiumQPACKSection
}

func (e *chromiumQPACKEncoder) encode(id uint64, headers [][2]string) (block, instructions []byte) {
	if e.table.capacity == 0 || len(e.sections) >= 512 {
		return chromiumQPACK(headers), nil
	}
	if !e.started {
		instructions = h3Int(nil, 5, 0x20, uint64(e.table.capacity))
		e.started = true
	}
	refs := make([]uint64, len(headers))
	required, minimum := uint64(0), ^uint64(0)
	blocked := uint64(0)
	for _, section := range e.sections {
		if section.required > e.known {
			blocked++
		}
	}
	canBlock := blocked < e.blocked
	for i, field := range headers {
		if field[0] == "authorization" || field[0] == "proxy-authorization" || field[0] == "cookie" {
			continue
		}
		found := false
		var number uint64
		for _, entry := range e.table.entries {
			if entry.field == field {
				number = entry.number
				found = true
				break
			}
		}
		if !found {
			for _, entry := range h3Static {
				if entry == field {
					found = true
					break
				}
			}
			if found {
				continue
			}
			size := 32 + len(field[0]) + len(field[1])
			safe := size <= e.table.capacity
			needed := e.table.size + size - e.table.capacity
			for _, entry := range e.table.entries {
				if needed <= 0 {
					break
				}
				if entry.number >= e.known || entry.number >= minimum {
					safe = false
					break
				}
				for _, section := range e.sections {
					if entry.number >= section.minimum {
						safe = false
						break
					}
				}
				if !safe {
					break
				}
				needed -= 32 + len(entry.field[0]) + len(entry.field[1])
			}
			if !safe {
				continue
			}
			number = e.table.inserted
			if e.table.insert(field) != nil {
				continue
			}
			instructions = httpHeaderText(instructions, field[0], 5, 0x40)
			instructions = httpHeaderText(instructions, field[1], 7, 0)
		}
		if number >= e.known && !canBlock {
			continue
		}
		refs[i] = number + 1
		required = max(required, number+1)
		minimum = min(minimum, number)
	}
	if required > 0 {
		block = h3Int(nil, 8, 0, required%(2*(e.maximum/32))+1)
	} else {
		block = []byte{0}
	}
	base := e.table.inserted
	if required == 0 {
		base = 0
	}
	block = h3Int(block, 7, 0, base-required)
	for i, field := range headers {
		if refs[i] != 0 {
			block = h3Int(block, 6, 0x80, base-refs[i])
		} else {
			wire := chromiumQPACK([][2]string{field})
			block = append(block, wire[2:]...)
		}
	}
	if required > 0 {
		if e.sections == nil {
			e.sections = map[uint64]chromiumQPACKSection{}
		}
		e.sections[id] = chromiumQPACKSection{required, minimum}
	}
	return
}
func (e *chromiumQPACKEncoder) acknowledge(first byte, value uint64) error {
	if first&0x80 != 0 {
		section, ok := e.sections[value]
		if !ok {
			return errors.New("QPACK acknowledgement references unknown section")
		}
		e.known = max(e.known, section.required)
		delete(e.sections, value)
	} else if first&0x40 != 0 {
		delete(e.sections, value)
	} else {
		if value == 0 || value > e.table.inserted-e.known {
			return errors.New("invalid QPACK insert count increment")
		}
		e.known += value
	}
	return nil
}
