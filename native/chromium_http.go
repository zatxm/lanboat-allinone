package native

import "encoding/binary"

// Encoder state is owned by the HTTP2 writer; cancelled queued headers cannot
// mutate the compression context seen by subsequent streams.
type chromiumHPACK struct {
	table       [][2]string
	size, limit int
	smallest    int
	resized     bool
}

func httpHeaderText(out []byte, text string, prefix uint, flag byte) []byte {
	bits := 0
	for i := range len(text) {
		bits += int(h3HuffmanBits[text[i]])
	}
	n := (bits + 7) / 8
	if n >= len(text) {
		out = h3Int(out, prefix, flag, uint64(len(text)))
		return append(out, text...)
	}
	out = h3Int(out, prefix, flag|byte(1<<prefix), uint64(n))
	var pending uint64
	available := uint(0)
	for i := range len(text) {
		width := uint(h3HuffmanBits[text[i]])
		pending = pending<<width | uint64(h3HuffmanCodes[text[i]])
		available += width
		for available >= 8 {
			available -= 8
			out = append(out, byte(pending>>available))
		}
	}
	if available > 0 {
		out = append(out, byte(pending<<(8-available))|byte((1<<(8-available))-1))
	}
	return out
}
func (e *chromiumHPACK) trim() {
	for e.size > e.limit && len(e.table) > 0 {
		i := len(e.table) - 1
		f := e.table[i]
		e.size -= 32 + len(f[0]) + len(f[1])
		e.table[i] = [2]string{}
		e.table = e.table[:i]
	}
}
func (e *chromiumHPACK) encode(fields [][2]string, limit int) []byte {
	var out []byte
	e.resize(limit)
	if e.resized {
		if e.smallest < e.limit {
			out = h3Int(out, 5, 0x20, uint64(e.smallest))
		}
		out = h3Int(out, 5, 0x20, uint64(e.limit))
		e.resized = false
	}
	for _, field := range fields {
		name, exact := 0, 0
		sensitive := field[0] == "authorization" || field[0] == "proxy-authorization" || field[0] == "cookie"
		for i, entry := range masqueHPACKStatic[1:] {
			index := i + 1
			if entry[0] == field[0] {
				if name == 0 {
					name = index
				}
				if entry[1] == field[1] {
					exact = index
					break
				}
			}
		}
		if !sensitive {
			for i, entry := range e.table {
				index := len(masqueHPACKStatic) + i
				if entry[0] == field[0] {
					if name == 0 {
						name = index
					}
					if entry[1] == field[1] {
						exact = index
						break
					}
				}
			}
		}
		if exact > 0 && !sensitive {
			out = h3Int(out, 7, 0x80, uint64(exact))
			continue
		}
		indexed := !sensitive && field[0] != ":method" && field[0] != ":path"
		prefix, first := uint(4), byte(0)
		if indexed {
			prefix, first = 6, 0x40
		} else if sensitive {
			first = 0x10
		}
		out = h3Int(out, prefix, first, uint64(name))
		if name == 0 {
			out = httpHeaderText(out, field[0], 7, 0)
		}
		out = httpHeaderText(out, field[1], 7, 0)
		if indexed {
			n := 32 + len(field[0]) + len(field[1])
			if n > e.limit {
				clear(e.table)
				e.table = nil
				e.size = 0
				continue
			}
			e.table = append(e.table, [2]string{})
			copy(e.table[1:], e.table)
			e.table[0] = field
			e.size += n
			e.trim()
		}
	}
	return out
}
func (e *chromiumHPACK) resize(limit int) {
	if limit == e.limit {
		return
	}
	if !e.resized {
		e.smallest = limit
	} else {
		e.smallest = min(e.smallest, limit)
	}
	e.resized = true
	e.limit = limit
	e.trim()
}
func chromiumH2Headers(id uint32, block []byte) []byte {
	priority := binary.BigEndian.AppendUint32(nil, 0x80000000)
	priority = append(priority, 146)
	return masqueHeaderFrames(id, 0x20, append(priority, block...))
}
func chromiumQPACK(headers [][2]string) []byte {
	out := []byte{0, 0}
	for _, field := range headers {
		name, exact := -1, -1
		sensitive := field[0] == "authorization" || field[0] == "proxy-authorization" || field[0] == "cookie"
		for i, entry := range h3Static {
			if entry[0] == field[0] {
				if name < 0 {
					name = i
				}
				if entry[1] == field[1] {
					exact = i
					break
				}
			}
		}
		if exact >= 0 && !sensitive {
			out = h3Int(out, 6, 0xc0, uint64(exact))
			continue
		}
		if name >= 0 {
			first := byte(0x50)
			if sensitive {
				first |= 0x20
			}
			out = h3Int(out, 4, first, uint64(name))
		} else {
			first := byte(0x20)
			if sensitive {
				first |= 0x10
			}
			out = httpHeaderText(out, field[0], 3, first)
		}
		out = httpHeaderText(out, field[1], 7, 0)
	}
	return out
}
