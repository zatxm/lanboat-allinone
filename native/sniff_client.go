package native

import (
	"bytes"
	"encoding/binary"
)

// Frame layout identifies a stack family; it is not an authenticated identity.
type quicClientFrames struct {
	crypto, ping, ack            int
	first, last                  uint64
	frames                       int
	bare, goLayout, safariLayout bool
}

func (s *quicClientFrames) add(kind uint64) {
	if s.frames == 0 {
		s.first = kind
	}
	s.frames++
	s.last = kind
	switch kind {
	case 6:
		s.crypto++
	case 1:
		s.ping++
	case 2, 3:
		s.ack++
	}
}
func (s *quicClientFrames) merge(p quicClientFrames) {
	s.crypto += p.crypto
	s.ping += p.ping
	s.ack += p.ack
	if p.crypto != 0 {
		s.bare = s.bare || p.frames == 1 && p.first == 6
		s.goLayout = s.goLayout || p.ping == 0 && p.ack == 0 && p.first == 0 && p.last == 6
		s.safariLayout = s.safariLayout || p.crypto == 1 && p.ping == 0 && p.ack == 0 && p.first == 6 && p.last == 0
	}
}

type quicHelloTraits struct {
	ciphers, groups, signatures, versions []byte
	legacyVersionProbe                    bool
}

func sniffQUICHello(crypto quicBuffer) ([]byte, bool) {
	var prefix [4]byte
	end := 0
	for _, part := range crypto.parts {
		if part.offset != uint64(end) {
			break
		}
		if end < 4 {
			copy(prefix[end:], part.data)
		}
		end += len(part.data)
	}
	if end == 0 {
		return nil, true
	}
	if prefix[0] != 1 {
		return nil, false
	}
	if end < 4 {
		return nil, true
	}
	want := 4 + (int(prefix[1])<<16 | int(prefix[2])<<8 | int(prefix[3]))
	if want > sniffLimit {
		return nil, false
	}
	if end < want {
		return nil, true
	}
	if len(crypto.parts[0].data) >= want {
		return crypto.parts[0].data[:want], false
	}
	hello := make([]byte, want)
	for _, part := range crypto.parts {
		if part.offset >= uint64(want) {
			break
		}
		copy(hello[int(part.offset):], part.data)
	}
	return hello, false
}

func parseQUICHelloTraits(hello []byte) (quicHelloTraits, bool) {
	var out quicHelloTraits
	if len(hello) < 4 || hello[0] != 1 {
		return out, false
	}
	h := stCursor{data: hello}
	h.number(1)
	body := h.take(h.number(3))
	if h.end() != nil {
		return out, false
	}
	p := stCursor{data: body}
	if p.number(2) != 0x0303 {
		return out, false
	}
	p.take(32)
	sid := p.vector(1)
	out.ciphers = p.vector(2)
	compression := p.vector(1)
	extensions := p.vector(2)
	if p.end() != nil || len(sid) > 32 || len(out.ciphers) == 0 || len(out.ciphers)%2 != 0 || !bytes.Equal(compression, []byte{0}) {
		return out, false
	}
	e := stCursor{data: extensions}
	var ids [256]uint16
	count := 0
	parameters := false
	for len(e.data) > 0 && e.err == nil {
		id := uint16(e.number(2))
		value := e.vector(2)
		if e.err != nil || count == len(ids) {
			return out, false
		}
		for _, seen := range ids[:count] {
			if seen == id {
				return out, false
			}
		}
		ids[count] = id
		count++
		v := stCursor{data: value}
		switch id {
		case 10:
			out.groups = v.vector(2)
			if len(out.groups)%2 != 0 {
				return out, false
			}
		case 13:
			out.signatures = v.vector(2)
			if len(out.signatures)%2 != 0 {
				return out, false
			}
		case 43:
			out.versions = v.vector(1)
			if len(out.versions)%2 != 0 {
				return out, false
			}
		case 57:
			parameters = true
			tp := quicReader(value)
			for len(tp) > 0 {
				id, err := tp.v()
				if err != nil {
					return out, false
				}
				n, err := tp.v()
				if err != nil {
					return out, false
				}
				data, err := tp.take(n)
				if err != nil {
					return out, false
				}
				// Older uQUIC Chrome profiles use arbitrary versions in the
				// draft version probe; Chromium uses RFC9287 reserved versions.
				if id == 0xff73db && len(data) >= 8 && len(data)%4 == 0 {
					for i := 4; i < len(data); i += 4 {
						v := binary.BigEndian.Uint32(data[i:])
						if v != quicVersion && v != quicVersion2 && v&0x0f0f0f0f != 0x0a0a0a0a {
							out.legacyVersionProbe = true
						}
					}
				}
			}
			continue
		default:
			continue
		}
		if v.end() != nil {
			return out, false
		}
	}
	return out, e.end() == nil && parameters
}
func quicGREASE(b []byte) bool { return len(b) >= 2 && binary.BigEndian.Uint16(b)&0x0f0f == 0x0a0a }
func classifyQUICClient(frames quicClientFrames, hello []byte) string {
	h, valid := parseQUICHelloTraits(hello)
	if !valid {
		return "unknown"
	}
	if frames.safariLayout {
		browser := len(h.versions) == 4 && quicGREASE(h.versions) && len(h.groups) == 10 && quicGREASE(h.groups)
		network := bytes.Equal(h.ciphers, []byte{0x13, 2}) && bytes.Equal(h.groups, []byte{0, 29}) && bytes.Equal(h.signatures, []byte{4, 3})
		if browser || network {
			return "safari"
		}
	}
	if frames.bare && frames.ping == 0 && !frames.goLayout {
		return "firefox"
	}
	if frames.goLayout && frames.ping == 0 {
		return "quic-go"
	}
	if h.legacyVersionProbe {
		return "quic-go"
	}
	if frames.ping > 0 || frames.crypto > 1 {
		return "chromium"
	}
	return "unknown"
}
