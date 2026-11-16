package native

import (
	"errors"
	"strings"
)

// HPACK's static wire table. QPACK uses the same integer and Huffman coding.
var masqueHPACKStatic = [][2]string{
	{"", ""}, {":authority", ""}, {":method", "GET"}, {":method", "POST"}, {":path", "/"}, {":path", "/index.html"}, {":scheme", "http"}, {":scheme", "https"}, {":status", "200"}, {":status", "204"}, {":status", "206"}, {":status", "304"}, {":status", "400"}, {":status", "404"}, {":status", "500"},
	{"accept-charset", ""}, {"accept-encoding", "gzip, deflate"}, {"accept-language", ""}, {"accept-ranges", ""}, {"accept", ""}, {"access-control-allow-origin", ""}, {"age", ""}, {"allow", ""}, {"authorization", ""}, {"cache-control", ""}, {"content-disposition", ""}, {"content-encoding", ""}, {"content-language", ""}, {"content-length", ""}, {"content-location", ""}, {"content-range", ""}, {"content-type", ""}, {"cookie", ""}, {"date", ""}, {"etag", ""}, {"expect", ""}, {"expires", ""}, {"from", ""}, {"host", ""}, {"if-match", ""}, {"if-modified-since", ""}, {"if-none-match", ""}, {"if-range", ""}, {"if-unmodified-since", ""}, {"last-modified", ""}, {"link", ""}, {"location", ""}, {"max-forwards", ""}, {"proxy-authenticate", ""}, {"proxy-authorization", ""}, {"range", ""}, {"referer", ""}, {"refresh", ""}, {"retry-after", ""}, {"server", ""}, {"set-cookie", ""}, {"strict-transport-security", ""}, {"transfer-encoding", ""}, {"user-agent", ""}, {"vary", ""}, {"via", ""}, {"www-authenticate", ""},
}

type masqueHPACK struct {
	table            [][2]string
	size, limit      int
	max, headerLimit int
}

func (d *masqueHPACK) entry(index uint64) ([2]string, error) {
	if index == 0 {
		return [2]string{}, errors.New("HPACK zero index")
	}
	if index < uint64(len(masqueHPACKStatic)) {
		return masqueHPACKStatic[index], nil
	}
	index -= uint64(len(masqueHPACKStatic))
	if index >= uint64(len(d.table)) {
		return [2]string{}, errors.New("HPACK index outside table")
	}
	return d.table[index], nil
}
func (d *masqueHPACK) trim() {
	for d.size > d.limit && len(d.table) > 0 {
		i := len(d.table) - 1
		v := d.table[i]
		d.size -= 32 + len(v[0]) + len(v[1])
		d.table[i] = [2]string{}
		d.table = d.table[:i]
	}
}
func (d *masqueHPACK) decode(block []byte) ([][2]string, error) {
	r := quicReader(block)
	var fields [][2]string
	size := 0
	started := false
	for len(r) > 0 {
		first := r[0]
		if first&0xe0 == 0x20 {
			if started {
				return nil, errors.New("HPACK table update after header")
			}
			n, e := h3ReadInt(&r, 5)
			if e != nil {
				return nil, e
			}
			maximum := d.max
			if maximum == 0 {
				maximum = 4096
			}
			if n > uint64(maximum) {
				return nil, errors.New("HPACK table exceeds advertised limit")
			}
			d.limit = int(n)
			d.trim()
			continue
		}
		started = true
		var v [2]string
		var e error
		if first&0x80 != 0 {
			var index uint64
			index, e = h3ReadInt(&r, 7)
			if e == nil {
				v, e = d.entry(index)
			}
		} else {
			prefix := uint(4)
			if first&0x40 != 0 {
				prefix = 6
			}
			var index uint64
			index, e = h3ReadInt(&r, prefix)
			if e == nil {
				if index == 0 {
					v[0], e = h3ReadText(&r, 7, 0x80)
				} else {
					var named [2]string
					named, e = d.entry(index)
					v[0] = named[0]
				}
			}
			if e == nil {
				v[1], e = h3ReadText(&r, 7, 0x80)
			}
			if e == nil && first&0x40 != 0 {
				n := 32 + len(v[0]) + len(v[1])
				if n > d.limit {
					d.table = nil
					d.size = 0
				} else {
					d.table = append(d.table, [2]string{})
					copy(d.table[1:], d.table[:len(d.table)-1])
					d.table[0] = v
					d.size += n
					d.trim()
				}
			}
		}
		if e != nil {
			return nil, e
		}
		size += 32 + len(v[0]) + len(v[1])
		maximum := d.headerLimit
		if maximum == 0 {
			maximum = 65536
		}
		if size > maximum || len(fields) >= 1024 {
			return nil, errors.New("MASQUE HTTP2 header exceeds limit")
		}
		fields = append(fields, v)
	}
	return fields, nil
}

const masqueProtocolHeader = "x-lanboat-masque-protocol"

func masqueRewriteHeaders(fields [][2]string) ([]byte, error) {
	pseudo := map[string]string{}
	regular := false
	for _, v := range fields {
		if strings.HasPrefix(v[0], ":") {
			if regular {
				return nil, errors.New("HTTP2 pseudo-header after regular header")
			}
			if _, ok := pseudo[v[0]]; ok {
				return nil, errors.New("duplicate HTTP2 pseudo-header")
			}
			pseudo[v[0]] = v[1]
		} else {
			regular = true
		}
	}
	protocol, hasProtocol := pseudo[":protocol"]
	if hasProtocol && protocol == "" {
		return nil, errors.New("empty HTTP2 protocol")
	}
	if protocol != "" && (pseudo[":method"] != "CONNECT" || pseudo[":authority"] == "" || pseudo[":path"] == "" || pseudo[":scheme"] != "https" && pseudo[":scheme"] != "http") {
		return nil, errors.New("invalid MASQUE Extended CONNECT")
	}
	var out []byte
	for _, v := range fields {
		// Only a real :protocol may produce the internal marker; regular headers cannot spoof it.
		if strings.EqualFold(v[0], masqueProtocolHeader) || v[0] == ":protocol" {
			continue
		}
		if protocol != "" && v[0] == ":method" {
			v[1] = "POST"
		}
		out = append(out, 0)
		out = h3Int(out, 7, 0, uint64(len(v[0])))
		out = append(out, v[0]...)
		out = h3Int(out, 7, 0, uint64(len(v[1])))
		out = append(out, v[1]...)
	}
	if protocol != "" {
		out = append(out, 0)
		out = h3Int(out, 7, 0, uint64(len(masqueProtocolHeader)))
		out = append(out, masqueProtocolHeader...)
		out = h3Int(out, 7, 0, uint64(len(protocol)))
		out = append(out, protocol...)
	}
	return out, nil
}

func masqueClientHeaders(fields [][2]string) ([]byte, bool, error) {
	protocol := ""
	for _, v := range fields {
		if strings.EqualFold(v[0], masqueProtocolHeader) {
			if protocol != "" {
				return nil, false, errors.New("duplicate MASQUE protocol marker")
			}
			protocol = v[1]
		}
	}
	if protocol == "" {
		b, e := masqueLiteralHeaders(fields)
		return b, false, e
	}
	var out [][2]string
	inserted := false
	method := ""
	for _, v := range fields {
		if strings.EqualFold(v[0], masqueProtocolHeader) {
			continue
		}
		if v[0] == ":method" {
			method = v[1]
			v[1] = "CONNECT"
		}
		if !strings.HasPrefix(v[0], ":") && !inserted {
			out = append(out, [2]string{":protocol", protocol})
			inserted = true
		}
		out = append(out, v)
	}
	if method != "POST" {
		return nil, false, errors.New("invalid MASQUE request marker")
	}
	if !inserted {
		out = append(out, [2]string{":protocol", protocol})
	}
	b, e := masqueLiteralHeaders(out)
	return b, true, e
}
func masqueLiteralHeaders(fields [][2]string) ([]byte, error) {
	var b []byte
	for _, v := range fields {
		b = append(b, 0)
		b = h3Int(b, 7, 0, uint64(len(v[0])))
		b = append(b, v[0]...)
		b = h3Int(b, 7, 0, uint64(len(v[1])))
		b = append(b, v[1]...)
		if len(b) > 131072 {
			return nil, errors.New("expanded HPACK header exceeds limit")
		}
	}
	return b, nil
}
