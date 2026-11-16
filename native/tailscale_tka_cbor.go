package native

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"unicode/utf8"
)

// Tailnet Lock uses CTAP2 CBOR: definite lengths, no tags, canonical map keys.
// This codec deliberately accepts only the wire types used by the authority.
type tsCBOR map[any]any

var errTKAEncoding = errors.New("invalid Tailnet Lock CBOR")

func tsCBORHead(dst []byte, kind byte, n uint64) []byte {
	switch {
	case n < 24:
		return append(dst, kind<<5|byte(n))
	case n <= 255:
		return append(dst, kind<<5|24, byte(n))
	case n <= 65535:
		return binary.BigEndian.AppendUint16(append(dst, kind<<5|25), uint16(n))
	case n <= 0xffffffff:
		return binary.BigEndian.AppendUint32(append(dst, kind<<5|26), uint32(n))
	default:
		return binary.BigEndian.AppendUint64(append(dst, kind<<5|27), n)
	}
}
func tsCBOREncode(dst []byte, value any) []byte {
	switch v := value.(type) {
	case nil:
		return append(dst, 0xf6)
	case uint64:
		return tsCBORHead(dst, 0, v)
	case []byte:
		if v == nil {
			return append(dst, 0xf6)
		}
		return append(tsCBORHead(dst, 2, uint64(len(v))), v...)
	case string:
		return append(tsCBORHead(dst, 3, uint64(len(v))), v...)
	case []any:
		dst = tsCBORHead(dst, 4, uint64(len(v)))
		for _, item := range v {
			dst = tsCBOREncode(dst, item)
		}
		return dst
	case tsCBOR:
		type item struct {
			key   []byte
			value any
		}
		items := make([]item, 0, len(v))
		for k, value := range v {
			items = append(items, item{tsCBOREncode(nil, k), value})
		}
		sort.Slice(items, func(i, j int) bool { return bytes.Compare(items[i].key, items[j].key) < 0 })
		dst = tsCBORHead(dst, 5, uint64(len(items)))
		for _, item := range items {
			dst = append(dst, item.key...)
			dst = tsCBOREncode(dst, item.value)
		}
		return dst
	default:
		panic("invalid internal TKA wire type")
	}
}

type tsCBORReader struct {
	b     []byte
	items int
}

func (r *tsCBORReader) value(depth int) (any, error) {
	r.items++
	if depth > 16 || r.items > 32768 || len(r.b) == 0 {
		return nil, errTKAEncoding
	}
	tag := r.b[0]
	r.b = r.b[1:]
	if tag == 0xf6 {
		return nil, nil
	}
	kind, n := tag>>5, uint64(tag&31)
	if kind != 0 && kind != 2 && kind != 3 && kind != 4 && kind != 5 {
		return nil, errTKAEncoding
	}
	if n >= 24 {
		var size int
		switch n {
		case 24:
			size = 1
		case 25:
			size = 2
		case 26:
			size = 4
		case 27:
			size = 8
		default:
			return nil, errTKAEncoding
		}
		if len(r.b) < size {
			return nil, errTKAEncoding
		}
		n = 0
		for _, b := range r.b[:size] {
			n = n<<8 | uint64(b)
		}
		r.b = r.b[size:]
	}
	switch kind {
	case 0:
		return n, nil
	case 2, 3:
		if n > uint64(len(r.b)) {
			return nil, errTKAEncoding
		}
		b := r.b[:int(n)]
		r.b = r.b[int(n):]
		if kind == 3 {
			if !utf8.Valid(b) {
				return nil, errTKAEncoding
			}
			return string(b), nil
		}
		return bytes.Clone(b), nil
	case 4:
		if n > 4096 {
			return nil, errTKAEncoding
		}
		a := make([]any, int(n))
		for i := range a {
			v, e := r.value(depth + 1)
			if e != nil {
				return nil, e
			}
			a[i] = v
		}
		return a, nil
	case 5:
		if n > 1024 {
			return nil, errTKAEncoding
		}
		m := make(tsCBOR, int(n))
		for range n {
			key, e := r.value(depth + 1)
			if e != nil {
				return nil, e
			}
			switch key.(type) {
			case uint64, string:
			default:
				return nil, errTKAEncoding
			}
			if _, ok := m[key]; ok {
				return nil, errTKAEncoding
			}
			v, e := r.value(depth + 1)
			if e != nil {
				return nil, e
			}
			m[key] = v
		}
		return m, nil
	}
	return nil, errTKAEncoding
}
func tsCBORDecode(b []byte) (tsCBOR, error) {
	if len(b) > 1<<20 {
		return nil, errTKAEncoding
	}
	r := tsCBORReader{b: b}
	v, e := r.value(0)
	m, ok := v.(tsCBOR)
	if e != nil || !ok || len(r.b) != 0 {
		return nil, errTKAEncoding
	}
	return m, nil
}
func (m tsCBOR) bytes(k uint64) []byte  { b, _ := m[k].([]byte); return b }
func (m tsCBOR) num(k uint64) uint64    { n, _ := m[k].(uint64); return n }
func (m tsCBOR) object(k uint64) tsCBOR { v, _ := m[k].(tsCBOR); return v }
func (m tsCBOR) array(k uint64) []any   { v, _ := m[k].([]any); return v }
func (m tsCBOR) only(keys ...uint64) bool {
	for k := range m {
		ok := false
		for _, allowed := range keys {
			if k == allowed {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
func tsTKAUnsigned(m tsCBOR, signature uint64) []byte {
	out := make(tsCBOR, len(m))
	for k, v := range m {
		if k != signature {
			out[k] = v
		}
	}
	return tsCBOREncode(nil, out)
}
