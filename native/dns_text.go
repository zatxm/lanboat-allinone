package native

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Keep quotes and escapes for SVCB, whose comma lists have a second escape layer.
func dnsTextFields(text string) ([]string, error) {
	if len(text) > 256<<10 {
		return nil, errors.New("DNS text record too large")
	}
	var fields []string
	start, depth, quoted := -1, 0, false
	flush := func(end int) {
		if start >= 0 {
			fields = append(fields, text[start:end])
			start = -1
		}
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c == '\\' {
			if start < 0 {
				start = i
			}
			i++
			if i == len(text) || text[i] == '\n' || text[i] == '\r' {
				return nil, errors.New("invalid DNS text escape")
			}
			continue
		}
		if c == '"' {
			quoted = !quoted
		}
		if !quoted {
			switch c {
			case ';':
				flush(i)
				for i < len(text) && text[i] != '\n' {
					i++
				}
				continue
			case '(', ')':
				flush(i)
				if c == '(' {
					depth++
				} else {
					depth--
				}
				if depth < 0 || depth > 1 {
					return nil, errors.New("invalid DNS text parentheses")
				}
				continue
			case ' ', '\t', '\r', '\n':
				flush(i)
				continue
			}
		}
		if start < 0 {
			start = i
		}
	}
	if quoted || depth != 0 {
		return nil, errors.New("unterminated DNS text string or parentheses")
	}
	flush(len(text))
	return fields, nil
}

func dnsTextString(s string) (string, error) {
	if strings.HasPrefix(s, "\"") {
		if len(s) < 2 || s[len(s)-1] != '"' {
			return "", errors.New("invalid DNS character string")
		}
		s = s[1 : len(s)-1]
	}
	return svcbUnescape(s)
}

func dnsTextType(s string) (uint16, error) {
	s = strings.ToUpper(s)
	if n, ok := dnsTypeNames[s]; ok {
		return n, nil
	}
	if strings.HasPrefix(s, "TYPE") {
		n, err := strconv.ParseUint(s[4:], 10, 16)
		return uint16(n), err
	}
	return 0, errors.New("unknown DNS RR type; use TYPE<number> and RFC3597 data")
}

func dnsTextTTL(s string) (uint32, error) {
	var total uint64
	for len(s) > 0 {
		n := strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' })
		if n == 0 {
			return 0, errors.New("invalid DNS TTL")
		}
		if n < 0 {
			n = len(s)
		}
		value, err := strconv.ParseUint(s[:n], 10, 32)
		if err != nil {
			return 0, err
		}
		s = s[n:]
		factor := uint64(1)
		if len(s) > 0 {
			switch s[0] | 32 {
			case 'w':
				factor = 604800
			case 'd':
				factor = 86400
			case 'h':
				factor = 3600
			case 'm':
				factor = 60
			case 's':
			default:
				return 0, errors.New("invalid DNS TTL unit")
			}
			s = s[1:]
		}
		total += value * factor
		if total > 1<<32-1 {
			return 0, errors.New("DNS TTL overflow")
		}
	}
	return uint32(total), nil
}

func parseTextRecord(text string) (dnsRecord, error) {
	rr := dnsRecord{class: 1, ttl: 300}
	fields, err := dnsTextFields(text)
	if err != nil {
		return rr, err
	}
	if len(fields) < 2 {
		return rr, errors.New("invalid text DNS record")
	}
	owner, err := dnsAppendName(nil, fields[0])
	if err != nil {
		return rr, err
	}
	rr.name, _, err = dnsName(owner, 0)
	if err != nil {
		return rr, err
	}
	i := 1
	classSet, ttlSet := false, false
	for ; i < len(fields); i++ {
		f := strings.ToUpper(fields[i])
		if f == "IN" || f == "CH" || f == "HS" || f == "CS" || strings.HasPrefix(f, "CLASS") {
			if classSet {
				return rr, errors.New("duplicate DNS class")
			}
			classSet = true
			switch f {
			case "IN":
				rr.class = 1
			case "CS":
				rr.class = 2
			case "CH":
				rr.class = 3
			case "HS":
				rr.class = 4
			default:
				n, e := strconv.ParseUint(f[5:], 10, 16)
				if e != nil {
					return rr, e
				}
				rr.class = uint16(n)
			}
		} else if f[0] >= '0' && f[0] <= '9' {
			if ttlSet {
				return rr, errors.New("duplicate DNS TTL")
			}
			ttlSet = true
			rr.ttl, err = dnsTextTTL(f)
			if err != nil {
				return rr, err
			}
		} else {
			break
		}
	}
	if i == len(fields) {
		return rr, errors.New("missing DNS RR type")
	}
	rr.typ, err = dnsTextType(fields[i])
	if err != nil {
		return rr, err
	}
	rr.data, err = encodeTextRData(rr.typ, fields[i+1:])
	if len(rr.data) > 65535 {
		return rr, errors.New("DNS RDATA exceeds65535 bytes")
	}
	return rr, err
}

func dnsTypeBitmap(values []string) ([]byte, error) {
	var types []uint16
	for _, v := range values {
		typ, err := dnsTextType(v)
		if err != nil {
			return nil, err
		}
		types = append(types, typ)
	}
	slices.Sort(types)
	types = slices.Compact(types)
	var out []byte
	for len(types) > 0 {
		window := types[0] >> 8
		n := 0
		for n < len(types) && types[n]>>8 == window {
			n++
		}
		length := int(byte(types[n-1]))/8 + 1
		start := len(out) + 2
		out = append(out, byte(window), byte(length))
		out = append(out, make([]byte, length)...)
		for _, typ := range types[:n] {
			out[start+int(byte(typ))/8] |= 0x80 >> (typ & 7)
		}
		types = types[n:]
	}
	return out, nil
}

func encodeTextRData(typ uint16, v []string) ([]byte, error) {
	if len(v) >= 2 && v[0] == `\#` {
		n, err := strconv.ParseUint(v[1], 10, 16)
		if err != nil {
			return nil, err
		}
		data, err := hex.DecodeString(strings.Join(v[2:], ""))
		if err != nil || uint64(len(data)) != n {
			return nil, errors.New("invalid RFC3597 data or length")
		}
		return data, nil
	}
	var data []byte
	var err error
	need := func(n int) bool { return len(v) == n }
	uints := func(bits ...int) {
		for _, size := range bits {
			if err != nil || len(v) == 0 {
				err = errors.New("missing or invalid DNS numeric field")
				return
			}
			n, e := strconv.ParseUint(v[0], 10, size)
			err, v = e, v[1:]
			switch size {
			case 8:
				data = append(data, byte(n))
			case 16:
				data = binary.BigEndian.AppendUint16(data, uint16(n))
			case 32:
				data = binary.BigEndian.AppendUint32(data, uint32(n))
			}
		}
	}
	name := func() {
		if err == nil && len(v) > 0 {
			var wire []byte
			wire, err = dnsAppendName(nil, v[0])
			if err == nil {
				var host string
				host, _, err = dnsName(wire, 0)
				if err == nil {
					data, err = dnsAppendName(data, host)
				}
			}
			v = v[1:]
		} else {
			err = errors.New("missing or invalid DNS name")
		}
	}
	chars := func() {
		if err != nil || len(v) == 0 {
			err = errors.New("missing or invalid DNS character string")
			return
		}
		var value string
		value, err = dnsTextString(v[0])
		v = v[1:]
		if len(value) > 255 {
			err = errors.New("DNS character string exceeds255 bytes")
		}
		data = append(append(data, byte(len(value))), value...)
	}
	binaryTail := func(isBase64 bool) {
		if err != nil || len(v) == 0 {
			err = errors.New("missing or invalid DNS binary data")
			return
		}
		var b []byte
		text := strings.Join(v, "")
		if isBase64 {
			b, err = base64.StdEncoding.DecodeString(text)
		} else {
			b, err = hex.DecodeString(text)
		}
		data, v = append(data, b...), nil
	}
	valid := true
	switch typ {
	case 1, 28:
		if valid = need(1); valid {
			ip, e := netip.ParseAddr(v[0])
			if e != nil || typ == 1 != ip.Is4() || ip.Zone() != "" {
				return nil, errors.New("invalid address RR family")
			}
			return ip.AsSlice(), nil
		}
	case 64, 65:
		return encodeSVCB(v)
	case 2, 3, 4, 5, 7, 8, 9, 12, 39:
		if valid = need(1); valid {
			name()
		}
	case 14, 17:
		if valid = need(2); valid {
			name()
			name()
		}
	case 15, 18, 21, 36, 107:
		if valid = need(2); valid {
			uints(16)
			name()
		}
	case 26:
		if valid = need(3); valid {
			uints(16)
			name()
			name()
		}
	case 33:
		if valid = need(4); valid {
			uints(16, 16, 16)
			name()
		}
	case 6:
		if valid = need(7); valid {
			name()
			name()
			uints(32)
			for len(v) > 0 && err == nil {
				var ttl uint32
				ttl, err = dnsTextTTL(v[0])
				data, v = binary.BigEndian.AppendUint32(data, ttl), v[1:]
			}
		}
	case 13:
		if valid = need(2); valid {
			chars()
			chars()
		}
	case 16, 99:
		valid = len(v) > 0
		for len(v) > 0 && err == nil {
			chars()
		}
	case 35:
		if valid = need(6); valid {
			uints(16, 16)
			chars()
			chars()
			chars()
			name()
		}
	case 43, 59, 32769:
		if valid = len(v) >= 4; valid {
			uints(16, 8, 8)
			binaryTail(false)
		}
	case 44:
		if valid = len(v) >= 3; valid {
			uints(8, 8)
			binaryTail(false)
		}
	case 52, 53:
		if valid = len(v) >= 4; valid {
			uints(8, 8, 8)
			binaryTail(false)
		}
	case 25, 48, 60:
		if valid = len(v) >= 4; valid {
			uints(16, 8, 8)
			binaryTail(true)
		}
	case 37:
		if valid = len(v) >= 4; valid {
			uints(16, 16, 8)
			binaryTail(true)
		}
	case 49, 61:
		binaryTail(true)
	case 24, 46:
		if valid = len(v) >= 9; valid {
			covered, e := dnsTextType(v[0])
			if e != nil {
				return nil, e
			}
			data, v = binary.BigEndian.AppendUint16(data, covered), v[1:]
			uints(8, 8)
			if err == nil {
				var ttl uint32
				ttl, err = dnsTextTTL(v[0])
				data, v = binary.BigEndian.AppendUint32(data, ttl), v[1:]
			}
			for range 2 {
				if err != nil {
					break
				}
				if len(v[0]) == 14 {
					var stamp time.Time
					stamp, err = time.Parse("20060102150405", v[0])
					if stamp.Unix() < 0 || stamp.Unix() > 1<<32-1 {
						err = errors.New("DNS signature time outside32-bit range")
					}
					data, v = binary.BigEndian.AppendUint32(data, uint32(stamp.Unix())), v[1:]
				} else {
					uints(32)
				}
			}
			uints(16)
			name()
			binaryTail(true)
		}
	case 47:
		if valid = len(v) >= 1; valid {
			name()
			if err == nil {
				var bitmap []byte
				bitmap, err = dnsTypeBitmap(v)
				data, v = append(data, bitmap...), nil
			}
		}
	case 50, 51:
		minimum := 4
		if typ == 50 {
			minimum++
		}
		if valid = len(v) >= minimum; valid {
			uints(8, 8, 16)
			if err == nil {
				var salt []byte
				if v[0] != "-" {
					salt, err = hex.DecodeString(v[0])
				}
				if len(salt) > 255 {
					err = errors.New("DNS NSEC3 salt too long")
				}
				data, v = append(append(data, byte(len(salt))), salt...), v[1:]
			}
			if typ == 50 && err == nil {
				var hash []byte
				hash, err = base32.HexEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(v[0]))
				if len(hash) == 0 || len(hash) > 255 {
					err = errors.New("invalid DNS NSEC3 hash length")
				}
				data, v = append(append(data, byte(len(hash))), hash...), v[1:]
				if err == nil {
					var bitmap []byte
					bitmap, err = dnsTypeBitmap(v)
					data, v = append(data, bitmap...), nil
				}
			}
		}
	case 62:
		if valid = len(v) >= 2; valid {
			uints(32, 16)
			if err == nil {
				var bitmap []byte
				bitmap, err = dnsTypeBitmap(v)
				data, v = append(data, bitmap...), nil
			}
		}
	case 63:
		if valid = len(v) >= 4; valid {
			uints(32, 8, 8)
			binaryTail(false)
		}
	case 108, 109:
		if valid = need(1); valid {
			data, err = hex.DecodeString(strings.ReplaceAll(v[0], "-", ""))
			want := 6
			if typ == 109 {
				want = 8
			}
			valid, v = len(data) == want, nil
		}
	case 256:
		if valid = need(3); valid {
			uints(16, 16)
			if err == nil {
				var target string
				target, err = dnsTextString(v[0])
				data, v = append(data, target...), nil
			}
		}
	case 257:
		if valid = need(3); valid {
			uints(8)
			if err == nil {
				var tag, value string
				tag, err = dnsTextString(v[0])
				if err == nil {
					value, err = dnsTextString(v[1])
				}
				valid = len(tag) > 0 && len(tag) <= 255
				for _, c := range tag {
					valid = valid && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9')
				}
				data = append(append(append(data, byte(len(tag))), tag...), value...)
				v = nil
			}
		}
	default:
		return nil, errors.New("DNS RR requires RFC3597 data: \\# <length> <hex>")
	}
	if err != nil {
		return nil, err
	}
	if !valid || len(v) != 0 {
		return nil, fmt.Errorf("invalid type%d DNS record fields", typ)
	}
	return data, nil
}
