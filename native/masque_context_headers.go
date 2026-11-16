package native

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

const masqueContextsHeader = "http-datagram-contexts"

type masqueContextCapabilities struct {
	templates, segments, mtu int
	derived                  uint16
	checksum                 bool
}

func masqueLocalContexts(protocol string) masqueContextCapabilities {
	c := masqueContextCapabilities{templates: 32, segments: 16, mtu: 65535, checksum: true}
	if protocol == "connect-ip" {
		c.derived = 511
	}
	return c
}

func masqueContextsAdvertisement(protocol string) string {
	if protocol != "connect-ip" && protocol != "connect-udp" {
		return ""
	}
	derived := ""
	if protocol == "connect-ip" {
		derived = ", derived=(0 1 2 3 4 5 6 7 8)"
	}
	return "max-templates=32, max-templates-segments=16, checksum=?1, mtu=65535" + derived
}

// Invalid optional negotiation is ignored; a peer must not use capabilities it never received.
func masqueContextsResponse(protocol, request string) string {
	if request == "" {
		return ""
	}
	if _, err := parseMasqueContextCapabilities(request); err != nil {
		return ""
	}
	return masqueContextsAdvertisement(protocol)
}

type masqueStructuredItem struct {
	kind        byte
	n           int64
	mask        uint16
	integerList bool
}
type masqueStructuredReader struct {
	s  string
	at int
}

var errMasqueStructured = errors.New("invalid MASQUE context capabilities")

func (r *masqueStructuredReader) spaces(chars string) {
	for r.at < len(r.s) && strings.ContainsRune(chars, rune(r.s[r.at])) {
		r.at++
	}
}
func (r *masqueStructuredReader) key() (string, error) {
	start := r.at
	for r.at < len(r.s) {
		c := r.s[r.at]
		if c >= 'a' && c <= 'z' || c == '*' || r.at > start && (c >= '0' && c <= '9' || strings.ContainsRune("_-.", rune(c))) {
			r.at++
			continue
		}
		break
	}
	if start == r.at {
		return "", errMasqueStructured
	}
	return r.s[start:r.at], nil
}
func (r *masqueStructuredReader) item() (masqueStructuredItem, error) {
	var v masqueStructuredItem
	if r.at == len(r.s) {
		return v, errMasqueStructured
	}
	first := r.s[r.at]
	r.at++
	switch {
	case first == '(':
		v.kind = '('
		v.integerList = true
		r.spaces(" ")
		for n := 0; r.at < len(r.s) && r.s[r.at] != ')'; n++ {
			if n >= 512 {
				return v, errMasqueStructured
			}
			if r.s[r.at] == '(' {
				return v, errMasqueStructured
			}
			item, err := r.item()
			if err != nil {
				return v, err
			}
			if item.kind != 'i' || item.n < 0 {
				v.integerList = false
			} else if item.n < 9 {
				v.mask |= 1 << item.n
			}
			if err = r.parameters(); err != nil {
				return v, err
			}
			if r.at < len(r.s) && r.s[r.at] != ')' && r.s[r.at] != ' ' {
				return v, errMasqueStructured
			}
			r.spaces(" ")
		}
		if r.at == len(r.s) {
			return v, errMasqueStructured
		}
		r.at++
	case first == '?':
		v.kind = 'b'
		if r.at == len(r.s) || r.s[r.at] != '0' && r.s[r.at] != '1' {
			return v, errMasqueStructured
		}
		v.n = int64(r.s[r.at] - '0')
		r.at++
	case first == '"' || first == '%':
		if first == '%' {
			if r.at == len(r.s) || r.s[r.at] != '"' {
				return v, errMasqueStructured
			}
			r.at++
		}
		v.kind = 's'
		start := r.at
		closed := false
		for r.at < len(r.s) {
			c := r.s[r.at]
			r.at++
			if c == '"' {
				if first == '%' {
					decoded, err := url.PathUnescape(r.s[start : r.at-1])
					if err != nil || !utf8.ValidString(decoded) {
						return v, errMasqueStructured
					}
				}
				closed = true
				break
			}
			if c < 0x20 || c > 0x7e {
				return v, errMasqueStructured
			}
			if c == '\\' && first == '"' {
				if r.at == len(r.s) || r.s[r.at] != '"' && r.s[r.at] != '\\' {
					return v, errMasqueStructured
				}
				r.at++
			}
			if c == '%' && first == '%' {
				if r.at+2 > len(r.s) {
					return v, errMasqueStructured
				}
				for _, digit := range r.s[r.at : r.at+2] {
					if !strings.ContainsRune("0123456789abcdef", digit) {
						return v, errMasqueStructured
					}
				}
				r.at += 2
			}
		}
		if !closed {
			return v, errMasqueStructured
		}
	case first == ':':
		v.kind = 'x'
		end := strings.IndexByte(r.s[r.at:], ':')
		if end < 0 {
			return v, errMasqueStructured
		}
		encoded := r.s[r.at : r.at+end]
		if strings.ContainsAny(encoded, "\r\n") {
			return v, errMasqueStructured
		}
		if _, err := base64.StdEncoding.DecodeString(encoded); err != nil {
			if strings.ContainsRune(encoded, '=') {
				return v, errMasqueStructured
			}
			if _, err = base64.RawStdEncoding.DecodeString(encoded); err != nil {
				return v, errMasqueStructured
			}
		}
		r.at += end + 1
	case first == '-' || first >= '0' && first <= '9' || first == '@':
		start := r.at - 1
		v.kind = 'i'
		if first == '@' {
			start = r.at
			if r.at < len(r.s) && r.s[r.at] == '-' {
				r.at++
			}
			v.kind = 'd'
		}
		digits := r.at
		for r.at < len(r.s) && r.s[r.at] >= '0' && r.s[r.at] <= '9' {
			r.at++
		}
		if r.at == digits && (first == '-' || first == '@') {
			return v, errMasqueStructured
		}
		numberStart := start
		if r.s[numberStart] == '-' {
			numberStart++
		}
		integerDigits := r.at - numberStart
		if integerDigits > 15 {
			return v, errMasqueStructured
		}
		if r.at < len(r.s) && r.s[r.at] == '.' && first != '@' {
			v.kind = 'f'
			r.at++
			fraction := r.at
			for r.at < len(r.s) && r.s[r.at] >= '0' && r.s[r.at] <= '9' {
				r.at++
			}
			if r.at-fraction < 1 || r.at-fraction > 3 || integerDigits > 12 {
				return v, errMasqueStructured
			}
		} else {
			n, e := strconv.ParseInt(r.s[start:r.at], 10, 64)
			if e != nil || n > 999999999999999 || n < -999999999999999 {
				return v, errMasqueStructured
			}
			v.n = n
		}
	default:
		if !(first >= 'A' && first <= 'Z' || first >= 'a' && first <= 'z' || first == '*') {
			return v, errMasqueStructured
		}
		v.kind = 't'
		for r.at < len(r.s) {
			c := r.s[r.at]
			if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~:/", rune(c)) {
				r.at++
			} else {
				break
			}
		}
	}
	return v, nil
}
func (r *masqueStructuredReader) parameters() error {
	for r.at < len(r.s) && r.s[r.at] == ';' {
		r.at++
		r.spaces(" ")
		if _, err := r.key(); err != nil {
			return err
		}
		if r.at < len(r.s) && r.s[r.at] == '=' {
			r.at++
			if r.at < len(r.s) && r.s[r.at] == '(' {
				return errMasqueStructured
			}
			if _, err := r.item(); err != nil {
				return err
			}
		}
	}
	return nil
}
func parseMasqueContextCapabilities(s string) (masqueContextCapabilities, error) {
	c := masqueContextCapabilities{mtu: 65535}
	if len(s) == 0 || len(s) > 4096 {
		return c, errMasqueStructured
	}
	r := masqueStructuredReader{s: s}
	for count := 0; ; count++ {
		if count >= 128 {
			return c, errMasqueStructured
		}
		r.spaces(" \t")
		key, e := r.key()
		if e != nil {
			return c, e
		}
		v := masqueStructuredItem{kind: 'b', n: 1}
		if r.at < len(s) && s[r.at] == '=' {
			r.at++
			v, e = r.item()
			if e != nil {
				return c, e
			}
		}
		if e = r.parameters(); e != nil {
			return c, e
		}
		switch key {
		case "max-templates", "max-templates-segments", "mtu":
			if v.kind != 'i' || v.n < 0 {
				return c, errMasqueStructured
			}
			n := int(min(v.n, 65536))
			switch key {
			case "max-templates":
				c.templates = n
			case "max-templates-segments":
				c.segments = n
			case "mtu":
				c.mtu = n
			}
		case "checksum":
			if v.kind != 'b' {
				return c, errMasqueStructured
			}
			c.checksum = v.n == 1
		case "derived":
			if v.kind != '(' || !v.integerList {
				return c, errMasqueStructured
			}
			c.derived = v.mask
		}
		r.spaces(" \t")
		if r.at == len(s) {
			return c, nil
		}
		if s[r.at] != ',' {
			return c, errMasqueStructured
		}
		r.at++
	}
}
