package native

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type WGHeaderRange string

func (r *WGHeaderRange) UnmarshalJSON(raw []byte) error {
	if string(raw) == "null" {
		return errors.New("AmneziaWG header range cannot be null")
	}
	var s string
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
	} else {
		var value uint32
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		s = strconv.FormatUint(uint64(value), 10)
	}
	*r = WGHeaderRange(s)
	return nil
}

type AmneziaWGOptions struct {
	Jc                     uint16        `json:"jc,omitempty"`
	JMin                   uint16        `json:"jmin,omitempty"`
	JMax                   uint16        `json:"jmax,omitempty"`
	S1                     uint16        `json:"s1,omitempty"`
	S2                     uint16        `json:"s2,omitempty"`
	S3                     uint16        `json:"s3,omitempty"`
	S4                     uint16        `json:"s4,omitempty"`
	H1                     WGHeaderRange `json:"h1,omitempty"`
	H2                     WGHeaderRange `json:"h2,omitempty"`
	H3                     WGHeaderRange `json:"h3,omitempty"`
	H4                     WGHeaderRange `json:"h4,omitempty"`
	I1                     string        `json:"i1,omitempty"`
	I2                     string        `json:"i2,omitempty"`
	I3                     string        `json:"i3,omitempty"`
	I4                     string        `json:"i4,omitempty"`
	I5                     string        `json:"i5,omitempty"`
	HeaderProtectionKey    string        `json:"header_protection_key,omitempty"`
	ContentPaddingAddition WGHeaderRange `json:"content_padding_addition,omitempty"`
	RekeyAfterTime         WGHeaderRange `json:"rekey_after_time,omitempty"`
	RekeyTimeout           WGHeaderRange `json:"rekey_timeout,omitempty"`
	RejectAfterTime        WGHeaderRange `json:"reject_after_time,omitempty"`
	KeepaliveTimeout       WGHeaderRange `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts   WGHeaderRange `json:"max_handshake_attempts,omitempty"`
	PersistentKeepalive    WGHeaderRange `json:"persistent_keepalive_interval,omitempty"`
	RandomTrailers         bool          `json:"random_trailers,omitempty"`
	DisableCookies         bool          `json:"disable_cookies,omitempty"`
}

type wgMagic struct{ low, high uint32 }
type wgSignaturePart struct {
	tag  string
	size int
	data []byte
}
type wgSignature struct {
	size  int
	parts []wgSignaturePart
}
type wgObfuscation struct {
	mask           *wgMask
	headers        [4]wgMagic
	padding        [4]int
	signatures     []wgSignature
	jc, jmin, jmax int
	v3             wgV3
}

func parseWGMagic(raw WGHeaderRange, fallback uint32) (wgMagic, error) {
	if raw == "" {
		return wgMagic{fallback, fallback}, nil
	}
	first, last, hasRange := strings.Cut(string(raw), "-")
	a, err := strconv.ParseUint(first, 10, 32)
	if err != nil {
		return wgMagic{}, errors.New("invalid AmneziaWG header range")
	}
	b := a
	if hasRange {
		b, err = strconv.ParseUint(last, 10, 32)
		if err != nil || a > b {
			return wgMagic{}, errors.New("invalid AmneziaWG header range")
		}
	}
	return wgMagic{uint32(a), uint32(b)}, nil
}

func parseWGSignature(raw string) (wgSignature, error) {
	var signature wgSignature
	if len(raw) > 131072 {
		return signature, errors.New("AmneziaWG signature exceeds128KiB")
	}
	timestamp := false
	for strings.TrimSpace(raw) != "" {
		raw = strings.TrimSpace(raw)
		if raw[0] != '<' {
			return signature, errors.New("AmneziaWG CPS requires angle-bracket tags")
		}
		body, rest, ok := strings.Cut(raw[1:], ">")
		if !ok {
			return signature, errors.New("unterminated AmneziaWG CPS tag")
		}
		raw = rest
		fields := strings.Fields(body)
		if len(fields) == 0 {
			return signature, errors.New("empty AmneziaWG CPS tag")
		}
		part := wgSignaturePart{tag: fields[0]}
		switch part.tag {
		case "t":
			if len(fields) != 1 || timestamp {
				return signature, errors.New("CPS timestamp must occur once per packet")
			}
			timestamp = true
			part.size = 4
		case "b":
			if len(fields) != 2 {
				return signature, errors.New("CPS bytes require one hex value")
			}
			var err error
			part.data, err = hex.DecodeString(strings.TrimPrefix(fields[1], "0x"))
			if err != nil || len(part.data) == 0 {
				return signature, errors.New("invalid CPS hex bytes")
			}
			part.size = len(part.data)
		case "r", "rc", "rd":
			if len(fields) != 2 {
				return signature, errors.New("CPS random tag requires a length")
			}
			n, err := strconv.ParseUint(fields[1], 10, 16)
			if err != nil || n > 1000 {
				return signature, errors.New("CPS random length must be0-1000")
			}
			part.size = int(n)
		default:
			return signature, fmt.Errorf("unknown CPS tag %q", part.tag)
		}
		signature.size += part.size
		if signature.size > 65507 || len(signature.parts) >= 256 {
			return signature, errors.New("CPS packet exceeds UDP or256-tag budget")
		}
		signature.parts = append(signature.parts, part)
	}
	if signature.size == 0 {
		return signature, errors.New("empty AmneziaWG signature")
	}
	return signature, nil
}

func newWGObfuscation(options *AmneziaWGOptions, mask *WGObfsOptions, mtu int) (*wgObfuscation, error) {
	if mtu == 0 {
		mtu = 1420
	}
	if ((mtu+15)&^15)+32 > 65507 {
		return nil, errors.New("WireGuard MTU plus encryption overhead exceeds65507 bytes")
	}
	if mask != nil {
		if options != nil {
			return nil, errors.New("amnezia and wgobfs cannot be combined")
		}
		if ((mtu+15)&^15)+32+8 > 65507 {
			return nil, errors.New("WireGuard MTU plus wgobfs padding exceeds65507 bytes")
		}
		return &wgObfuscation{mask: newWGMask(mask.Password)}, nil
	}
	if options == nil {
		return nil, nil
	}
	o := options
	c := &wgObfuscation{padding: [4]int{int(o.S1), int(o.S2), int(o.S3), int(o.S4)}, jc: int(o.Jc), jmin: int(o.JMin), jmax: int(o.JMax)}
	if err := c.v3.configure(o, c.padding, mtu); err != nil {
		return nil, err
	}
	for i, raw := range []WGHeaderRange{o.H1, o.H2, o.H3, o.H4} {
		var err error
		c.headers[i], err = parseWGMagic(raw, uint32(i+1))
		if err != nil {
			return nil, err
		}
		for j := 0; j < i; j++ {
			if c.headers[i].low <= c.headers[j].high && c.headers[j].low <= c.headers[i].high {
				return nil, errors.New("AmneziaWG H1-H4 ranges must not overlap")
			}
		}
	}
	for i, size := range []int{148, 92, 64, 32} {
		if c.padding[i]+size > 65507 {
			return nil, errors.New("AmneziaWG prefix exceeds UDP packet capacity")
		}
	}
	if (mtu+15)&^15+32+c.padding[3] > 65507 {
		return nil, errors.New("WireGuard MTU plus AmneziaWG overhead exceeds65507 bytes")
	}
	if c.jmin > c.jmax || c.jmax > 65507 || c.jc*c.jmax > 1<<20 {
		return nil, errors.New("AmneziaWG junk train must fit1MiB with jmin<=jmax<=65507")
	}
	if c.jc > 0 && c.jmax == 0 {
		return nil, errors.New("AmneziaWG junk packets require jmax>0")
	}
	for _, raw := range []string{o.I1, o.I2, o.I3, o.I4, o.I5} {
		if raw == "" {
			continue
		}
		signature, err := parseWGSignature(raw)
		if err != nil {
			return nil, err
		}
		c.signatures = append(c.signatures, signature)
	}
	return c, nil
}

func wgRandomRange(low, high uint32) uint32 {
	if low == high {
		return low
	}
	span := uint64(high) - uint64(low) + 1
	limit := uint64(1) << 32
	limit -= limit % span
	var raw [4]byte
	for {
		rand.Read(raw[:])
		n := uint64(binary.LittleEndian.Uint32(raw[:]))
		if n < limit {
			return low + uint32(n%span)
		}
	}
}

func (c *wgObfuscation) header(kind uint32) uint32 {
	if c == nil || c.mask != nil {
		return kind
	}
	r := c.headers[kind-1]
	return wgRandomRange(r.low, r.high)
}

func (c *wgObfuscation) prefix(kind uint32) int {
	if c == nil {
		return 0
	}
	return c.padding[kind-1]
}

func (c *wgObfuscation) decode(packet []byte) ([]byte, uint32) {
	if c != nil && c.mask != nil {
		return c.mask.decode(packet)
	}
	if c == nil {
		if len(packet) < 4 {
			return nil, 0
		}
		return packet, binary.LittleEndian.Uint32(packet)
	}
	for i, minSize := range []int{148, 92, 64, 32} {
		size := len(packet) - c.padding[i]
		if size < minSize || i < 3 && size != minSize && !c.v3.trailers {
			continue
		}
		body := packet[c.padding[i]:]
		magic := binary.LittleEndian.Uint32(body)
		if c.v3.key != nil {
			block := chachaBlock(c.v3.key, packet[:12], 0)
			magic ^= binary.LittleEndian.Uint32(block[:4])
		}
		if magic >= c.headers[i].low && magic <= c.headers[i].high {
			if i < 3 {
				body = body[:minSize]
			}
			if c.v3.key != nil {
				n := len(body)
				if i == 3 {
					n = 16
				}
				wgHeaderXOR(body[:n], c.v3.key, packet[:12])
			}
			return body, uint32(i + 1)
		}
	}
	return nil, 0
}

func (c *wgObfuscation) wrap(kind uint32, body []byte) []byte {
	if c != nil && c.mask != nil {
		return c.mask.encode(append(make([]byte, 0, len(body)+32), body...))
	}
	n := c.prefix(kind)
	trailer := 0
	if c != nil && c.v3.trailers && kind < 4 && n+len(body) < 500 {
		trailer = int(wgRandomRange(0, uint32(499-n-len(body))))
	}
	if n == 0 && trailer == 0 {
		return body
	}
	packet := make([]byte, n+len(body)+trailer)
	rand.Read(packet[:n])
	copy(packet[n:], body)
	rand.Read(packet[n+len(body):])
	if c != nil && c.v3.key != nil {
		size := len(body)
		if kind == 4 {
			size = min(16, size)
		}
		wgHeaderXOR(packet[n:n+size], c.v3.key, packet[:12])
	}
	return packet
}

func (s wgSignature) packet() []byte {
	packet := make([]byte, s.size)
	position := 0
	for _, part := range s.parts {
		field := packet[position : position+part.size]
		position += part.size
		switch part.tag {
		case "b":
			copy(field, part.data)
		case "t":
			binary.BigEndian.PutUint32(field, uint32(time.Now().Unix()))
		case "r":
			rand.Read(field)
		case "rc", "rd":
			alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
			if part.tag == "rd" {
				alphabet = "0123456789"
			}
			for i := range field {
				field[i] = alphabet[wgRandomRange(0, uint32(len(alphabet)-1))]
			}
		}
	}
	return packet
}

func (c *wgObfuscation) decoys(ctx context.Context, send func([]byte) error) error {
	if c == nil {
		return nil
	}
	for _, signature := range c.signatures {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := send(signature.packet()); err != nil {
			return err
		}
	}
	for range c.jc {
		if err := ctx.Err(); err != nil {
			return err
		}
		packet := make([]byte, wgRandomRange(uint32(c.jmin), uint32(c.jmax)))
		rand.Read(packet)
		if err := send(packet); err != nil {
			return err
		}
	}
	return nil
}
