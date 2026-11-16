package native

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strings"
)

// Peers may finish reading an already-written request before its FIN arrives,
// using H3_NO_ERROR or the legacy QUIC code0.
// The caller must still read and validate the response status.
func h3FinishRequest(s *quicStream) error {
	err := s.CloseWrite()
	var stop *quicStreamStopError
	if errors.As(err, &stop) && (stop.code == 0 || stop.code == 0x100) {
		return nil
	}
	return err
}

func readQUICVar(r io.Reader) (uint64, error) {
	var b [8]byte
	if _, e := io.ReadFull(r, b[:1]); e != nil {
		return 0, e
	}
	n := 1 << uint(b[0]>>6)
	if _, e := io.ReadFull(r, b[1:n]); e != nil {
		return 0, e
	}
	q := quicReader(b[:n])
	return q.v()
}
func readQUICString(r io.Reader, limit uint64) (string, error) {
	n, e := readQUICVar(r)
	if e != nil {
		return "", e
	}
	if n > limit {
		return "", errors.New("QUIC string exceeds limit")
	}
	b := make([]byte, n)
	_, e = io.ReadFull(r, b)
	return string(b), e
}
func h3Int(b []byte, prefix uint, first byte, v uint64) []byte {
	mask := uint64(1<<prefix) - 1
	if v < mask {
		return append(b, first|byte(v))
	}
	b = append(b, first|byte(mask))
	v -= mask
	for v >= 128 {
		b = append(b, byte(v)|128)
		v >>= 7
	}
	return append(b, byte(v))
}
func h3ReadInt(r *quicReader, prefix uint) (uint64, error) {
	if len(*r) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	mask := uint64(1<<prefix) - 1
	n := uint64((*r)[0]) & mask
	*r = (*r)[1:]
	if n < mask {
		return n, nil
	}
	for shift := uint(0); shift <= 56; shift += 7 {
		b, e := r.take(1)
		if e != nil {
			return 0, e
		}
		n += uint64(b[0]&127) << shift
		if b[0]&128 == 0 {
			return n, nil
		}
	}
	return 0, errors.New("QPACK integer overflow")
}

type h3HuffNode struct {
	child  [2]int
	symbol int
}

var h3HuffTree = func() []h3HuffNode {
	nodes := []h3HuffNode{{symbol: -1}}
	for symbol, code := range h3HuffmanCodes {
		p := 0
		for bit := int(h3HuffmanBits[symbol]) - 1; bit >= 0; bit-- {
			v := int(code >> bit & 1)
			next := nodes[p].child[v]
			if next == 0 {
				next = len(nodes)
				nodes[p].child[v] = next
				nodes = append(nodes, h3HuffNode{symbol: -1})
			}
			p = next
		}
		nodes[p].symbol = symbol
	}
	return nodes
}()

func h3Huffman(b []byte) (string, error) {
	out := make([]byte, 0, len(b)*2)
	p, pad := 0, 0
	ones := true
	for _, v := range b {
		for bit := 7; bit >= 0; bit-- {
			x := int(v >> bit & 1)
			p = h3HuffTree[p].child[x]
			if p == 0 {
				return "", errors.New("invalid QPACK Huffman code")
			}
			pad++
			ones = ones && x == 1
			symbol := h3HuffTree[p].symbol
			if symbol >= 0 {
				if symbol == 256 || len(out) >= 65536 {
					return "", errors.New("invalid QPACK Huffman symbol")
				}
				out = append(out, byte(symbol))
				p, pad, ones = 0, 0, true
			}
		}
	}
	if p != 0 && (pad > 7 || !ones) {
		return "", errors.New("invalid QPACK Huffman padding")
	}
	return string(out), nil
}
func h3ReadText(r *quicReader, prefix uint, huff byte) (string, error) {
	if len(*r) == 0 {
		return "", io.ErrUnexpectedEOF
	}
	encoded := (*r)[0]&huff != 0
	n, e := h3ReadInt(r, prefix)
	if e != nil {
		return "", e
	}
	b, e := r.take(n)
	if e != nil {
		return "", e
	}
	if encoded {
		return h3Huffman(b)
	}
	return string(b), nil
}
func h3Encode(headers [][2]string) []byte {
	out := []byte{0, 0}
	for _, h := range headers {
		out = h3Int(out, 3, 0x20, uint64(len(h[0])))
		out = append(out, h[0]...)
		out = h3Int(out, 7, 0, uint64(len(h[1])))
		out = append(out, h[1]...)
	}
	return out
}
func h3Decode(b []byte) (map[string]string, error) {
	return h3DecodeHeaders(b, nil)
}

func h3DecodeHeaders(b []byte, headers http.Header) (map[string]string, error) {
	r := quicReader(b)
	required, e := h3ReadInt(&r, 8)
	if e != nil || required != 0 {
		return nil, errors.New("QPACK dynamic table was not negotiated")
	}
	base, e := h3ReadInt(&r, 7)
	if e != nil || base != 0 {
		return nil, errors.New("invalid QPACK base")
	}
	h := map[string]string{}
	total := 0
	fields := 0
	regular := false
	for len(r) > 0 {
		first := r[0]
		var k, v string
		switch {
		case first&0x80 != 0:
			if first&0x40 == 0 {
				return nil, errors.New("invalid QPACK dynamic reference")
			}
			index, e := h3ReadInt(&r, 6)
			if e != nil || index >= uint64(len(h3Static)) {
				return nil, errors.New("invalid QPACK static reference")
			}
			k, v = h3Static[index][0], h3Static[index][1]
		case first&0xc0 == 0x40:
			if first&0x10 == 0 {
				return nil, errors.New("invalid QPACK dynamic name")
			}
			index, e := h3ReadInt(&r, 4)
			if e != nil || index >= uint64(len(h3Static)) {
				return nil, errors.New("invalid QPACK static name")
			}
			k = h3Static[index][0]
			v, e = h3ReadText(&r, 7, 0x80)
			if e != nil {
				return nil, e
			}
		case first&0xe0 == 0x20:
			k, e = h3ReadText(&r, 3, 8)
			if e != nil {
				return nil, e
			}
			v, e = h3ReadText(&r, 7, 0x80)
			if e != nil {
				return nil, e
			}
		default:
			return nil, errors.New("invalid QPACK field representation")
		}
		total += len(k) + len(v)
		fields++
		if total > 65536 || fields > 256 || k == "" || k != strings.ToLower(k) || strings.ContainsAny(k+v, "\r\n\x00") {
			return nil, errors.New("invalid HTTP3 headers")
		}
		if _, ok := h[k]; ok && (headers == nil || strings.HasPrefix(k, ":") || k == "content-length") {
			return nil, errors.New("duplicate HTTP3 header")
		}
		if strings.HasPrefix(k, ":") {
			if regular {
				return nil, errors.New("HTTP3 pseudo-header follows ordinary header")
			}
		} else {
			regular = true
			if headers != nil {
				if err := validateHTTPHeader(k, []string{v}); err != nil {
					return nil, err
				}
				switch k {
				case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
					return nil, errors.New("HTTP3 forbids connection-specific headers")
				}
				headers.Add(k, v)
			}
		}
		h[k] = v
	}
	return h, nil
}
func h3WriteFrame(w io.Writer, kind uint64, b []byte) error {
	header := quicVar(nil, kind)
	header = quicVar(header, uint64(len(b)))
	if e := writeAll(w, header); e != nil {
		return e
	}
	return writeAll(w, b)
}
func h3ReadFrame(r io.Reader) (uint64, []byte, error) {
	kind, e := readQUICVar(r)
	if e != nil {
		return 0, nil, e
	}
	n, e := readQUICVar(r)
	if e != nil {
		return 0, nil, e
	}
	if n > 65536 {
		return 0, nil, errors.New("HTTP3 frame exceeds limit")
	}
	b := make([]byte, n)
	_, e = io.ReadFull(r, b)
	return kind, b, e
}
func h3Start(ctx context.Context, c *quicConn) error {
	return h3StartSettings(ctx, c, nil)
}
func h3StartSettings(ctx context.Context, c *quicConn, extra [][2]uint64) error {
	s, e := c.OpenStream(ctx, true)
	if e != nil {
		return e
	}
	if e = writeAll(s, []byte{0}); e != nil {
		return e
	}
	settings := quicVar(nil, 1)
	settings = quicVar(settings, 0)
	settings = quicVar(settings, 6)
	settings = quicVar(settings, 65536)
	settings = quicVar(settings, 8)
	settings = quicVar(settings, 1)
	for _, setting := range extra {
		settings = quicVar(settings, setting[0])
		settings = quicVar(settings, setting[1])
	}
	return h3WriteFrame(s, 4, settings)
}
func h3Uni(s *quicStream) error {
	kind, e := readQUICVar(s)
	if e != nil {
		return e
	}
	return h3UniBody(s, kind, nil)
}
func h3UniBody(s *quicStream, kind uint64, observe func(map[uint64]uint64) error) error {
	switch kind {
	case 0:
		first := true
		for {
			frame, b, e := h3ReadFrame(s)
			if e != nil {
				return e
			}
			if first && frame != 4 {
				return errors.New("missing HTTP3 settings")
			}
			if !first && frame == 4 {
				return errors.New("duplicate HTTP3 SETTINGS frame")
			}
			first = false
			if frame == 4 {
				r := quicReader(b)
				seen := map[uint64]bool{}
				settings := map[uint64]uint64{}
				for len(r) > 0 {
					id, e := r.v()
					if e != nil {
						return e
					}
					n, e := r.v()
					if e != nil {
						return e
					}
					if seen[id] {
						return errors.New("duplicate HTTP3 setting")
					}
					seen[id] = true
					if id >= 2 && id <= 5 {
						return errors.New("forbidden HTTP3 setting")
					}
					settings[id] = n
				}
				if observe != nil {
					if e := observe(settings); e != nil {
						return e
					}
				}
			}
		}
	case 2:
		for {
			r := make([]byte, 1)
			_, e := io.ReadFull(s, r)
			if e != nil {
				return e
			}
			if r[0] != 0x20 {
				return errors.New("QPACK capacity is zero")
			}
		}
	case 3:
		_, e := io.CopyN(io.Discard, s, 65536)
		return e
	default:
		// Unknown unidirectional streams (including GREASE) are not critical.
		_, _ = io.CopyN(io.Discard, s, 65536)
		return nil
	}
}
func h3Status(s *quicStream, headers ...http.Header) (map[string]string, error) {
	for {
		kind, b, e := h3ReadFrame(s)
		if e != nil {
			return nil, e
		}
		if kind == 1 {
			if len(headers) > 0 {
				return h3DecodeHeaders(b, headers[0])
			}
			return h3Decode(b)
		}
		if kind == 0 {
			return nil, errors.New("HTTP3 DATA before HEADERS")
		}
	}
}
func quicU16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }
