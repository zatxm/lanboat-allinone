package native

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type snellObfsOptions struct {
	Type string `json:"type"`
	Host string `json:"host,omitempty"`
	Path string `json:"path,omitempty"`
}

func (o Obfuscation) snellOptions(host, version string) (snellObfsOptions, error) {
	if snellVersion(version) == 6 && (o != "" && o != "none" || host != "") {
		return snellObfsOptions{}, errors.New("legacy obfs requires Snell version 1-5")
	}
	v := snellObfsOptions{Host: host, Path: "/"}
	if o == "" || o == "none" {
		return v, nil
	}
	if o[0] == '{' {
		if e := json.Unmarshal([]byte(o), &v); e != nil {
			return v, e
		}
	} else {
		v.Type = string(o)
	}
	if v.Type != "http" && v.Type != "tls" {
		return v, errors.New("Snell obfs must be http or tls")
	}
	if v.Type == "tls" && snellVersion(version) >= 4 {
		return v, errors.New("Snell4/5 support only HTTP obfuscation;TLS obfuscation requires version1-3")
	}
	if v.Host == "" {
		v.Host = "cloudfront.net"
	}
	if !validHTTPHost(v.Host) || len(v.Host) > 253 || v.Path == "" || v.Path[0] != '/' || strings.ContainsAny(v.Path, "\r\n\x00 ") {
		return v, errors.New("invalid Snell obfs host or path")
	}
	return v, nil
}

type snellObfsConn struct {
	net.Conn
	options             snellObfsOptions
	server, sent, hello bool
	rmu, wmu            sync.Mutex
	reader              *bufio.Reader
	pending             []byte
}

func dialSnellObfs(raw net.Conn, o Outbound) (net.Conn, error) {
	v, e := o.Obfs.snellOptions(o.ObfsParam, o.Version)
	if e != nil {
		return nil, e
	}
	if v.Type == "" {
		return raw, nil
	}
	return &snellObfsConn{Conn: raw, options: v}, nil
}
func acceptSnellObfs(raw net.Conn, in Inbound) (net.Conn, error) {
	v, e := in.Obfs.snellOptions(in.ObfsParam, in.Version)
	if e != nil {
		return nil, e
	}
	if v.Type == "" {
		return raw, nil
	}
	return acceptCamouflage(raw, v)
}
func acceptCamouflage(raw net.Conn, v snellObfsOptions) (net.Conn, error) {
	c := &snellObfsConn{Conn: raw, server: true, options: v}
	if v.Type == "http" {
		c.reader = bufio.NewReader(raw)
		h, e := readHTTPHeader(c.reader)
		if e != nil {
			return nil, e
		}
		if !bytes.HasPrefix(h, []byte("GET ")) && !bytes.HasPrefix(h, []byte("POST ")) {
			return nil, errors.New("invalid Snell HTTP camouflage")
		}
		c.hello = true
		return c, nil
	}
	kind, hello, e := readSSRTLSRecord(raw)
	if e != nil {
		return nil, e
	}
	if kind != 22 || len(hello) < 42 || hello[0] != 1 || int(hello[1])<<16|int(hello[2])<<8|int(hello[3]) != len(hello)-4 {
		return nil, errors.New("invalid Snell ClientHello")
	}
	r := quicReader(hello[4:])
	if _, e = r.take(34); e != nil {
		return nil, e
	}
	skip := func(bytes int) error {
		size, e := r.take(uint64(bytes))
		if e != nil {
			return e
		}
		n := int(size[0])
		if bytes == 2 {
			n = int(binary.BigEndian.Uint16(size))
		}
		_, e = r.take(uint64(n))
		return e
	}
	if e = skip(1); e != nil {
		return nil, e
	}
	if e = skip(2); e != nil {
		return nil, e
	}
	if e = skip(1); e != nil {
		return nil, e
	}
	size, e := r.take(2)
	if e != nil || int(quicU16(size)) != len(r) {
		return nil, errors.New("invalid Snell TLS extension length")
	}
	for len(r) > 0 {
		h, e := r.take(4)
		if e != nil {
			return nil, e
		}
		body, e := r.take(uint64(quicU16(h[2:])))
		if e != nil {
			return nil, e
		}
		if quicU16(h) == 35 {
			if c.pending != nil {
				return nil, errors.New("duplicate Snell session ticket")
			}
			c.pending = append([]byte{}, body...)
		}
	}
	if len(c.pending) == 0 {
		return nil, errors.New("missing Snell session ticket")
	}
	c.hello = true
	return c, nil
}
func (c *snellObfsConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	size := len(b)
	var out []byte
	if !c.sent {
		c.sent = true
		if c.options.Type == "http" {
			if c.server {
				out = []byte("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\n\r\n")
			} else {
				out = fmt.Appendf(nil, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/7.88.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nContent-Length: %d\r\n\r\n", c.options.Path, c.options.Host, base64.StdEncoding.EncodeToString(ssrRandom(16)), len(b))
			}
			out = append(out, b...)
			return size, writeAll(c.Conn, out)
		}
		if c.server {
			prefix := make([]byte, 102)
			copy(prefix, []byte{22, 3, 3, 0, 91, 2, 0, 0, 87, 3, 3})
			copy(prefix[11:43], ssrRandom(32))
			prefix[43] = 32
			copy(prefix[44:76], ssrRandom(32))
			copy(prefix[76:], []byte{0xc0, 0x2f, 0, 0, 15})
			copy(prefix[96:], []byte{20, 3, 3, 0, 1, 1})
			out = prefix
		} else {
			n := min(1024, len(b))
			out = snellClientHello(c.options.Host, b[:n])
			b = b[n:]
		}
	}
	if c.options.Type == "http" {
		return size, writeAll(c.Conn, b)
	}
	for len(b) > 0 {
		n := min(16384, len(b))
		out = append(out, ssrTLSRecord(23, b[:n])...)
		b = b[n:]
	}
	if e := writeAll(c.Conn, out); e != nil {
		return 0, e
	}
	return size, nil
}
func (c *snellObfsConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.options.Type == "http" {
		if c.reader == nil {
			c.reader = bufio.NewReader(c.Conn)
			h, e := readHTTPHeader(c.reader)
			if e != nil {
				return 0, e
			}
			if !bytes.HasPrefix(h, []byte("HTTP/1.1 200")) && !bytes.HasPrefix(h, []byte("HTTP/1.1 101")) {
				return 0, errors.New("invalid Snell HTTP response")
			}
		}
		return c.reader.Read(b)
	}
	for len(c.pending) == 0 {
		if !c.hello {
			var prefix [107]byte
			if _, e := io.ReadFull(c.Conn, prefix[:]); e != nil {
				return 0, e
			}
			if prefix[0] != 22 || prefix[1] != 3 {
				return 0, errors.New("invalid Snell TLS response")
			}
			n := int(quicU16(prefix[105:]))
			if n > 18432 {
				return 0, errors.New("Snell TLS record too large")
			}
			c.pending = make([]byte, n)
			if _, e := io.ReadFull(c.Conn, c.pending); e != nil {
				return 0, e
			}
			c.hello = true
		} else {
			kind, data, e := readSSRTLSRecord(c.Conn)
			if e != nil {
				return 0, e
			}
			if kind != 23 {
				return 0, errors.New("invalid Snell TLS record type")
			}
			c.pending = data
		}
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *snellObfsConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func snellClientHello(host string, first []byte) []byte {
	hello := append([]byte{3, 3}, ssrRandom(32)...)
	binary.BigEndian.PutUint32(hello[2:], uint32(time.Now().Unix()))
	hello = append(hello, 32)
	hello = append(hello, ssrRandom(32)...)
	hello = append(hello, 0, 56)
	hello = append(hello,
		0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
		0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
		0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
		0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff)
	hello = append(hello, 1, 0)
	ext := []byte{0, 35, byte(len(first) >> 8), byte(len(first))}
	ext = append(ext, first...)
	ext = append(ext, 0, 0, byte((len(host)+5)>>8), byte(len(host)+5), byte((len(host)+3)>>8), byte(len(host)+3), 0, byte(len(host)>>8), byte(len(host)))
	ext = append(ext, host...)
	// Conventional ClientHello extensions preserve Snell's fixed trailer layout.
	trailer := []byte{
		0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02,
		0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
		0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01,
		0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02,
		0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00}
	ext = append(ext, trailer...)
	hello = binary.BigEndian.AppendUint16(hello, uint16(len(ext)))
	hello = append(hello, ext...)
	handshake := append([]byte{1, byte(len(hello) >> 16), byte(len(hello) >> 8), byte(len(hello))}, hello...)
	out := ssrTLSRecord(22, handshake)
	out[2] = 1
	return out
}
