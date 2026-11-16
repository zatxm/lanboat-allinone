package native

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

func SSRObfuscations() []string {
	return []string{"plain", "http_simple", "http_post", "random_head", "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"}
}

// CRC32's all-ones residue survives another zero byte. Avoid emitting a header
// whose shorter prefix is already a valid header; the wire has no length field.
func ssrRandomHead() []byte {
	for {
		head := ssrRandom(32)
		head = binary.LittleEndian.AppendUint32(head, ^crc32.ChecksumIEEE(head))
		if ssrRandomHeadEnd(head) == len(head) {
			return head
		}
	}
}
func ssrRandomHeadEnd(head []byte) int {
	for i := 8; i <= len(head); i++ {
		if crc32.ChecksumIEEE(head[:i]) == 0xffffffff {
			return i
		}
	}
	return 0
}
func dialSSRObfs(raw net.Conn, o Outbound, key *ssKey) (net.Conn, error) {
	host := strings.Split(o.ObfsParam, ",")[0]
	if host == "" {
		host = o.Server
	}
	switch o.Obfs {
	case "http_simple", "http_post":
		return &ssrHTTPMask{Conn: raw, host: host, post: o.Obfs == "http_post"}, nil
	case "random_head":
		head := ssrRandomHead()
		if err := writeAll(raw, head); err != nil {
			return nil, err
		}
		var reply [128]byte
		if _, err := raw.Read(reply[:]); err != nil {
			return nil, err
		}
		return raw, nil
	case "tls1.2_ticket_auth", "tls1.2_ticket_fastauth":
		return dialSSRTLS(raw, host, key.master)
	default:
		return raw, nil
	}
}
func acceptSSRObfs(raw net.Conn, in Inbound, key *ssKey, replay *replayWindow) (net.Conn, error) {
	switch in.Obfs {
	case "http_simple", "http_post":
		reader := bufio.NewReader(raw)
		header, err := readHTTPHeader(reader)
		if err != nil {
			return nil, err
		}
		parts := strings.SplitN(string(header), " ", 3)
		if len(parts) != 3 || parts[0] != "GET" && parts[0] != "POST" {
			return nil, errors.New("invalid SSR HTTP request")
		}
		var prefix []byte
		path := parts[1]
		for len(path) > 0 {
			i := strings.IndexByte(path, '%')
			if i < 0 {
				break
			}
			path = path[i:]
			if len(path) < 3 {
				return nil, errors.New("invalid SSR percent encoding")
			}
			value, err := strconv.ParseUint(path[1:3], 16, 8)
			if err != nil {
				return nil, errors.New("invalid SSR percent encoding")
			}
			prefix = append(prefix, byte(value))
			path = path[3:]
		}
		if len(prefix) == 0 {
			return nil, errors.New("SSR HTTP request contains no cipher prefix")
		}
		return &ssrHTTPMask{Conn: raw, server: true, reader: reader, pending: prefix}, nil
	case "random_head":
		reader, wrapped := (*bufio.Reader)(nil), raw
		if c, ok := raw.(*bufferedConn); ok {
			reader = c.reader
		} else {
			reader = bufio.NewReader(raw)
			wrapped = &bufferedConn{Conn: raw, reader: reader}
		}
		var head []byte
		var b [1]byte
		for len(head) < 128 {
			if _, err := io.ReadFull(reader, b[:]); err != nil {
				return nil, err
			}
			head = append(head, b[0])
			if len(head) >= 8 && crc32.ChecksumIEEE(head) == 0xffffffff {
				// Consume the equivalent trailing residues in a buffered peer header.
				for reader.Buffered() > 0 && len(head) < 128 {
					next, _ := reader.Peek(1)
					if next[0] != 0 {
						break
					}
					reader.ReadByte()
					head = append(head, 0)
				}
				return wrapped, writeAll(raw, ssrRandomHead())
			}
		}
		return nil, errors.New("invalid SSR random header")
	case "tls1.2_ticket_auth", "tls1.2_ticket_fastauth":
		return acceptSSRTLS(raw, key, replay)
	default:
		return raw, nil
	}
}

type ssrHTTPMask struct {
	net.Conn
	host               string
	post, server, sent bool
	reader             *bufio.Reader
	pending            []byte
	rmu, wmu           sync.Mutex
}

func (c *ssrHTTPMask) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	out := b
	if !c.sent {
		c.sent = true
		if c.server {
			out = append([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n"), b...)
		} else {
			var path strings.Builder
			n := min(64, len(b))
			for _, v := range b[:n] {
				fmt.Fprintf(&path, "%%%02x", v)
			}
			method := "GET"
			if c.post {
				method = "POST"
			}
			header := method + " /" + path.String() + " HTTP/1.1\r\nHost: " + c.host + "\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n"
			out = append([]byte(header), b[n:]...)
		}
	}
	if err := writeAll(c.Conn, out); err != nil {
		return 0, err
	}
	return len(b), nil
}
func (c *ssrHTTPMask) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.reader == nil {
		c.reader = bufio.NewReader(c.Conn)
		header, err := readHTTPHeader(c.reader)
		if err != nil {
			return 0, err
		}
		if !bytes.HasPrefix(header, []byte("HTTP/1.")) {
			return 0, errors.New("invalid SSR HTTP response")
		}
	}
	return c.reader.Read(b)
}
func (c *ssrHTTPMask) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return nil
}

func ssrTLSRecord(kind byte, data []byte) []byte {
	return append([]byte{kind, 3, 3, byte(len(data) >> 8), byte(len(data))}, data...)
}
func readSSRTLSRecord(reader io.Reader) (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(header[3:]))
	if header[1] != 3 || header[2] > 3 || n > 18432 {
		return 0, nil, errors.New("invalid camouflage TLS record")
	}
	data := make([]byte, n)
	_, err := io.ReadFull(reader, data)
	return header[0], data, err
}

type ssrTLSRecords struct {
	net.Conn
	pending  []byte
	rmu, wmu sync.Mutex
}

func (c *ssrTLSRecords) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for empty := 0; len(c.pending) == 0; empty++ {
		if empty >= 16 {
			return 0, errors.New("too many empty TLS camouflage records")
		}
		kind, data, err := readSSRTLSRecord(c.Conn)
		if err != nil {
			return 0, err
		}
		if kind != 23 {
			return 0, errors.New("unexpected TLS camouflage record")
		}
		c.pending = data
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *ssrTLSRecords) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for len(b) > 0 {
		n := min(len(b), 16384)
		if err := writeAll(c.Conn, ssrTLSRecord(23, b[:n])); err != nil {
			return written, err
		}
		b = b[n:]
		written += n
	}
	return written, nil
}
func (c *ssrTLSRecords) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return nil
}

func acceptSSRTLS(raw net.Conn, key *ssKey, replay *replayWindow) (net.Conn, error) {
	kind, hello, err := readSSRTLSRecord(raw)
	if err != nil {
		return nil, err
	}
	if kind != 22 || len(hello) < 71 || hello[0] != 1 || hello[38] != 32 {
		return nil, errors.New("invalid SSR TLS ClientHello")
	}
	id := hello[39:71]
	auth := hello[6:38]
	macKey := append(append([]byte{}, key.master...), id...)
	if !hmac.Equal(auth[22:], ssrMAC(sha1.New, macKey, auth[:22], 10)) {
		return nil, errors.New("SSR TLS authentication rejected")
	}
	if err := ssrTime(binary.BigEndian.Uint32(auth)); err != nil {
		return nil, err
	}
	if err := replay.add(key, append(append([]byte{}, id...), auth...)); err != nil {
		return nil, err
	}
	serverAuth := ssrRandom(22)
	serverAuth = append(serverAuth, ssrMAC(sha1.New, macKey, serverAuth, 10)...)
	serverHello := append([]byte{3, 3}, serverAuth...)
	serverHello = append(serverHello, 32)
	serverHello = append(serverHello, id...)
	serverHello = append(serverHello, 0, 47, 0, 0, 0)
	serverHello = append([]byte{2, 0, 0, byte(len(serverHello))}, serverHello...)
	reply := ssrTLSRecord(22, serverHello)
	reply = append(reply, ssrTLSRecord(20, []byte{1})...)
	reply = append(reply, 22, 3, 3, 0, 32)
	reply = append(reply, ssrRandom(22)...)
	reply = append(reply, ssrMAC(sha1.New, macKey, reply, 10)...)
	if err := writeAll(raw, reply); err != nil {
		return nil, err
	}
	var finished []byte
	for i := 0; i < 2; i++ {
		kind, body, err := readSSRTLSRecord(raw)
		if err != nil {
			return nil, err
		}
		if i == 0 && (kind != 20 || !bytes.Equal(body, []byte{1})) || i == 1 && (kind != 22 || len(body) < 10) {
			return nil, errors.New("invalid SSR TLS Finished")
		}
		finished = append(finished, ssrTLSRecord(kind, body)...)
	}
	if !hmac.Equal(finished[len(finished)-10:], ssrMAC(sha1.New, macKey, finished[:len(finished)-10], 10)) {
		return nil, errors.New("SSR TLS Finished authentication rejected")
	}
	return &ssrTLSRecords{Conn: raw}, nil
}

func dialSSRTLS(raw net.Conn, host string, key []byte) (net.Conn, error) {
	id := ssrRandom(32)
	mk := append(append([]byte(nil), key...), id...)
	auth := binary.BigEndian.AppendUint32(nil, uint32(time.Now().Unix()))
	auth = append(auth, ssrRandom(18)...)
	auth = append(auth, ssrMAC(sha1.New, mk, auth, 10)...)
	hello := append([]byte{3, 3}, auth...)
	hello = append(hello, 32)
	hello = append(hello, id...)
	suites, _ := hex.DecodeString("001cc02bc02fcca9cca8cc14cc13c00ac014c009c013009c0035002f000a0100")
	hello = append(hello, suites...)
	host = strings.Split(host, ",")[0]
	sni := binary.BigEndian.AppendUint16(nil, uint16(len(host)+3))
	sni = append(sni, 0)
	sni = binary.BigEndian.AppendUint16(sni, uint16(len(host)))
	sni = append(sni, host...)
	ext := []byte{0xff, 1, 0, 1, 0, 0, 0, byte(len(sni) >> 8), byte(len(sni))}
	ext = append(ext, sni...)
	ext = append(ext, 0, 23, 0, 0, 0, 35, 0, 128)
	ext = append(ext, ssrRandom(128)...)
	hello = binary.BigEndian.AppendUint16(hello, uint16(len(ext)))
	hello = append(hello, ext...)
	packet := ssrTLSRecord(22, append([]byte{1, 0, byte(len(hello) >> 8), byte(len(hello))}, hello...))
	packet[2] = 1
	if err := writeAll(raw, packet); err != nil {
		return nil, err
	}
	var reply []byte
	changed := false
	for i := 0; i < 5; i++ {
		kind, body, err := readSSRTLSRecord(raw)
		if err != nil {
			return nil, err
		}
		reply = append(reply, ssrTLSRecord(kind, body)...)
		if kind == 20 {
			changed = true
		} else if changed {
			break
		}
	}
	if len(reply) < 76 || !hmac.Equal(ssrMAC(sha1.New, mk, reply[11:33], 10), reply[33:43]) || !hmac.Equal(ssrMAC(sha1.New, mk, reply[:len(reply)-10], 10), reply[len(reply)-10:]) {
		return nil, errors.New("SSR TLS authentication failed")
	}
	finished := append(ssrTLSRecord(20, []byte{1}), []byte{22, 3, 3, 0, 32}...)
	finished = append(finished, ssrRandom(22)...)
	finished = append(finished, ssrMAC(sha1.New, mk, finished, 10)...)
	if err := writeAll(raw, finished); err != nil {
		return nil, err
	}
	return &ssrTLSRecords{Conn: raw}, nil
}
