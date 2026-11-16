package native

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
)

// Naive pads only the first eight records in each direction. HTTP frame
// boundaries are independent of these records; reads must not assume alignment.
type naiveConn struct {
	net.Conn
	readMu, writeMu   sync.Mutex
	reads, writes     int
	reading           bool
	remaining, pad    int
	readErr, writeErr error
	buffer            []byte
}

func validateNaiveCongestion(kind, algorithm string, quic, server bool) error {
	if algorithm == "" {
		return nil
	}
	if kind != "naive" || !quic {
		return errors.New("quic_congestion_control requires Naive HTTP3")
	}
	if algorithm != "cubic" && algorithm != "bbr" && algorithm != "reno" && !(algorithm == "bbr2" && !server) {
		return errors.New("Naive quic_congestion_control must be bbr, cubic or reno; bbr2 is client-only")
	}
	return nil
}

func naiveQUICOptions(algorithm string, server bool) quicOptions {
	if algorithm == "" {
		algorithm = "cubic"
		if server {
			algorithm = "bbr"
		}
	}
	return proxyQUICOptions("naive", algorithm)
}

func (c *naiveConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if c.readErr != nil {
			return 0, c.readErr
		}
		if !c.reading {
			if c.reads == 8 {
				return c.Conn.Read(p)
			}
			var header [3]byte
			_, c.readErr = io.ReadFull(c.Conn, header[:])
			if c.readErr != nil {
				continue
			}
			c.remaining, c.pad = int(binary.BigEndian.Uint16(header[:2])), int(header[2])
			c.reading = true
		}
		if c.remaining > 0 {
			n, err := io.ReadFull(c.Conn, p[:min(len(p), c.remaining)])
			c.remaining -= n
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			c.readErr = err
			return n, err
		}
		var zeros [255]byte
		_, c.readErr = io.ReadFull(c.Conn, zeros[:c.pad])
		if c.readErr == io.EOF {
			c.readErr = io.ErrUnexpectedEOF
		}
		c.reads++
		c.reading = false
	}
}

func (c *naiveConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	n := 0
	for len(p) > 0 {
		if c.writes == 8 {
			written, err := c.Conn.Write(p)
			c.writeErr = err
			return n + written, err
		}
		size := min(len(p), 65535)
		var random [1]byte
		rand.Read(random[:])
		padding := int(random[0])
		length := 3 + size + padding
		if cap(c.buffer) < length {
			c.buffer = make([]byte, 3+size+255)
		}
		frame := c.buffer[:length]
		binary.BigEndian.PutUint16(frame, uint16(size))
		frame[2] = byte(padding)
		copy(frame[3:], p[:size])
		clear(frame[3+size:])
		if c.writeErr = writeAll(c.Conn, frame); c.writeErr != nil {
			return n, c.writeErr
		}
		c.writes++
		if c.writes == 8 {
			c.buffer = nil
		}
		n += size
		p = p[size:]
	}
	return n, nil
}

func (c *naiveConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func naiveHeader(response bool) string {
	var random [63]byte
	rand.Read(random[:])
	base, span := 16, 17
	if response {
		base, span = 30, 33
	}
	randomMinSize := 256 - 256%span
	for int(random[0]) >= randomMinSize {
		rand.Read(random[:1])
	}
	size := base + int(random[0])%span
	// These symbols have long HPACK codes and do not compress into short headers.
	const alphabet = "!#$%&'()*+,-./:;<=>?@[]^_`{|}~"
	for i := range size {
		random[i] = alphabet[int(random[i+1])%len(alphabet)]
	}
	return string(random[:size])
}

func naivePaddingReply(present bool, reply string) (bool, error) {
	switch reply {
	case "":
		return present, nil
	case "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, errors.New("unsupported Naive padding reply")
	}
}

func naivePaddingSelect(present bool, request string) (bool, string, error) {
	if request == "" {
		return present, "", nil
	}
	for _, value := range strings.Split(request, ",") {
		switch strings.TrimSpace(value) {
		case "1":
			return true, "1", nil
		case "0":
			return false, "0", nil
		}
	}
	return false, "", errors.New("no supported Naive padding type")
}

func validateNaiveTLS(tls TLSOptions, h2, h3 bool) error {
	if !tls.Enabled || tls.DisableSNI {
		return errors.New("Naive requires TLS with SNI")
	}
	if tls.MinVersion == "1.0" || tls.MinVersion == "1.1" || tls.MaxVersion == "1.0" || tls.MaxVersion == "1.1" {
		return errors.New("Naive requires TLS1.2 or newer")
	}
	alpnLen := len(tls.ALPN)
	if h2 && alpnLen != 0 && !slices.Contains(tls.ALPN, "h2") {
		return errors.New("Naive ALPN must include h2")
	}
	if h3 && alpnLen != 0 && !slices.Contains(tls.ALPN, "h3") {
		return errors.New("Naive ALPN must include h3")
	}
	if h3 {
		return tls.validateQUICVersion()
	}
	return nil
}

func validateNaiveHeaders(kind string, headers map[string]headerValues, quic bool, network string) error {
	if kind != "naive" {
		if len(headers) != 0 || quic || network != "" && kind != "mieru" {
			return errors.New("extra_headers, quic and network require naive type")
		}
		return nil
	}
	if network != "" && network != "tcp" && network != "udp" {
		return errors.New("Naive network must be tcp or udp")
	}
	seen, size := map[string]bool{}, 0
	for name, values := range headers {
		key := strings.ToLower(name)
		if seen[key] {
			return errors.New("duplicate Naive header " + name)
		}
		seen[key] = true
		if err := transportHeaderName(name, false); err != nil {
			return err
		}
		switch strings.ToLower(name) {
		case "padding", "padding-type-request", "padding-type-reply", "proxy-authorization", "host", "te", "trailer", "proxy-connection", "keep-alive":
			return errors.New("Naive owns header " + name)
		}
		for _, value := range values {
			size += len(name) + len(value)
			if strings.ContainsAny(value, "\r\n\x00") {
				return errors.New("invalid Naive header value")
			}
		}
	}
	if len(headers) > 128 || size > 32768 {
		return errors.New("Naive extra headers exceed limit")
	}
	return nil
}

func (c *trustClient) dialNaive(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "udp" {
		return nil, errors.New("Naive network must be TCP or UDP")
	}
	if network == "udp" && !c.outbound.UDPOverTCP {
		return nil, errors.New("Naive UDP requires udp_over_tcp")
	}
	encoded, err := encodeAddress(address)
	if err != nil {
		return nil, err
	}
	authority := address
	if network == "udp" {
		authority = "sp.v2.udp-over-tcp.arpa:443"
	}
	conn, err := c.connect(ctx, authority)
	if err != nil {
		return nil, err
	}
	if network == "udp" {
		// UoT v2 connected mode uses the ordinary SOCKS destination in its header.
		if err = writeAll(conn, append([]byte{1}, encoded...)); err != nil {
			conn.Close()
			return nil, err
		}
		conn = &streamPacketConn{Conn: conn, address: address}
	}
	return c.runtime.own(conn)
}

func (r *Runtime) serveNaive(in Inbound, conn net.Conn, authority, authorization string, padded bool, respond func(int) error) {
	if r.trustStreams.Add(1) > 1024 {
		r.trustStreams.Add(-1)
		_ = respond(503)
		return
	}
	defer r.trustStreams.Add(-1)
	user, ok := trustUser(in, authorization)
	if !ok {
		_ = respond(407)
		return
	}
	if _, err := encodeAddress(authority); err != nil {
		_ = respond(400)
		return
	}
	q := request{origin: r.socketOrigin(conn.RemoteAddr(), conn.LocalAddr()), inbound: in.Tag, source: conn.RemoteAddr().String(), metadata: Metadata{AuthUser: user}, network: "tcp", address: authority}
	if padded {
		conn = &naiveConn{Conn: conn}
	}
	if authority == "sp.v2.udp-over-tcp.arpa:443" {
		if respond(200) != nil {
			return
		}
		q.network = "udp"
		_ = r.serveUOT(conn, q)
		return
	}
	remote, err := r.routeDial(r.ctx, q)
	if err != nil {
		_ = respond(502)
		return
	}
	if respond(200) != nil {
		remote.Close()
		return
	}
	r.relay(conn, remote)
}
