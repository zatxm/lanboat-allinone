package native

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

func isDNSQUIC(kind string) bool { return kind == "dns-quic" || kind == "dns-h3" }

type dnsQUICClient struct {
	resolver  *resolver
	server    DNSServer
	tlsConfig *tls.Config
	mu        sync.Mutex
	conn      *quicConn
}

func (c *dnsQUICClient) close() {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}
func (c *dnsQUICClient) session(ctx context.Context) (*quicConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if conn := c.conn; conn != nil {
		select {
		case <-conn.done:
			c.conn = nil
		default:
			return conn, nil
		}
	}
	raw, e := c.resolver.dialDNS(ctx, c.server, "udp")
	if e != nil {
		return nil, e
	}
	config, e := c.resolver.prepareTLS(ctx, c.server, c.tlsConfig)
	if e != nil {
		raw.Close()
		return nil, e
	}
	config = cloneTLSConfig(config)
	if len(config.NextProtos) == 0 {
		config.NextProtos = []string{"doq"}
		if c.server.Type == "h3" {
			config.NextProtos = []string{"h3"}
		}
	}
	conn, e := dialQUIC(ctx, c.resolver.ctx, raw, config)
	if e != nil {
		return nil, e
	}
	if c.server.Type == "h3" {
		if e = h3Start(ctx, conn); e != nil {
			conn.Close()
			return nil, e
		}
	}
	c.conn = conn
	go dnsQUICPeerStreams(conn, c.server.Type == "h3")
	return conn, nil
}
func dnsQUICPeerStreams(conn *quicConn, h3 bool) {
	var workers sync.WaitGroup
	slots := make(chan struct{}, 16)
	defer workers.Wait()
	for {
		s, e := conn.AcceptStream(conn.ctx)
		if e != nil {
			return
		}
		if !h3 || s.id&2 == 0 {
			s.Close()
			conn.cancel()
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			s.Close()
			conn.cancel()
			return
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			defer s.Close()
			if h3Uni(s) != nil {
				conn.cancel()
			}
		}()
	}
}
func (c *dnsQUICClient) exchange(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) < 12 || len(query) > 65535 {
		return nil, errors.New("invalid DNS query size")
	}
	conn, e := c.session(ctx)
	if e != nil {
		return nil, e
	}
	s, e := conn.OpenStream(ctx, false)
	if e != nil {
		return nil, e
	}
	defer s.Close()
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		s.SetDeadline(deadline)
	}
	if c.server.Type == "quic" {
		q := append([]byte(nil), query...)
		q[0], q[1] = 0, 0
		if e = writeAll(s, binary.BigEndian.AppendUint16(nil, uint16(len(q)))); e == nil {
			e = writeAll(s, q)
		}
		if e == nil {
			e = s.CloseWrite()
		}
		if e != nil {
			return nil, e
		}
		reply, e := readDoQMessage(s)
		if e != nil {
			return nil, e
		}
		reply[0], reply[1] = query[0], query[1]
		return reply, nil
	}
	path := c.server.Path
	if path == "" {
		path = "/dns-query"
	}
	port := c.server.ServerPort
	if port == 0 {
		port = 443
	}
	headers := [][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", portAddress(c.server.Server, port)}, {":path", path}, {"content-type", "application/dns-message"}, {"accept", "application/dns-message"}, {"content-length", strconv.Itoa(len(query))}}
	if e = h3WriteFrame(s, 1, h3Encode(headers)); e == nil {
		e = h3WriteFrame(s, 0, query)
	}
	if e == nil {
		e = s.CloseWrite()
	}
	if e != nil {
		return nil, e
	}
	h, body, e := readDNSH3Message(s)
	if e != nil {
		return nil, e
	}
	if h[":status"] != "200" {
		return nil, fmt.Errorf("DoH3 HTTP status %s", h[":status"])
	}
	if !dnsMediaType(h["content-type"]) || len(body) < 12 {
		return nil, errors.New("invalid DoH3 DNS response")
	}
	return body, nil
}
func readDoQMessage(r io.Reader) ([]byte, error) {
	var size [2]byte
	if _, e := io.ReadFull(r, size[:]); e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n < 12 {
		return nil, errors.New("invalid DoQ message size")
	}
	b := make([]byte, n)
	if _, e := io.ReadFull(r, b); e != nil {
		return nil, e
	}
	if b[0] != 0 || b[1] != 0 {
		return nil, errors.New("DoQ message ID must be zero")
	}
	var extra [1]byte
	if _, e := io.ReadFull(r, extra[:]); e != io.EOF {
		return nil, errors.New("DoQ requires one message followed by FIN")
	}
	return b, nil
}
func dnsMediaType(v string) bool {
	return strings.EqualFold(strings.TrimSpace(strings.SplitN(v, ";", 2)[0]), "application/dns-message")
}
func readDNSH3Message(r io.Reader) (map[string]string, []byte, error) {
	var headers map[string]string
	var body []byte
	trailers := false
	for frames := 0; frames < 128; frames++ {
		kind, b, e := h3ReadFrame(r)
		if e == io.EOF && headers != nil {
			if value := headers["content-length"]; value != "" {
				n, err := strconv.Atoi(value)
				if err != nil || n != len(body) {
					return nil, nil, errors.New("DoH3 content-length mismatch")
				}
			}
			return headers, body, nil
		}
		if e != nil {
			return nil, nil, e
		}
		switch kind {
		case 1:
			h, e := h3Decode(b)
			if e != nil {
				return nil, nil, e
			}
			if headers == nil {
				if status := h[":status"]; len(status) == 3 && status[0] == '1' {
					continue
				}
				headers = h
			} else {
				if trailers {
					return nil, nil, errors.New("duplicate DoH3 trailers")
				}
				trailers = true
				for k := range h {
					if strings.HasPrefix(k, ":") {
						return nil, nil, errors.New("pseudo-header in DoH3 trailers")
					}
				}
			}
		case 0:
			if headers == nil || trailers || len(body)+len(b) > 65535 {
				return nil, nil, errors.New("invalid DoH3 DATA")
			}
			body = append(body, b...)
		case 3, 4, 5, 7, 13:
			return nil, nil, errors.New("forbidden DoH3 request stream frame")
		}
	}
	return nil, nil, errors.New("DoH3 frame limit exceeded")
}

func (r *Runtime) serveDNSQUIC(in Inbound, c *quicConn) error {
	defer c.Close()
	var workers sync.WaitGroup
	defer func() { c.cancel(); workers.Wait() }()
	h3 := in.Type == "dns-h3"
	if h3 {
		ctx, cancel := context.WithTimeout(c.ctx, handshakeTimeout)
		e := h3Start(ctx, c)
		cancel()
		if e != nil {
			return e
		}
	}
	for {
		s, e := c.AcceptStream(c.ctx)
		if e != nil {
			return e
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer s.Close()
			if s.id&2 != 0 {
				if !h3 || h3Uni(s) != nil {
					c.cancel()
				}
				return
			}
			s.SetDeadline(time.Now().Add(10 * time.Second))
			ctx, cancel := context.WithCancel(c.ctx)
			defer cancel()
			query, e := readDoQOrH3(s, h3)
			if e != nil {
				if h3 {
					h3WriteFrame(s, 1, h3Encode([][2]string{{":status", "400"}}))
					s.CloseWrite()
				}
				return
			}
			q := request{origin: r.socketOrigin(c.remote, c.local), source: c.remote.String(), inbound: in.Tag}
			r.enrichProcess(ctx, &q)
			r.enrichNeighbor(ctx, &q)
			reply, e := r.ExchangeDNS(WithMetadata(ctx, q.metadata), query, in.Tag)
			if e != nil {
				_, end, _, err := dnsQuestion(query)
				if err != nil {
					return
				}
				reply = dnsResponse(query, end, nil, 0, 2)
			}
			if h3 {
				e = h3WriteFrame(s, 1, h3Encode([][2]string{{":status", "200"}, {"content-type", "application/dns-message"}, {"content-length", strconv.Itoa(len(reply))}}))
				if e == nil {
					e = h3WriteFrame(s, 0, reply)
				}
			} else {
				e = writeAll(s, binary.BigEndian.AppendUint16(nil, uint16(len(reply))))
				if e == nil {
					e = writeAll(s, reply)
				}
			}
			if e == nil {
				s.CloseWrite()
			}
		}()
	}
}
func readDoQOrH3(s io.Reader, h3 bool) ([]byte, error) {
	if !h3 {
		return readDoQMessage(s)
	}
	h, body, e := readDNSH3Message(s)
	if e != nil {
		return nil, e
	}
	u, e := url.ParseRequestURI(h[":path"])
	if e != nil || u.Path != "/dns-query" || h[":scheme"] != "https" || !validHTTPHost(h[":authority"]) {
		return nil, errors.New("invalid DoH3 target")
	}
	for k := range h {
		if strings.HasPrefix(k, ":") && k != ":method" && k != ":scheme" && k != ":authority" && k != ":path" {
			return nil, errors.New("invalid DoH3 request pseudo-header")
		}
	}
	switch h[":method"] {
	case "POST":
		if !dnsMediaType(h["content-type"]) {
			return nil, errors.New("invalid DoH3 content-type")
		}
	case "GET":
		if len(body) != 0 {
			return nil, errors.New("unexpected DoH3 GET body")
		}
		body, e = base64.RawURLEncoding.DecodeString(u.Query().Get("dns"))
		if e != nil {
			return nil, e
		}
	default:
		return nil, errors.New("invalid DoH3 method")
	}
	if len(body) < 12 || len(body) > 65535 {
		return nil, errors.New("invalid DoH3 query size")
	}
	return body, nil
}
