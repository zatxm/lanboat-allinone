package native

import (
	"context"
	"errors"

	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"
)

// HTTP/3 DATA is streamed rather than buffering a complete long-lived tunnel.
type trustH3Conn struct {
	*quicStream
	remaining      uint64
	trailers       bool
	writeMu        sync.Mutex
	writeBuffer    []byte
	decodeTrailers func([]byte) error
}

func (c *trustH3Conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for c.remaining == 0 {
		kind, e := readQUICVar(c.quicStream)
		if e != nil {
			return 0, e
		}
		size, e := readQUICVar(c.quicStream)
		if e != nil {
			return 0, e
		}
		if kind == 0 {
			if c.trailers {
				return 0, errors.New("HTTP3 DATA after trailers")
			}
			c.remaining = size
			continue
		}
		limit := uint64(65536)
		if c.decodeTrailers != nil {
			limit = 262144
		}
		if (kind == 1 || c.decodeTrailers == nil) && size > limit || kind == 4 || kind == 3 || kind == 7 || kind == 5 || kind == 13 || kind == 2 || kind == 6 || kind == 8 || kind == 9 {
			return 0, errors.New("invalid HTTP3 tunnel frame")
		}
		if kind == 1 {
			if c.trailers {
				return 0, errors.New("duplicate HTTP3 trailers")
			}
			c.trailers = true
			if c.decodeTrailers != nil {
				wire := make([]byte, int(size))
				if _, err := io.ReadFull(c.quicStream, wire); err != nil {
					return 0, err
				}
				if err := c.decodeTrailers(wire); err != nil {
					return 0, err
				}
				continue
			}
		}
		if _, e = io.CopyN(io.Discard, c.quicStream, int64(size)); e != nil {
			return 0, e
		}
	}
	n, e := c.quicStream.Read(b[:min(uint64(len(b)), c.remaining)])
	c.remaining -= uint64(n)
	if e == io.EOF && c.remaining != 0 {
		e = io.ErrUnexpectedEOF
	}
	return n, e
}
func (c *trustH3Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	n := 0
	for len(b) > 0 {
		size := min(len(b), 16384)
		frame := quicVar(c.writeBuffer[:0], 0)
		frame = quicVar(frame, uint64(size))
		frame = append(frame, b[:size]...)
		c.writeBuffer = frame[:0]
		if e := writeAll(c.quicStream, frame); e != nil {
			return n, e
		}
		n += size
		b = b[size:]
	}
	return n, nil
}
func (c *trustClient) h3Session(ctx context.Context) (*quicConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if q := c.quic; q != nil {
		select {
		case <-q.done:
			c.quic = nil
		default:
			draining := false
			if c.outbound.Type == "naive" && c.naiveH3 != nil {
				c.naiveH3.mu.Lock()
				draining = c.naiveH3.draining
				c.naiveH3.mu.Unlock()
			}
			if !draining {
				return q, nil
			}
			c.quic = nil
		}
	}
	if c.outbound.Type == "naive" && len(c.naiveH3Sessions) >= 8 {
		return nil, errors.New("too many draining Naive HTTP3 sessions")
	}
	raw, e := c.runtime.endpoint(ctx, c.outbound, "udp")
	if e != nil {
		return nil, e
	}
	cfg, e := c.runtime.outboundTLS(ctx, c.outbound)
	if e != nil {
		raw.Close()
		return nil, e
	}
	cfg = cloneTLSConfig(cfg)
	cfg.NextProtos = []string{"h3"}
	var options quicOptions
	if c.outbound.Type == "naive" {
		options = naiveQUICOptions(c.outbound.QUICCongestionControl, false)
	}
	q, e := dialQUIC(ctx, c.runtime.ctx, raw, cfg, options)
	if e != nil {
		return nil, e
	}
	if c.outbound.Type == "naive" {
		n, err := newChromiumH3(ctx, q)
		if err != nil {
			q.Close()
			return nil, err
		}
		c.naiveH3 = n
		if c.naiveH3Sessions == nil {
			c.naiveH3Sessions = map[*chromiumH3Session]struct{}{}
		}
		c.naiveH3Sessions[n] = struct{}{}
		go n.peerStreams(c)
	} else if e = h3Start(ctx, q); e != nil {
		q.Close()
		return nil, e
	}
	c.quic = q
	if c.outbound.Type != "naive" {
		go dnsQUICPeerStreams(q, true)
	}
	return q, nil
}
func (c *trustClient) connectH3(ctx context.Context, authority string) (net.Conn, error) {
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := c.connectH3Once(ctx, authority)
		if !errors.Is(err, errChromiumH3Draining) {
			return conn, err
		}
	}
	return nil, errChromiumH3Draining
}

func (c *trustClient) connectH3Once(ctx context.Context, authority string) (net.Conn, error) {
	q, e := c.h3Session(ctx)
	if e != nil {
		return nil, e
	}
	if c.outbound.Type == "naive" {
		c.mu.Lock()
		n := c.naiveH3
		c.mu.Unlock()
		if n == nil || n.q != q {
			return nil, net.ErrClosed
		}
		return n.connect(ctx, c, authority)
	}
	s, e := q.OpenStream(ctx, false)
	if e != nil {
		return nil, e
	}
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	if d, ok := ctx.Deadline(); ok {
		s.SetDeadline(d)
	}
	requestHeaders := [][2]string{{":method", "CONNECT"}, {":authority", authority}, {"user-agent", runtime.GOOS + " Lanboat " + authority}, {"proxy-authorization", c.authorization()}}
	block := h3Encode(requestHeaders)
	e = h3WriteFrame(s, 1, block)
	if e == nil {
		var headers map[string]string
		headers, e = h3Status(s)
		status := headers[":status"]
		if e == nil && status != "200" {
			e = errors.New("TrustTunnel CONNECT: HTTP " + status)
		}
		if status == "407" {
			q.Close()
		}
	}
	if e != nil {
		s.Close()
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		s.Close()
		return nil, e
	}
	s.SetDeadline(time.Time{})
	var conn net.Conn = &trustH3Conn{quicStream: s}
	return conn, nil
}
func (r *Runtime) serveTrustQUIC(in Inbound, q *quicConn) error {
	if in.Type == "naive" {
		return serveHTTP3(q, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { r.serveTrustHTTP(in, w, req) }))
	}
	defer q.Close()
	if e := h3Start(q.ctx, q); e != nil {
		return e
	}
	var workers sync.WaitGroup
	// Close transport before waiting, so blocked streams always wake on shutdown.
	defer workers.Wait()
	defer q.Close()
	slots := make(chan struct{}, 128)
	for {
		s, e := q.AcceptStream(q.ctx)
		if e != nil {
			return e
		}
		select {
		case slots <- struct{}{}:
		default:
			s.Close()
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			defer s.Close()
			if s.id&2 != 0 {
				if h3Uni(s) != nil {
					q.cancel()
				}
				return
			}
			s.SetDeadline(time.Now().Add(handshakeTimeout))
			kind, body, e := h3ReadFrame(s)
			if e != nil || kind != 1 {
				return
			}
			headers, e := h3Decode(body)
			if e != nil {
				return
			}
			respond := func(status int) error {
				responseHeaders := [][2]string{{":status", strconv.Itoa(status)}}
				return h3WriteFrame(s, 1, h3Encode(responseHeaders))
			}
			if headers[":method"] != "CONNECT" || headers[":scheme"] != "" || headers[":path"] != "" {
				_ = respond(400)
				_ = s.CloseWrite()
				return
			}
			s.SetDeadline(time.Time{})
			conn := &trustH3Conn{quicStream: s}
			r.serveTrust(in, conn, headers[":authority"], headers["proxy-authorization"], respond)
			_ = s.CloseWrite()
		}()
	}
}
