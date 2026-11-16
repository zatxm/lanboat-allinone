package native

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

const defaultAnyPadding = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000"

type paddingStep struct {
	minimum, maximum int
	check            bool
}
type anyPadding struct {
	steps map[int][]paddingStep
	stop  int
	hash  string
}

func parseAnyPadding(text string) (*anyPadding, error) {
	if len(text) > 8192 {
		return nil, errors.New("AnyTLS padding scheme exceeds limit")
	}
	p := &anyPadding{steps: map[int][]paddingStep{}}
	digest := md5.Sum([]byte(text))
	p.hash = hex.EncodeToString(digest[:])
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			return nil, errors.New("invalid AnyTLS padding setting")
		}
		if key == "stop" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 64 {
				return nil, errors.New("invalid AnyTLS padding stop")
			}
			p.stop = n
			continue
		}
		index, err := strconv.Atoi(key)
		if err != nil || index < 0 || index > 63 {
			return nil, errors.New("invalid AnyTLS padding index")
		}
		for _, part := range strings.Split(value, ",") {
			if part == "c" {
				p.steps[index] = append(p.steps[index], paddingStep{check: true})
				continue
			}
			a, b, ok := strings.Cut(part, "-")
			if !ok {
				return nil, errors.New("invalid AnyTLS padding range")
			}
			low, e1 := strconv.Atoi(a)
			high, e2 := strconv.Atoi(b)
			if e1 != nil || e2 != nil || low < 0 || high < low || high > 65535 {
				return nil, errors.New("invalid AnyTLS padding bounds")
			}
			p.steps[index] = append(p.steps[index], paddingStep{minimum: low, maximum: high})
		}
	}
	if p.stop == 0 || len(p.steps[0]) != 1 || p.steps[0][0].check {
		return nil, errors.New("AnyTLS requires an authentication padding range")
	}
	return p, nil
}

func randomPadding(step paddingStep) int {
	if step.minimum == step.maximum {
		return step.minimum
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	return step.minimum + int(binary.LittleEndian.Uint32(b[:])%uint32(step.maximum-step.minimum+1))
}

func anyFrame(command byte, id uint32, data []byte) []byte {
	header := []byte{command}
	header = binary.BigEndian.AppendUint32(header, id)
	header = binary.BigEndian.AppendUint16(header, uint16(len(data)))
	return append(header, data...)
}

type anySession struct {
	conn       net.Conn
	runtime    *Runtime
	client     *anyClient
	padding    *anyPadding
	mu         sync.Mutex
	writeMu    sync.Mutex
	openMu     sync.Mutex
	writing    atomic.Uint32
	streams    map[uint32]*anyStream
	next, last uint32
	closed     bool
	settings   bool
	version    atomic.Int32
	packet     int
	idle       time.Time
	done       chan struct{}
	handlers   sync.WaitGroup
}

type anyClient struct {
	runtime   *Runtime
	outbound  Outbound
	mu        sync.Mutex
	sessions  []*anySession
	padding   *anyPadding
	closed    bool
	idleTimer *time.Timer
}

func (c *anyClient) close() { c.stopSessions(true) }
func (c *anyClient) stopSessions(permanent bool) {
	c.mu.Lock()
	if permanent {
		c.closed = true
	}
	if c.idleTimer != nil {
		c.idleTimer.Stop()
	}
	sessions := append([]*anySession(nil), c.sessions...)
	c.sessions = nil
	c.mu.Unlock()
	for _, s := range sessions {
		s.close(net.ErrClosed)
		<-s.done
	}
}

func (c *anyClient) reap() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	timeout := 30 * time.Second
	if c.outbound.IdleSessionTimeout != "" {
		timeout, _ = time.ParseDuration(c.outbound.IdleSessionTimeout)
	}
	minimum := 1
	if c.outbound.MinIdleSession != nil {
		minimum = *c.outbound.MinIdleSession
	}
	idle := 0
	for _, s := range c.sessions {
		s.mu.Lock()
		if !s.closed && len(s.streams) == 0 {
			idle++
		}
		s.mu.Unlock()
	}
	kept := c.sessions[:0]
	for _, s := range c.sessions {
		s.mu.Lock()
		dead := s.closed
		expired := !dead && len(s.streams) == 0 && idle > minimum && time.Since(s.idle) >= timeout
		s.mu.Unlock()
		if expired {
			s.close(net.ErrClosed)
			idle--
		}
		if !dead && !expired {
			kept = append(kept, s)
		}
	}
	c.sessions = kept
	if len(kept) > 0 {
		interval := 30 * time.Second
		if c.outbound.IdleSessionCheckInterval != "" {
			interval, _ = time.ParseDuration(c.outbound.IdleSessionCheckInterval)
		}
		c.idleTimer = time.AfterFunc(interval, c.reap)
	} else {
		c.idleTimer = nil
	}
}

func (c *anyClient) dial(ctx context.Context, network, address string) (net.Conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	var selected *anySession
	for i := len(c.sessions) - 1; i >= 0; i-- {
		s := c.sessions[i]
		s.mu.Lock()
		idle := !s.closed && len(s.streams) == 0 && s.next < ^uint32(0)
		s.mu.Unlock()
		if idle {
			selected = s
			break
		}
	}
	if selected != nil {
		c.mu.Unlock()
		stop := context.AfterFunc(ctx, func() { selected.close(ctx.Err()) })
		defer stop()
		stream, err := selected.open(address, network)
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			stream.Close()
			return nil, err
		}
		return c.runtime.own(stream)
	}
	padding := c.padding
	c.mu.Unlock()
	raw, err := c.runtime.endpoint(ctx, c.outbound, "tcp")
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	cfg, err := c.runtime.outboundTLS(ctx, c.outbound)
	if err != nil {
		raw.Close()
		return nil, err
	}
	conn, err := handshakeTLS(ctx, raw, cfg, c.outbound.TLS)
	if err != nil {
		raw.Close()
		return nil, err
	}
	password := sha256.Sum256([]byte(c.outbound.Password))
	pad := randomPadding(padding.steps[0][0])
	auth := append(password[:], byte(pad>>8), byte(pad))
	auth = append(auth, make([]byte, pad)...)
	if err := writeAll(conn, auth); err != nil {
		conn.Close()
		return nil, err
	}
	s := &anySession{conn: conn, runtime: c.runtime, client: c, padding: padding, streams: map[uint32]*anyStream{}, done: make(chan struct{})}
	stream, err := s.open(address, network)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		conn.Close()
		return nil, net.ErrClosed
	}
	c.sessions = append(c.sessions, s)
	if c.idleTimer == nil {
		interval := 30 * time.Second
		if c.outbound.IdleSessionCheckInterval != "" {
			interval, _ = time.ParseDuration(c.outbound.IdleSessionCheckInterval)
		}
		c.idleTimer = time.AfterFunc(interval, c.reap)
	}
	c.mu.Unlock()
	go func() { defer close(s.done); err := s.loop(nil, request{}); s.close(err) }()
	return c.runtime.own(stream)
}

func (s *anySession) open(address, network string) (net.Conn, error) {
	s.openMu.Lock()
	defer s.openMu.Unlock()
	s.mu.Lock()
	if s.closed || s.next == ^uint32(0) {
		s.mu.Unlock()
		return nil, net.ErrClosed
	}
	s.next++
	stream := newAnyStream(s, s.next)
	s.streams[s.next] = stream
	s.mu.Unlock()
	requestAddress := address
	if network == "udp" {
		requestAddress = "sp.v2.udp-over-tcp.arpa:443"
	}
	encoded, err := encodeAddress(requestAddress)
	if err != nil {
		stream.Close()
		return nil, err
	}
	frames := anyFrame(1, stream.id, nil)
	frames = append(frames, anyFrame(2, stream.id, encoded)...)
	if network == "udp" {
		destination, err := encodeAddress(address)
		if err != nil {
			stream.Close()
			return nil, err
		}
		frames = append(frames, anyFrame(2, stream.id, append([]byte{1}, destination...))...)
	}
	if err := s.send(frames); err != nil {
		s.close(err)
		return nil, err
	}
	if network == "udp" {
		return &streamPacketConn{Conn: stream, address: address}, nil
	}
	return stream, nil
}

func (s *anySession) send(frames []byte) error {
	return s.sendStream(frames, nil)
}

func (s *anySession) sendStream(frames []byte, stream *anyStream) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	deadline := time.Now().Add(handshakeTimeout)
	if stream != nil {
		stream.mu.Lock()
		if stream.closed {
			stream.mu.Unlock()
			return net.ErrClosed
		}
		if !stream.writeDeadline.IsZero() {
			deadline = stream.writeDeadline
		}
		s.writing.Store(stream.id)
		_ = s.conn.SetWriteDeadline(deadline)
		stream.mu.Unlock()
	} else {
		_ = s.conn.SetWriteDeadline(deadline)
	}
	defer func() { s.writing.Store(0); _ = s.conn.SetWriteDeadline(time.Time{}) }()
	if s.client != nil && !s.settings {
		settings := "v=2\nclient=lanboat-allinone/" + Version + "\npadding-md5=" + s.padding.hash
		frames = append(anyFrame(4, 0, []byte(settings)), frames...)
		s.settings = true
	}
	s.packet++
	if s.client != nil && s.packet < s.padding.stop {
		for _, step := range s.padding.steps[s.packet] {
			if step.check {
				if len(frames) == 0 {
					return nil
				}
				continue
			}
			size := randomPadding(step)
			if size == 0 {
				continue
			}
			if size < len(frames) {
				if err := writeAll(s.conn, frames[:size]); err != nil {
					return err
				}
				frames = frames[size:]
				continue
			}
			padding := size - len(frames)
			if padding >= 7 {
				frames = append(frames, anyFrame(0, 0, make([]byte, padding-7))...)
			}
			if len(frames) > 0 {
				if err := writeAll(s.conn, frames); err != nil {
					return err
				}
				frames = nil
			}
		}
	}
	if len(frames) > 0 {
		return writeAll(s.conn, frames)
	}
	return nil
}

func (s *anySession) close(err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	streams := make([]*anyStream, 0, len(s.streams))
	for _, stream := range s.streams {
		streams = append(streams, stream)
	}
	s.streams = map[uint32]*anyStream{}
	s.mu.Unlock()
	s.conn.Close()
	for _, stream := range streams {
		stream.finish(err)
	}
}

func (s *anySession) loop(in *Inbound, q request) error {
	for {
		var header [7]byte
		if _, err := io.ReadFull(s.conn, header[:]); err != nil {
			return err
		}
		command, id, size := header[0], binary.BigEndian.Uint32(header[1:]), int(binary.BigEndian.Uint16(header[5:]))
		data := make([]byte, size)
		if _, err := io.ReadFull(s.conn, data); err != nil {
			return err
		}
		if command == 0 {
			continue
		}
		if in != nil && s.version.Load() == 0 && command != 4 {
			return errors.New("AnyTLS settings must precede streams")
		}
		s.mu.Lock()
		stream := s.streams[id]
		s.mu.Unlock()
		switch command {
		case 1:
			if in == nil || size != 0 || id == 0 {
				return errors.New("invalid AnyTLS stream open")
			}
			s.mu.Lock()
			if id <= s.last || len(s.streams) >= 128 {
				s.mu.Unlock()
				return errors.New("AnyTLS stream identity or capacity violation")
			}
			s.last = id
			stream = newAnyStream(s, id)
			s.streams[id] = stream
			s.handlers.Add(1)
			s.mu.Unlock()
			go func() {
				defer s.handlers.Done()
				defer stream.Close()
				if err := s.runtime.handleAnyStream(stream, q); err != nil && s.runtime.ctx.Err() == nil {
					s.runtime.logger.Debug("AnyTLS stream ended", zap.Error(err))
				}
			}()
		case 2:
			if stream != nil && len(data) > 0 {
				if err := stream.push(data); err != nil {
					return err
				}
			}
		case 3:
			if size != 0 {
				return errors.New("AnyTLS FIN cannot contain data")
			}
			if stream != nil {
				stream.finish(io.EOF)
			}
		case 4:
			if in == nil || s.version.Load() != 0 || id != 0 || size > 4096 {
				return errors.New("invalid AnyTLS client settings")
			}
			settings := parseAnySettings(string(data))
			version, _ := strconv.Atoi(settings["v"])
			if version < 1 || version > 2 {
				return errors.New("unsupported AnyTLS version")
			}
			s.version.Store(int32(version))
			if version >= 2 {
				if err := s.send(anyFrame(10, 0, []byte("v=2"))); err != nil {
					return err
				}
			}
			text := defaultAnyPadding
			if len(in.PaddingScheme) > 0 {
				text = strings.Join(in.PaddingScheme, "\n")
			}
			padding, _ := parseAnyPadding(text)
			if settings["padding-md5"] != padding.hash {
				if err := s.send(anyFrame(6, 0, []byte(text))); err != nil {
					return err
				}
			}
		case 5:
			return fmt.Errorf("AnyTLS peer alert: %s", string(data[:min(len(data), 1024)]))
		case 6:
			if s.client == nil {
				return errors.New("unexpected AnyTLS padding update")
			}
			padding, err := parseAnyPadding(string(data))
			if err != nil {
				return err
			}
			s.client.mu.Lock()
			s.client.padding = padding
			s.client.mu.Unlock()
		case 7:
			if s.client == nil {
				return errors.New("unexpected AnyTLS SYNACK")
			}
			if stream != nil && len(data) > 0 {
				stream.finish(fmt.Errorf("AnyTLS destination rejected: %s", string(data[:min(len(data), 1024)])))
			}
		case 8:
			if size != 0 {
				return errors.New("invalid AnyTLS heartbeat")
			}
			if err := s.send(anyFrame(9, id, nil)); err != nil {
				return err
			}
		case 9:
			if size != 0 {
				return errors.New("invalid AnyTLS heartbeat response")
			}
		case 10:
			if s.client == nil || size > 4096 {
				return errors.New("invalid AnyTLS server settings")
			}
		default:
			return errors.New("unknown AnyTLS command")
		}
	}
}

func parseAnySettings(text string) map[string]string {
	settings := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			settings[key] = value
		}
	}
	return settings
}

func (r *Runtime) serveAnyTLS(in Inbound, c net.Conn, q request) error {
	var auth [34]byte
	if _, err := io.ReadFull(c, auth[:]); err != nil {
		return err
	}
	valid := 0
	for _, user := range in.Users {
		sum := sha256.Sum256([]byte(user.Password))
		valid |= subtle.ConstantTimeCompare(sum[:], auth[:32])
	}
	if valid != 1 {
		return errors.New("AnyTLS authentication rejected")
	}
	if _, err := io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint16(auth[32:]))); err != nil {
		return err
	}
	_ = c.SetDeadline(time.Time{})
	s := &anySession{conn: c, runtime: r, streams: map[uint32]*anyStream{}}
	err := s.loop(&in, q)
	s.close(err)
	s.handlers.Wait()
	return err
}

func (r *Runtime) handleAnyStream(stream *anyStream, q request) error {
	_ = stream.SetReadDeadline(time.Now().Add(handshakeTimeout))
	address, err := readAddress(stream)
	if err != nil {
		return err
	}
	q.address = address
	host, _, _ := net.SplitHostPort(address)
	if host == "sp.v2.udp-over-tcp.arpa" {
		if stream.session.version.Load() >= 2 {
			if err := stream.session.send(anyFrame(7, stream.id, nil)); err != nil {
				return err
			}
		}
		_ = stream.SetDeadline(time.Time{})
		return r.serveUOT(stream, q)
	}
	remote, err := r.routeDial(r.ctx, q)
	if err != nil {
		if stream.session.version.Load() >= 2 {
			_ = stream.session.send(anyFrame(7, stream.id, []byte(err.Error())))
		}
		return err
	}
	if stream.session.version.Load() >= 2 {
		if err := stream.session.send(anyFrame(7, stream.id, nil)); err != nil {
			remote.Close()
			return err
		}
	}
	r.relay(stream, remote)
	return nil
}

type anyStream struct {
	session                     *anySession
	id                          uint32
	mu                          sync.Mutex
	queue                       [][]byte
	bytes                       int
	err                         error
	closed                      bool
	readDeadline, writeDeadline time.Time
	notify                      chan struct{}
	space                       chan struct{}
}

func newAnyStream(s *anySession, id uint32) *anyStream {
	return &anyStream{session: s, id: id, notify: make(chan struct{}, 1), space: make(chan struct{}, 1)}
}
func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
func (c *anyStream) push(data []byte) error {
	for {
		c.mu.Lock()
		if c.closed || c.err != nil {
			c.mu.Unlock()
			return nil
		}
		if c.bytes+len(data) <= 256*1024 {
			c.queue = append(c.queue, data)
			c.bytes += len(data)
			signal(c.notify)
			c.mu.Unlock()
			return nil
		}
		c.mu.Unlock()
		select {
		case <-c.space:
		case <-c.session.runtime.ctx.Done():
			return net.ErrClosed
		}
	}
}
func (c *anyStream) finish(err error) {
	if err == nil {
		err = io.EOF
	}
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	signal(c.notify)
	signal(c.space)
	c.mu.Unlock()
}
func (c *anyStream) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if len(c.queue) > 0 {
			first := c.queue[0]
			n := copy(b, first)
			c.queue[0] = first[n:]
			if len(c.queue[0]) == 0 {
				c.queue[0] = nil
				c.queue = c.queue[1:]
			}
			c.bytes -= n
			signal(c.space)
			c.mu.Unlock()
			return n, nil
		}
		err := c.err
		deadline := c.readDeadline
		c.mu.Unlock()
		if err != nil {
			return 0, err
		}
		if err := waitAny(c.notify, c.session.runtime.ctx, deadline); err != nil {
			return 0, err
		}
	}
}
func waitAny(ch <-chan struct{}, ctx context.Context, deadline time.Time) error {
	var timeout <-chan time.Time
	var timer *time.Timer
	if !deadline.IsZero() {
		duration := time.Until(deadline)
		if duration <= 0 {
			return os.ErrDeadlineExceeded
		}
		timer = time.NewTimer(duration)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case <-ch:
		return nil
	case <-timeout:
		return os.ErrDeadlineExceeded
	case <-ctx.Done():
		return net.ErrClosed
	}
}
func (c *anyStream) Write(b []byte) (int, error) {
	c.mu.Lock()
	closed := c.closed
	deadline := c.writeDeadline
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if !deadline.IsZero() && time.Now().After(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	written := 0
	for len(b) > 0 {
		n := min(len(b), 32768)
		if err := c.session.sendStream(anyFrame(2, c.id, b[:n]), c); err != nil {
			return written, err
		}
		written += n
		b = b[n:]
	}
	return written, nil
}
func (c *anyStream) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.queue = nil
	c.bytes = 0
	if c.err == nil {
		c.err = net.ErrClosed
	}
	signal(c.notify)
	signal(c.space)
	c.mu.Unlock()
	s := c.session
	s.mu.Lock()
	delete(s.streams, c.id)
	s.idle = time.Now()
	dead := s.closed
	s.mu.Unlock()
	if !dead {
		return s.send(anyFrame(3, c.id, nil))
	}
	return nil
}
func (c *anyStream) CloseWrite() error    { return c.session.send(anyFrame(3, c.id, nil)) }
func (c *anyStream) LocalAddr() net.Addr  { return c.session.conn.LocalAddr() }
func (c *anyStream) RemoteAddr() net.Addr { return c.session.conn.RemoteAddr() }
func (c *anyStream) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	if c.session.writing.Load() == c.id {
		_ = c.session.conn.SetWriteDeadline(t)
	}
	signal(c.notify)
	c.mu.Unlock()
	return nil
}
func (c *anyStream) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	signal(c.notify)
	c.mu.Unlock()
	return nil
}
func (c *anyStream) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	if c.session.writing.Load() == c.id {
		_ = c.session.conn.SetWriteDeadline(t)
	}
	c.mu.Unlock()
	return nil
}

func (r *Runtime) serveUOT(c net.Conn, q request) error {
	var mode [1]byte
	if _, err := io.ReadFull(c, mode[:]); err != nil {
		return err
	}
	address, err := readAddress(c)
	if err != nil {
		return err
	}
	if mode[0] == 1 {
		q.address = address
		return r.serveStreamPackets(c, q, false)
	}
	if mode[0] != 0 {
		return errors.New("invalid UoT connection mode")
	}
	flows := newUDPFlows(r)
	defer flows.Close()
	var writes sync.Mutex
	for {
		address, err := readUOTAddress(c)
		if err != nil {
			return err
		}
		var size [2]byte
		if _, err := io.ReadFull(c, size[:]); err != nil {
			return err
		}
		data := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		if _, err := io.ReadFull(c, data); err != nil {
			return err
		}
		q.address = address
		if err := flows.send(address, q, data, func(data []byte, from string) error {
			addr, err := encodeAddress(from)
			if err != nil {
				return err
			}
			addr[0] = map[byte]byte{1: 0, 4: 1, 3: 2}[addr[0]]
			frame := binary.BigEndian.AppendUint16(addr, uint16(len(data)))
			frame = append(frame, data...)
			writes.Lock()
			defer writes.Unlock()
			return writeAll(c, frame)
		}); err != nil {
			return err
		}
	}
}
func readUOTAddress(r io.Reader) (string, error) {
	var kind [1]byte
	if _, err := io.ReadFull(r, kind[:]); err != nil {
		return "", err
	}
	mapped, ok := map[byte]byte{0: 1, 1: 4, 2: 3}[kind[0]]
	if !ok {
		return "", errors.New("invalid UoT address type")
	}
	return readAddress(io.MultiReader(bytes.NewReader([]byte{mapped}), r))
}
