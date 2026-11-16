package native

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"runtime"
	"slices"
	"sync"
	"time"

	"go.uber.org/zap"
)

const genericMuxAddress = "sp.mux.sing-box.arpa:444"
const brutalExchangeAddress = "_BrutalBwExchange:0"

type MultiplexOptions struct {
	Enabled        bool          `json:"enabled,omitempty"`
	Protocol       string        `json:"protocol,omitempty"`
	MaxConnections int           `json:"max_connections,omitempty"`
	MinStreams     int           `json:"min_streams,omitempty"`
	MaxStreams     int           `json:"max_streams,omitempty"`
	Padding        bool          `json:"padding,omitempty"`
	Brutal         BrutalOptions `json:"brutal,omitzero"`
}
type BrutalOptions struct {
	Enabled  bool `json:"enabled,omitempty"`
	UpMbps   int  `json:"up_mbps,omitempty"`
	DownMbps int  `json:"down_mbps,omitempty"`
}

func (o MultiplexOptions) generic(kind string) bool {
	return o.Enabled && kind != "snell" && kind != "sudoku" && o.Protocol != "mux.cool" && o.Protocol != "trojan-go"
}
func (o MultiplexOptions) validate(kind string, server bool) error {
	if !o.Enabled {
		return nil
	}
	switch kind {
	case "shadowsocks", "shadowsocksr", "socks", "http", "mixed", "vmess", "vless", "trojan", "relay", "snell", "sudoku":
	default:
		return fmt.Errorf("multiplex is not supported for %s", kind)
	}
	if o.MaxConnections < 0 || o.MinStreams < 0 || o.MaxStreams < 0 || o.MaxConnections > 128 || o.MinStreams > 128 || o.MaxStreams > 128 {
		return errors.New("multiplex limits must be within 0..128")
	}
	if o.MaxStreams != 0 && (o.MaxConnections != 0 || o.MinStreams != 0) {
		return errors.New("max_streams conflicts with max_connections/min_streams")
	}
	if !o.generic(kind) {
		if o.Protocol != "" && !(o.Protocol == "mux.cool" && (kind == "vmess" || kind == "vless")) && !(o.Protocol == "trojan-go" && kind == "trojan") {
			return errors.New("invalid legacy multiplex protocol")
		}
		if o.Padding || o.Brutal.Enabled || o.MaxStreams != 0 || o.MinStreams != 0 || o.MaxConnections != 0 {
			return errors.New("generic multiplex options require h2mux, smux or yamux")
		}
		return nil
	}
	switch o.Protocol {
	case "", "h2mux", "smux", "yamux":
	default:
		return fmt.Errorf("unknown multiplex protocol %q", o.Protocol)
	}
	if o.Brutal.Enabled {
		if o.Brutal.UpMbps < 1 || o.Brutal.DownMbps < 1 || o.Brutal.UpMbps > 1000000 || o.Brutal.DownMbps > 1000000 {
			return errors.New("TCP Brutal up_mbps/down_mbps must be within 1..1000000")
		}
		if server && runtime.GOOS != "linux" {
			return errors.New("TCP Brutal server requires Linux")
		}
	}
	return nil
}

type genericMuxBypassKey struct{}

// routeDial returns this internal dispatch target; relay takes over without an extra pipe or copy.
type genericMuxTarget struct {
	request request
	options MultiplexOptions
}

func (*genericMuxTarget) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (*genericMuxTarget) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (*genericMuxTarget) Close() error                     { return nil }
func (*genericMuxTarget) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*genericMuxTarget) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*genericMuxTarget) SetDeadline(time.Time) error      { return nil }
func (*genericMuxTarget) SetReadDeadline(time.Time) error  { return nil }
func (*genericMuxTarget) SetWriteDeadline(time.Time) error { return nil }

type genericMuxSession interface {
	open(context.Context) (net.Conn, error)
	close(error)
	dead() bool
}
type genericSMUX struct{ *smuxSession }

func (s genericSMUX) open(ctx context.Context) (net.Conn, error) { return s.smuxSession.open(ctx) }
func (s genericSMUX) dead() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

type genericMuxEntry struct {
	session genericMuxSession
	active  int
	idle    *time.Timer
	retired bool
}
type genericMuxOpening struct {
	done   chan struct{}
	cancel context.CancelFunc
}
type genericMuxClient struct {
	runtime  *Runtime
	outbound Outbound
	mu       sync.Mutex
	entries  []*genericMuxEntry
	opening  *genericMuxOpening
}

func (p *genericMuxClient) reset() {
	p.mu.Lock()
	entries := p.entries
	p.entries = nil
	if p.opening != nil {
		p.opening.cancel()
		p.opening = nil
	}
	for _, e := range entries {
		e.retired = true
		if e.idle != nil {
			e.idle.Stop()
		}
	}
	p.mu.Unlock()
	for _, e := range entries {
		e.session.close(net.ErrClosed)
	}
}
func (p *genericMuxClient) release(e *genericMuxEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e.active--
	if e.active != 0 || e.retired || e.session.dead() {
		return
	}
	e.idle = time.AfterFunc(30*time.Second, func() {
		p.mu.Lock()
		if e.active != 0 {
			p.mu.Unlock()
			return
		}
		for i, item := range p.entries {
			if item == e {
				p.entries = slices.Delete(p.entries, i, i+1)
				e.retired = true
				p.mu.Unlock()
				e.session.close(net.ErrClosed)
				return
			}
		}
		p.mu.Unlock()
	})
}
func (p *genericMuxClient) acquire(ctx context.Context) (*genericMuxEntry, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if p.runtime.ctx.Err() != nil {
			return nil, net.ErrClosed
		}
		p.mu.Lock()
		live := p.entries[:0]
		var best *genericMuxEntry
		for _, e := range p.entries {
			if e.session.dead() {
				e.retired = true
				if e.idle != nil {
					e.idle.Stop()
				}
				continue
			}
			live = append(live, e)
			if e.active < 128 && (best == nil || e.active < best.active) {
				best = e
			}
		}
		clear(p.entries[len(live):])
		p.entries = live
		options := p.outbound.Multiplex
		limit := options.MaxStreams
		if limit == 0 {
			limit = options.MinStreams
		}
		if limit == 0 {
			limit = 8
		}
		reuse := best != nil && (best.active == 0 || best.active < limit || options.MaxConnections > 0 && len(live) >= options.MaxConnections || options.Brutal.Enabled)
		if reuse {
			if best.idle != nil {
				best.idle.Stop()
				best.idle = nil
			}
			best.active++
			p.mu.Unlock()
			return best, nil
		}
		if pending := p.opening; pending != nil {
			p.mu.Unlock()
			select {
			case <-pending.done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-p.runtime.ctx.Done():
				return nil, net.ErrClosed
			}
		}
		if options.Brutal.Enabled && len(live) > 0 || options.MaxConnections > 0 && len(live) >= options.MaxConnections || len(live) >= 128 {
			p.mu.Unlock()
			return nil, errors.New("multiplex stream capacity exhausted at connection limit")
		}
		child, cancel := context.WithCancel(ctx)
		pending := &genericMuxOpening{done: make(chan struct{}), cancel: cancel}
		p.opening = pending
		p.mu.Unlock()
		raw, err := p.runtime.dialOutbound(context.WithValue(child, genericMuxBypassKey{}, p.outbound.Tag), p.outbound.Tag, "tcp", genericMuxAddress)
		var session genericMuxSession
		if err == nil {
			stop := context.AfterFunc(child, func() { raw.Close() })
			session, err = p.newSession(child, raw)
			stop()
		}
		p.mu.Lock()
		if err == nil {
			err = child.Err()
		}
		if p.opening == pending {
			p.opening = nil
		} else if err == nil {
			err = net.ErrClosed
		}
		if err == nil {
			best = &genericMuxEntry{session: session, active: 1}
			p.entries = append(p.entries, best)
		}
		close(pending.done)
		p.mu.Unlock()
		cancel()
		if err != nil {
			if raw != nil {
				raw.Close()
			}
			if session != nil {
				session.close(err)
			}
			return nil, err
		}
		return best, nil
	}
}
func (p *genericMuxClient) newSession(ctx context.Context, raw net.Conn) (genericMuxSession, error) {
	options := p.outbound.Multiplex
	code := byte(2)
	if options.Protocol == "smux" {
		code = 0
	}
	if options.Protocol == "yamux" {
		code = 1
	}
	header := []byte{0, code}
	if options.Padding {
		header = []byte{1, code, 1, 0, 0}
		padding := make([]byte, 256+rand.IntN(512))
		binary.BigEndian.PutUint16(header[3:], uint16(len(padding)))
		header = append(header, padding...)
	}
	if d, ok := ctx.Deadline(); ok {
		raw.SetDeadline(d)
	}
	if err := writeAll(raw, header); err != nil {
		return nil, err
	}
	var wire net.Conn = raw
	if options.Padding {
		wire = &genericPaddingConn{Conn: wire}
	}
	var s genericMuxSession
	if code == 2 {
		s = newGenericH2Client(p.runtime.ctx, wire)
	} else {
		protocol := muxSMUX
		if code == 1 {
			protocol = muxYAMUX
		}
		s = genericSMUX{newMuxConfigured(p.runtime.ctx, wire, true, protocol, 1, 0, false)}
	}
	if options.Brutal.Enabled {
		c, err := s.open(ctx)
		if err != nil {
			s.close(err)
			return nil, err
		}
		if d, ok := ctx.Deadline(); ok {
			c.SetDeadline(d)
		}
		conn, err := genericClientRequest(c, "tcp", brutalExchangeAddress)
		if err == nil {
			err = binary.Write(conn, binary.BigEndian, uint64(options.Brutal.DownMbps)*125000)
		}
		var reply [9]byte
		if err == nil {
			_, err = io.ReadFull(conn, reply[:1])
		}
		if err == nil && reply[0] != 1 {
			var message string
			message, err = readMuxMessage(conn)
			if err == nil {
				err = fmt.Errorf("TCP Brutal: %s", message)
			}
		} else if err == nil {
			_, err = io.ReadFull(conn, reply[1:])
		}
		c.Close()
		if err != nil {
			s.close(err)
			return nil, err
		}
		send := min(uint64(options.Brutal.UpMbps)*125000, binary.BigEndian.Uint64(reply[1:]))
		if err = setTCPBrutal(raw, send); err != nil {
			p.runtime.logger.Debug("TCP Brutal client kernel unavailable; server remains enabled", zap.Error(err))
		}
	}
	raw.SetDeadline(time.Time{})
	return s, nil
}
func (p *genericMuxClient) dial(ctx context.Context, network, address string) (net.Conn, error) {
	e, err := p.acquire(ctx)
	if err != nil {
		return nil, err
	}
	c, err := e.session.open(ctx)
	if err != nil {
		p.release(e)
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	if deadline, ok := ctx.Deadline(); ok {
		c.SetDeadline(deadline)
	}
	conn, err := genericClientRequest(c, network, address)
	stop()
	if err == nil {
		err = ctx.Err()
	}
	c.SetDeadline(time.Time{})
	if err != nil {
		c.Close()
		p.release(e)
		return nil, err
	}
	wrapped := &genericPooledConn{Conn: conn, release: func() { p.release(e) }}
	return p.runtime.own(wrapped)
}

type genericPooledConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *genericPooledConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (c *genericPooledConn) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return nil
}

type genericResponseConn struct {
	net.Conn
	once sync.Once
	err  error
}

func (c *genericResponseConn) Read(b []byte) (int, error) {
	c.once.Do(func() {
		var status [1]byte
		_, c.err = io.ReadFull(c.Conn, status[:])
		if c.err == nil && status[0] != 0 {
			var message string
			message, c.err = readMuxMessage(c.Conn)
			if c.err == nil {
				c.err = fmt.Errorf("multiplex remote: %s", message)
			}
		}
	})
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(b)
}
func (c *genericResponseConn) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return nil
}
func genericClientRequest(c net.Conn, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "udp" {
		return nil, errors.New("multiplex requires TCP or UDP")
	}
	target, err := encodeAddress(address)
	if address == brutalExchangeAddress {
		target = append(append([]byte{3, byte(len("_BrutalBwExchange"))}, "_BrutalBwExchange"...), 0, 0)
		err = nil
	}
	if err != nil {
		return nil, err
	}
	header := append([]byte{0, 0}, target...)
	if network == "udp" {
		header[1] = 1
	}
	if err = writeAll(c, header); err != nil {
		return nil, err
	}
	response := &genericResponseConn{Conn: c}
	if network == "udp" {
		return &genericPacketConn{Conn: response}, nil
	}
	return response, nil
}
func readMuxMessage(r io.Reader) (string, error) {
	// A varint length is part of the shared multiplex error format; cap untrusted strings.
	b := bufio.NewReaderSize(r, 16)
	n, err := binary.ReadUvarint(b)
	// Do not buffer beyond the string when the caller continues with this stream.
	if err != nil {
		return "", err
	}
	if n > 4096 {
		return "", errors.New("multiplex error message exceeds 4KiB")
	}
	value := make([]byte, n)
	_, err = io.ReadFull(b, value)
	return string(value), err
}
func writeMuxError(c net.Conn, cause error) error { return writeMuxStatus(c, 1, cause) }
func writeMuxStatus(c net.Conn, status byte, cause error) error {
	text := cause.Error()
	if len(text) > 4096 {
		text = text[:4096]
	}
	var b [10]byte
	n := binary.PutUvarint(b[:], uint64(len(text)))
	return writeAll(c, append(append([]byte{status}, b[:n]...), text...))
}

func (r *Runtime) serveGenericMux(c net.Conn, q request, options MultiplexOptions) error {
	defer c.Close()
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	var header [3]byte
	if _, err := io.ReadFull(c, header[:2]); err != nil {
		return err
	}
	if header[0] > 1 || header[1] > 2 {
		return errors.New("invalid multiplex negotiation")
	}
	padded := false
	if header[0] == 1 {
		if _, err := io.ReadFull(c, header[2:]); err != nil {
			return err
		}
		if header[2] > 1 {
			return errors.New("invalid multiplex padding flag")
		}
		padded = header[2] == 1
	}
	if padded {
		var n uint16
		if err := binary.Read(c, binary.BigEndian, &n); err != nil {
			return err
		}
		if _, err := io.CopyN(io.Discard, c, int64(n)); err != nil {
			return err
		}
	} else if options.Padding {
		return errors.New("non-padded multiplex connection rejected")
	}
	c.SetDeadline(time.Time{})
	wire := c
	if padded {
		wire = &genericPaddingConn{Conn: c}
	}
	if header[1] == 2 {
		return r.serveGenericH2(wire, func(stream net.Conn) { r.serveGenericMuxStream(stream, c, q, options) })
	}
	protocol := muxSMUX
	if header[1] == 1 {
		protocol = muxYAMUX
	}
	s := newMuxConfigured(r.ctx, wire, false, protocol, 1, 0, false)
	var workers sync.WaitGroup
	defer func() { s.close(net.ErrClosed); workers.Wait() }()
	for {
		select {
		case stream := <-s.accept:
			workers.Go(func() { r.serveGenericMuxStream(stream, c, q, options) })
		case <-s.done:
			s.mu.Lock()
			err := s.err
			s.mu.Unlock()
			return err
		}
	}
}
func (r *Runtime) serveGenericMuxStream(c, carrier net.Conn, q request, options MultiplexOptions) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	var flags uint16
	if err := binary.Read(c, binary.BigEndian, &flags); err != nil {
		return
	}
	if flags & ^uint16(3) != 0 || flags == 2 {
		writeMuxError(c, errors.New("invalid multiplex stream flags"))
		return
	}
	address, err := readAddress(c)
	if err != nil {
		return
	}
	if address == genericMuxAddress && flags == 0 {
		writeMuxError(c, errors.New("nested multiplex destination rejected"))
		return
	}
	q.address = address
	q.logID = 0
	q.network = "tcp"
	if flags&1 != 0 {
		q.network = "udp"
	}
	if address == brutalExchangeAddress && flags == 0 {
		var receive uint64
		if err = binary.Read(c, binary.BigEndian, &receive); err != nil {
			return
		}
		if !options.Brutal.Enabled || receive < 65536 || receive > 125000000000 {
			err = errors.New("TCP Brutal disabled or invalid receive rate")
		} else {
			err = setTCPBrutal(carrier, min(receive, uint64(options.Brutal.UpMbps)*125000))
		}
		if writeAll(c, []byte{0}) != nil {
			return
		}
		if err != nil {
			writeMuxStatus(c, 0, err)
			return
		}
		var reply [9]byte
		reply[0] = 1
		binary.BigEndian.PutUint64(reply[1:], uint64(options.Brutal.DownMbps)*125000)
		writeAll(c, reply[:])
		return
	}
	if flags&2 != 0 {
		r.serveGenericMuxPackets(c, q)
		return
	}
	remote, err := r.routeDial(r.ctx, q)
	if err != nil {
		writeMuxError(c, err)
		return
	}
	defer remote.Close()
	if writeAll(c, []byte{0}) != nil {
		return
	}
	c.SetDeadline(time.Time{})
	if q.network == "udp" {
		r.relayDatagrams(&genericPacketConn{Conn: c}, remote, r.udpTimeoutFor(q.inbound, udpTimeout))
	} else {
		r.relay(c, remote)
	}
}
func (r *Runtime) serveGenericMuxPackets(c net.Conn, q request) {
	if writeAll(c, []byte{0}) != nil {
		return
	}
	c.SetDeadline(time.Time{})
	// Packet-address mode is bounded and reuses the router's destination-aware UDP association.
	packets := &genericPacketConn{Conn: c, addresses: true}
	flows := newUDPFlows(r)
	defer flows.Close()
	q.network = "udp"
	data := make([]byte, 65535)
	for {
		c.SetReadDeadline(time.Now().Add(r.udpTimeoutFor(q.inbound, udpTimeout)))
		n, address, err := packets.readTarget(data)
		if err != nil {
			return
		}
		q.address = address
		if _, err = encodeAddress(address); err != nil {
			return
		}
		if err = flows.send(address, q, data[:n], func(b []byte, from string) error {
			c.SetWriteDeadline(time.Now().Add(handshakeTimeout))
			_, err := packets.writeTarget(b, from)
			return err
		}); err != nil {
			return
		}
	}
}

type genericPacketConn struct {
	net.Conn
	addresses       bool
	readMu, writeMu sync.Mutex
}

func (c *genericPacketConn) Read(p []byte) (int, error) { n, _, err := c.readTarget(p); return n, err }
func (c *genericPacketConn) readTarget(p []byte) (int, string, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	var address string
	var err error
	if c.addresses {
		address, err = readAddress(c.Conn)
		if err != nil {
			return 0, "", err
		}
	}
	var n uint16
	if err = binary.Read(c.Conn, binary.BigEndian, &n); err != nil {
		return 0, address, err
	}
	if int(n) > len(p) {
		_, err = io.CopyN(io.Discard, c.Conn, int64(n))
		if err == nil {
			err = io.ErrShortBuffer
		}
		return 0, address, err
	}
	size, err := io.ReadFull(c.Conn, p[:n])
	return size, address, err
}
func (c *genericPacketConn) Write(p []byte) (int, error) { return c.writeTarget(p, "") }
func (c *genericPacketConn) writeTarget(p []byte, address string) (int, error) {
	if len(p) > 65535 {
		return 0, errors.New("multiplex UDP packet exceeds 65535 bytes")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	var header []byte
	if c.addresses {
		var err error
		header, err = encodeAddress(address)
		if err != nil {
			return 0, err
		}
	}
	header = binary.BigEndian.AppendUint16(header, uint16(len(p)))
	if err := writeAll(c.Conn, header); err != nil {
		return 0, err
	}
	if err := writeAll(c.Conn, p); err != nil {
		return 0, err
	}
	return len(p), nil
}
