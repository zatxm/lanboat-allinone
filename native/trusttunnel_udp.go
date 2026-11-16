package native

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

const trustUDPMax = 65507

func trustIP(b []byte) netip.Addr {
	a := netip.AddrFrom16([16]byte(b[:16]))
	// ::1 is the one zero-prefixed address that denotes IPv6 loopback.
	if a.IsLoopback() {
		return a
	}
	for _, v := range b[:12] {
		if v != 0 {
			return a.Unmap()
		}
	}
	return netip.AddrFrom4([4]byte(b[12:16]))
}
func trustPutIP(b []byte, a netip.Addr) {
	clear(b[:16])
	a = a.Unmap()
	if a.Is4() {
		v := a.As4()
		copy(b[12:16], v[:])
	} else {
		v := a.As16()
		copy(b[:16], v[:])
	}
}
func trustReadPacket(r io.Reader, b []byte, request bool) (source, destination netip.AddrPort, payload []byte, err error) {
	var header [4]byte
	if _, err = io.ReadFull(r, header[:]); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint32(header[:]))
	minimum := 36
	if request {
		minimum++
	}
	if n < minimum || n > len(b) {
		err = errors.New("invalid TrustTunnel UDP frame length")
		return
	}
	if _, err = io.ReadFull(r, b[:n]); err != nil {
		return
	}
	source = netip.AddrPortFrom(trustIP(b[:16]), binary.BigEndian.Uint16(b[16:18]))
	destination = netip.AddrPortFrom(trustIP(b[18:34]), binary.BigEndian.Uint16(b[34:36]))
	if destination.Port() == 0 {
		err = errors.New("TrustTunnel UDP destination port is zero")
		return
	}
	offset := 36
	if request {
		offset += 1 + int(b[36])
		if offset > n {
			err = io.ErrUnexpectedEOF
			return
		}
	}
	if n-offset > trustUDPMax {
		err = errors.New("TrustTunnel UDP payload exceeds limit")
		return
	}
	payload = b[offset:n]
	return
}
func trustWritePacket(w io.Writer, source, destination netip.AddrPort, payload []byte, request bool) error {
	if len(payload) > trustUDPMax {
		return errors.New("TrustTunnel UDP payload exceeds limit")
	}
	var h [41]byte
	size := 36 + len(payload)
	header := h[:40]
	if request {
		size++
		header = h[:41]
	}
	binary.BigEndian.PutUint32(h[:4], uint32(size))
	trustPutIP(h[4:20], source.Addr())
	binary.BigEndian.PutUint16(h[20:22], source.Port())
	trustPutIP(h[22:38], destination.Addr())
	binary.BigEndian.PutUint16(h[38:40], destination.Port())
	if err := writeAll(w, header); err != nil {
		return err
	}
	return writeAll(w, payload)
}
func (r *Runtime) serveTrustUDP(c net.Conn, q request) error {
	flows := newUDPFlows(r)
	flows.timeout = 120 * time.Second
	defer flows.Close()
	var writeMu sync.Mutex
	b := make([]byte, 36+1+255+trustUDPMax)
	for {
		c.SetReadDeadline(time.Now().Add(120 * time.Second))
		src, dst, payload, e := trustReadPacket(c, b, true)
		if e != nil {
			return e
		}
		if dst.Addr().IsUnspecified() || dst.Addr().IsMulticast() {
			continue
		}
		q.address = dst.String()
		e = flows.send(src.String()+"/"+dst.String(), q, payload, func(p []byte, _ string) error {
			writeMu.Lock()
			defer writeMu.Unlock()
			c.SetWriteDeadline(time.Now().Add(handshakeTimeout))
			return trustWritePacket(c, dst, src, p, false)
		})
		// A denied or unreachable destination must not terminate other UDP flows.
		if e != nil && r.ctx.Err() != nil {
			return e
		}
	}
}

type trustUDPMux struct {
	conn        net.Conn
	mu, writeMu sync.Mutex
	packets     map[netip.AddrPort]*trustPacket
	next        uint32
	done        chan struct{}
	once        sync.Once
}

func (m *trustUDPMux) close() { m.once.Do(func() { close(m.done); m.conn.Close() }) }
func (c *trustClient) dialPacket(ctx context.Context, address string) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	ips, e := c.runtime.directIPs(ctx, host)
	if e != nil {
		return nil, e
	}
	if len(ips) == 0 {
		return nil, errors.New("TrustTunnel UDP target resolved to no addresses")
	}
	destination, e := netip.ParseAddrPort(net.JoinHostPort(ips[0].String(), port))
	if e != nil || destination.Port() == 0 {
		return nil, errors.New("invalid TrustTunnel UDP destination")
	}
	if destination.Addr().Is4() && destination.Addr().String() == "0.0.0.1" {
		return nil, errors.New("0.0.0.1 is ambiguous in TrustTunnel padded addressing")
	}
	c.muxMu.Lock()
	defer c.muxMu.Unlock()
	m := c.udp
	if m != nil {
		select {
		case <-m.done:
			m = nil
		default:
		}
	}
	if m == nil {
		conn, e := c.connect(ctx, "_udp2")
		if e != nil {
			return nil, e
		}
		m = &trustUDPMux{conn: conn, packets: map[netip.AddrPort]*trustPacket{}, done: make(chan struct{})}
		c.udp = m
		go m.receive()
	}
	m.mu.Lock()
	if len(m.packets) >= 256 || m.next >= ^uint32(0)-1 {
		m.mu.Unlock()
		return nil, errors.New("TrustTunnel UDP association limit reached")
	}
	m.next++
	if uint16(m.next) == 0 {
		m.next++
	}
	label := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(m.next >> 24), byte(m.next >> 16)}), uint16(m.next))
	p := &trustPacket{mux: m, id: label, destination: destination, incoming: make(chan []byte, 1), done: make(chan struct{}), wake: make(chan struct{})}
	m.packets[p.id] = p
	m.mu.Unlock()
	return c.runtime.own(p)
}
func (m *trustUDPMux) receive() {
	defer m.close()
	b := make([]byte, 36+trustUDPMax)
	for {
		m.conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		src, dst, payload, e := trustReadPacket(m.conn, b, false)
		if e != nil {
			return
		}
		if !dst.Addr().Is4() {
			continue
		}
		m.mu.Lock()
		p := m.packets[dst]
		m.mu.Unlock()
		if p == nil || p.destination != src {
			continue
		}
		// A slow association drops datagrams instead of stalling every other flow.
		select {
		case p.incoming <- append([]byte{}, payload...):
		default:
		}
	}
}

type trustPacket struct {
	mux                         *trustUDPMux
	id                          netip.AddrPort
	destination                 netip.AddrPort
	incoming                    chan []byte
	done                        chan struct{}
	once                        sync.Once
	mu                          sync.Mutex
	wake                        chan struct{}
	readDeadline, writeDeadline time.Time
}

func (p *trustPacket) Read(b []byte) (int, error) {
	for {
		p.mu.Lock()
		d, wake := p.readDeadline, p.wake
		p.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !d.IsZero() {
			timer = time.NewTimer(max(0, time.Until(d)))
			timeout = timer.C
		}
		var payload []byte
		var e error
		select {
		case payload = <-p.incoming:
		case <-p.done:
			e = net.ErrClosed
		case <-p.mux.done:
			e = net.ErrClosed
		case <-wake:
		case <-timeout:
			e = os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
		if e != nil {
			return 0, e
		}
		if payload != nil {
			if len(payload) > len(b) {
				return 0, io.ErrShortBuffer
			}
			return copy(b, payload), nil
		}
	}
}
func (p *trustPacket) Write(b []byte) (int, error) {
	if len(b) > trustUDPMax {
		return 0, errors.New("TrustTunnel UDP payload exceeds limit")
	}
	select {
	case <-p.done:
		return 0, net.ErrClosed
	case <-p.mux.done:
		return 0, net.ErrClosed
	default:
	}
	p.mux.writeMu.Lock()
	defer p.mux.writeMu.Unlock()
	p.mu.Lock()
	d := p.writeDeadline
	p.mu.Unlock()
	limit := time.Now().Add(handshakeTimeout)
	if !d.IsZero() && d.Before(limit) {
		limit = d
	}
	if !limit.After(time.Now()) {
		return 0, os.ErrDeadlineExceeded
	}
	p.mux.conn.SetWriteDeadline(limit)
	e := trustWritePacket(p.mux.conn, p.id, p.destination, b, true)
	if e != nil {
		p.mux.close()
		return 0, e
	}
	return len(b), nil
}
func (p *trustPacket) Close() error {
	p.once.Do(func() { close(p.done); p.mux.mu.Lock(); delete(p.mux.packets, p.id); p.mux.mu.Unlock() })
	return nil
}
func (p *trustPacket) LocalAddr() net.Addr  { return p.mux.conn.LocalAddr() }
func (p *trustPacket) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(p.destination) }
func (p *trustPacket) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.readDeadline = t
	close(p.wake)
	p.wake = make(chan struct{})
	p.mu.Unlock()
	return nil
}
func (p *trustPacket) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	p.writeDeadline = t
	p.mu.Unlock()
	return nil
}
func (p *trustPacket) SetDeadline(t time.Time) error {
	p.SetWriteDeadline(t)
	return p.SetReadDeadline(t)
}
