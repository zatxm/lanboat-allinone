package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

func encodeRelayBind(address string) ([]byte, error) {
	if address == "" {
		address = "0.0.0.0:0"
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = "0.0.0.0"
	}
	if ip, err := netip.ParseAddr(host); err != nil || ip.Zone() != "" {
		return nil, errors.New("Relay bind address must be an unscoped IP")
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	encoded, err := encodeAddress(net.JoinHostPort(host, "1"))
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(encoded[len(encoded)-2:], uint16(n))
	return encoded, nil
}

func readRelayResponse(reader io.Reader) (string, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return "", err
	}
	if header[0] != 1 || header[1] != 0 {
		return "", fmt.Errorf("Relay response status %d (version %d)", header[1], header[0])
	}
	size := int(binary.BigEndian.Uint16(header[2:]))
	if size > 4096 {
		return "", errors.New("Relay response features exceed limit")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return "", err
	}
	var address string
	for len(data) > 0 {
		if len(data) < 3 {
			return "", io.ErrUnexpectedEOF
		}
		kind, n := data[0], int(binary.BigEndian.Uint16(data[1:3]))
		data = data[3:]
		if n > len(data) {
			return "", io.ErrUnexpectedEOF
		}
		if kind == 2 {
			r := bytes.NewReader(data[:n])
			a, err := readAddress(r)
			if err != nil || r.Len() != 0 {
				return "", errors.New("invalid Relay response address")
			}
			if _, err = encodeAddress(a); err != nil {
				return "", err
			}
			if address == "" {
				address = a
			}
		}
		data = data[n:]
	}
	return address, nil
}
func writeRelayResponse(w io.Writer, address string) error {
	features := []byte(nil)
	if address != "" {
		a, err := encodeAddress(address)
		if err != nil {
			return err
		}
		features = relayFeature(2, a)
	}
	h := binary.BigEndian.AppendUint16([]byte{1, 0}, uint16(len(features)))
	return writeAll(w, append(h, features...))
}

func (r *Runtime) relayBindConn(ctx context.Context, tag, address string, udp bool) (net.Conn, string, error) {
	o, ok := r.outbounds[tag]
	if !ok || o.Type != "relay" {
		return nil, "", errors.New("Relay BIND requires a relay outbound tag")
	}
	a, err := encodeRelayBind(address)
	if err != nil {
		return nil, "", err
	}
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	stopRuntime := context.AfterFunc(r.ctx, cancel)
	defer stopRuntime()
	if o.DomainResolver != "" {
		opt := o.DomainResolver.options()
		ctx = context.WithValue(ctx, dnsBootstrapKey{}, opt.Server)
		ctx = context.WithValue(ctx, dnsQueryOptionsKey{}, opt)
	}
	c, err := r.dialProxyTransport(ctx, o)
	if err != nil {
		return nil, "", err
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	features := relayFeature(2, a)
	if o.Username != "" || o.Password != "" {
		auth := append([]byte{byte(len(o.Username))}, o.Username...)
		auth = append(auth, byte(len(o.Password)))
		auth = append(auth, o.Password...)
		features = append(features, relayFeature(1, auth)...)
	}
	cmd := byte(2)
	if udp {
		cmd |= 128
	}
	header := binary.BigEndian.AppendUint16([]byte{1, cmd}, uint16(len(features)))
	if err = writeAll(c, append(header, features...)); err == nil {
		address, err = readRelayResponse(c)
	}
	if err == nil && address == "" {
		err = errors.New("Relay BIND response has no address")
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		c.Close()
		return nil, "", err
	}
	_ = c.SetDeadline(time.Time{})
	return c, address, nil
}

type relayListener struct {
	session *smuxSession
	address net.Addr
	stop    func() bool
}

// ListenRelay opens an authenticated remote TCP listener through a Relay node.
// Its lifetime is bounded by ctx, Runtime.Close, or the returned listener.Close.
func (r *Runtime) ListenRelay(ctx context.Context, tag, address string) (net.Listener, error) {
	c, bound, err := r.relayBindConn(ctx, tag, address, false)
	if err != nil {
		return nil, err
	}
	ap, err := netip.ParseAddrPort(bound)
	a := net.TCPAddrFromAddrPort(ap)
	if err != nil {
		c.Close()
		return nil, err
	}
	s := newSMUX(r.ctx, c, false)
	l := &relayListener{session: s, address: a}
	l.stop = context.AfterFunc(ctx, func() { s.close(net.ErrClosed) })
	return l, nil
}
func (l *relayListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.session.accept:
		_ = c.SetReadDeadline(time.Now().Add(handshakeTimeout))
		peer, err := readRelayResponse(c)
		if err != nil || peer == "" {
			c.Close()
			if err == nil {
				err = errors.New("Relay peer response has no address")
			}
			return nil, err
		}
		ap, err := netip.ParseAddrPort(peer)
		a := net.TCPAddrFromAddrPort(ap)
		if err != nil {
			c.Close()
			return nil, err
		}
		_ = c.SetReadDeadline(time.Time{})
		return &relayPeerConn{smuxStream: c, local: l.address, remote: a}, nil
	case <-l.session.done:
		return nil, net.ErrClosed
	}
}
func (l *relayListener) Close() error   { l.stop(); l.session.close(net.ErrClosed); return nil }
func (l *relayListener) Addr() net.Addr { return l.address }

type relayPeerConn struct {
	*smuxStream
	local, remote net.Addr
}

func (c *relayPeerConn) LocalAddr() net.Addr  { return c.local }
func (c *relayPeerConn) RemoteAddr() net.Addr { return c.remote }

type relayPacketConn struct {
	net.Conn
	address         net.Addr
	readMu, writeMu sync.Mutex
	stop            func() bool
}
type relayUDPAddress string

func (a relayUDPAddress) Network() string { return "udp" }
func (a relayUDPAddress) String() string  { return string(a) }

// ListenRelayPacket opens a remote UDP socket; datagrams retain their peer address.
func (r *Runtime) ListenRelayPacket(ctx context.Context, tag, address string) (net.PacketConn, error) {
	c, bound, err := r.relayBindConn(ctx, tag, address, true)
	if err != nil {
		return nil, err
	}
	ap, err := netip.ParseAddrPort(bound)
	a := net.UDPAddrFromAddrPort(ap)
	if err != nil {
		c.Close()
		return nil, err
	}
	p := &relayPacketConn{Conn: c, address: a}
	p.stop = context.AfterFunc(ctx, func() { c.Close() })
	return p, nil
}
func (c *relayPacketConn) Close() error {
	if c.stop != nil {
		c.stop()
	}
	return c.Conn.Close()
}
func (c *relayPacketConn) LocalAddr() net.Addr { return c.address }
func (c *relayPacketConn) ReadFrom(p []byte) (n int, peer net.Addr, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	var h [3]byte
	consumed, err := io.ReadFull(c.Conn, h[:])
	defer func() {
		// A partial frame cannot be retried at a new boundary. An idle read
		// timeout before any header byte remains recoverable.
		if err != nil && consumed > 0 {
			c.Conn.Close()
		}
	}()
	if err != nil {
		return 0, nil, err
	}
	size := int(binary.BigEndian.Uint16(h[:2]))
	if h[2] != 255 || size > 65507 {
		return 0, nil, errors.New("invalid Relay UDP tunnel frame")
	}
	address, err := readAddress(c.Conn)
	if err != nil {
		return 0, nil, err
	}
	if _, err = encodeAddress(address); err != nil {
		return 0, nil, err
	}
	n = min(size, len(p))
	if _, err = io.ReadFull(c.Conn, p[:n]); err != nil {
		return 0, nil, err
	}
	if _, err = io.CopyN(io.Discard, c.Conn, int64(size-n)); err != nil {
		return 0, nil, err
	}
	var a net.Addr = relayUDPAddress(address)
	if ip, err := netip.ParseAddrPort(address); err == nil {
		a = net.UDPAddrFromAddrPort(ip)
	}
	return n, a, nil
}
func (c *relayPacketConn) WriteTo(p []byte, a net.Addr) (int, error) {
	if len(p) > 65507 {
		return 0, errors.New("Relay UDP payload exceeds limit")
	}
	if a == nil {
		return 0, errors.New("Relay UDP requires a destination")
	}
	encoded, err := encodeAddress(a.String())
	if err != nil {
		return 0, err
	}
	h := binary.BigEndian.AppendUint16(nil, uint16(len(p)))
	h = append(h, 255)
	h = append(h, encoded...)
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err = writeAll(c.Conn, h); err == nil {
		err = writeAll(c.Conn, p)
	}
	if err != nil {
		c.Conn.Close()
		return 0, err
	}
	return len(p), nil
}

func (r *Runtime) serveRelayBind(in Inbound, c net.Conn, q relayRequest) error {
	if !in.Bind {
		_ = writeAll(c, []byte{1, 3, 0, 0})
		return errors.New("Relay BIND disabled")
	}
	if r.relayBinds.Add(1) > 32 {
		r.relayBinds.Add(-1)
		_ = writeAll(c, []byte{1, 4, 0, 0})
		return errors.New("Relay BIND capacity exceeded")
	}
	var listener net.Listener
	var packets net.PacketConn
	var err error
	if q.udp {
		packets, err = in.ListenOptions.listenPacket(r.ctx, "udp", q.address)
	} else {
		listener, err = in.ListenOptions.listen(r.ctx, "tcp", q.address)
	}
	if err != nil {
		// Once the peer sees a failure it can retry immediately; free the slot
		// before writing that response rather than after the handler returns.
		r.relayBinds.Add(-1)
		_ = writeAll(c, []byte{1, 4, 0, 0})
		return err
	}
	defer r.relayBinds.Add(-1)
	if q.udp {
		defer packets.Close()
		return r.serveRelayUDPBind(c, packets)
	}
	defer listener.Close()
	if err = writeRelayResponse(c, listener.Addr().String()); err != nil {
		return err
	}
	s := newSMUX(r.ctx, c, true)
	defer s.close(net.ErrClosed)
	go func() { <-s.done; listener.Close() }()
	// The reverse-listener client must not open streams back into the server.
	go func() {
		for {
			select {
			case peer := <-s.accept:
				peer.Close()
			case <-s.done:
				return
			}
		}
	}()
	var workers sync.WaitGroup
	defer func() { s.close(net.ErrClosed); workers.Wait() }()
	for {
		peer, err := listener.Accept()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(s.ctx, handshakeTimeout)
		stream, err := s.open(ctx)
		cancel()
		if err != nil {
			peer.Close()
			if s.ctx.Err() != nil {
				return err
			}
			continue
		}
		workers.Go(func() {
			defer peer.Close()
			stop := context.AfterFunc(s.ctx, func() { peer.Close() })
			defer stop()
			defer stream.Close()
			_ = stream.SetWriteDeadline(time.Now().Add(handshakeTimeout))
			if writeRelayResponse(stream, peer.RemoteAddr().String()) == nil {
				r.relay(stream, peer)
			}
		})
	}
}
func (r *Runtime) serveRelayUDPBind(c net.Conn, pc net.PacketConn) error {
	if err := writeRelayResponse(c, pc.LocalAddr().String()); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { c.Close(); pc.Close() })
	defer stop()
	tunnel := &relayPacketConn{Conn: c, address: pc.LocalAddr()}
	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 65507)
		for {
			n, from, e := pc.ReadFrom(buffer)
			if e == nil {
				_, e = tunnel.WriteTo(buffer[:n], from)
				if e == nil {
					r.down.Add(int64(n))
				}
			}
			if e != nil {
				done <- e
				cancel()
				return
			}
		}
	}()
	var err error
	buffer := make([]byte, 65507)
	for {
		n, to, e := tunnel.ReadFrom(buffer)
		if e != nil {
			err = e
			break
		}
		ap, e := netip.ParseAddrPort(to.String())
		if e != nil {
			host, port, _ := net.SplitHostPort(to.String())
			ips, e := r.directIPs(ctx, host)
			if e != nil || len(ips) == 0 {
				err = errors.New("Relay UDP destination resolution failed")
				break
			}
			value, _ := strconv.ParseUint(port, 10, 16)
			ap = netip.AddrPortFrom(ips[0], uint16(value))
		}
		if _, e = pc.WriteTo(buffer[:n], net.UDPAddrFromAddrPort(ap)); e != nil {
			err = e
			break
		}
		r.up.Add(int64(n))
	}
	cancel()
	<-done
	return err
}
