package native

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

const quicInboxPackets = 256
const quicInboxBytes = 256 << 10

func (c *quicConn) queuePacket(data []byte, remote net.Addr) bool {
	c.packetMu.Lock()
	defer c.packetMu.Unlock()
	if c.ctx.Err() != nil || c.packetBytes+len(data) > quicInboxBytes || len(c.packets) == cap(c.packets) {
		return false
	}
	c.packets <- quicDatagram{data: append([]byte(nil), data...), remote: remote}
	c.packetBytes += len(data)
	return true
}
func (c *quicConn) discardPackets() {
	c.packetMu.Lock()
	defer c.packetMu.Unlock()
	for {
		select {
		case <-c.packets:
		default:
			c.packetBytes = 0
			return
		}
	}
}

func (c *quicConn) receivePacket(packet quicDatagram) error {
	c.packetMu.Lock()
	c.packetBytes -= len(packet.data)
	c.packetMu.Unlock()
	c.packetRemote = packet.remote
	err := c.handleDatagram(packet.data)
	c.packetRemote = nil
	return err
}
func (c *quicConn) receiveBurst() error {
	for range 32 {
		select {
		case packet := <-c.packets:
			if err := c.receivePacket(packet); err != nil {
				return err
			}
		default:
			return nil
		}
	}
	return nil
}

type quicEndpoint struct {
	options quicOptions
	ctx     context.Context
	cancel  context.CancelFunc
	packet  net.PacketConn
	config  *tls.Config
	secret  [32]byte
	mu      sync.Mutex
	conns   map[string]*quicConn
	accept  chan *quicConn
	done    chan struct{}
	once    sync.Once
}

func listenQUIC(ctx context.Context, packet net.PacketConn, config *tls.Config, options ...quicOptions) (*quicEndpoint, error) {
	if config == nil || len(config.Certificates) == 0 && config.GetCertificate == nil && config.GetConfigForClient == nil || len(config.NextProtos) == 0 {
		return nil, errors.New("QUIC server requires certificate and ALPN")
	}
	child, cancel := context.WithCancel(ctx)
	var option quicOptions
	if len(options) > 0 {
		option = options[0]
	}
	if option.discoverMTU || option.packetSize != 0 {
		if err := quicDontFragment(packet); err != nil {
			cancel()
			return nil, err
		}
	}
	e := &quicEndpoint{options: option, ctx: child, cancel: cancel, packet: packet, config: config, conns: map[string]*quicConn{}, accept: make(chan *quicConn, 128), done: make(chan struct{})}
	rand.Read(e.secret[:])
	go e.readLoop()
	return e, nil
}
func (e *quicEndpoint) retryToken(remote net.Addr, odcid, scid []byte) []byte {
	token := binary.BigEndian.AppendUint64(nil, uint64(time.Now().Unix()))
	token = append(token, byte(len(odcid)))
	token = append(token, odcid...)
	token = append(token, scid...)
	m := hmac.New(sha256.New, e.secret[:])
	m.Write([]byte(remote.String()))
	m.Write(token)
	return append(token, m.Sum(nil)[:16]...)
}
func (e *quicEndpoint) checkToken(remote net.Addr, cid, token []byte) ([]byte, bool) {
	if len(token) < 8+1+8+8+16 || len(token) > 128 {
		return nil, false
	}
	n := int(token[8])
	if n < 8 || n > 20 || len(token) != 9+n+8+16 {
		return nil, false
	}
	now := time.Now().Unix()
	issued := int64(binary.BigEndian.Uint64(token))
	if issued > now+1 || now-issued > 30 || !bytes.Equal(token[9+n:9+n+8], cid) {
		return nil, false
	}
	m := hmac.New(sha256.New, e.secret[:])
	m.Write([]byte(remote.String()))
	m.Write(token[:len(token)-16])
	if !hmac.Equal(m.Sum(nil)[:16], token[len(token)-16:]) {
		return nil, false
	}
	return token[9 : 9+n], true
}
func (e *quicEndpoint) sendRetry(remote net.Addr, h quicHeader) {
	scid := make([]byte, 8)
	rand.Read(scid)
	token := e.retryToken(remote, h.dcid, scid)
	packet := []byte{0xf0, 0, 0, 0, 1, byte(len(h.scid))}
	packet = append(packet, h.scid...)
	packet = append(packet, 8)
	packet = append(packet, scid...)
	packet = append(packet, token...)
	packet = append(packet, quicRetryTag(h.dcid, packet)...)
	e.packet.WriteTo(packet, remote)
}
func (e *quicEndpoint) readLoop() {
	defer close(e.done)
	buffer := make([]byte, 65535)
	for {
		n, remote, err := e.packet.ReadFrom(buffer)
		if err != nil {
			return
		}
		header, err := parseQUICHeader(buffer[:n])
		if err != nil || header.retry {
			continue
		}
		e.mu.Lock()
		conn := e.conns[string(header.dcid)]
		e.mu.Unlock()
		if conn == nil {
			if header.level != 0 || n < 1200 || len(header.dcid) < 8 {
				continue
			}
			odcid, ok := e.checkToken(remote, header.dcid, header.token)
			if !ok {
				e.sendRetry(remote, header)
				continue
			}
			e.mu.Lock()
			if e.ctx.Err() != nil {
				e.mu.Unlock()
				return
			}
			if len(e.conns) >= 256 {
				e.mu.Unlock()
				continue
			}
			cid := append([]byte{}, header.dcid...)
			var createErr error
			conn, createErr = newQUICConn(e.ctx, e.config, e.packet.LocalAddr(), remote, cid, header.scid, odcid, cid, true, func(b []byte) error { _, err := e.packet.WriteTo(b, remote); return err }, func() { e.mu.Lock(); delete(e.conns, string(cid)); e.mu.Unlock() }, e.options)
			if createErr != nil {
				e.mu.Unlock()
				continue
			}
			conn.onReady = func(c *quicConn) bool {
				select {
				case e.accept <- c:
					return true
				default:
					return false
				}
			}
			conn.sendTo = func(b []byte, target net.Addr) error { _, err := e.packet.WriteTo(b, target); return err }
			conn.send = func(b []byte) error { return conn.sendTo(b, conn.pathRemote) }
			e.conns[string(cid)] = conn
			e.mu.Unlock()
			go conn.run()
		}
		if !sameQUICIP(remote, conn.remote) {
			continue
		}
		conn.queuePacket(buffer[:n], remote)
	}
}
func (e *quicEndpoint) Accept(ctx context.Context) (*quicConn, error) {
	select {
	case c := <-e.accept:
		return c, nil
	case <-e.ctx.Done():
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (e *quicEndpoint) Close() error {
	e.once.Do(func() {
		e.cancel()
		_ = e.packet.SetWriteDeadline(time.Now().Add(time.Second))
		e.mu.Lock()
		all := make([]*quicConn, 0, len(e.conns))
		for _, c := range e.conns {
			all = append(all, c)
		}
		e.mu.Unlock()
		for _, c := range all {
			c.cancel()
		}
		for _, c := range all {
			<-c.done
		}
		// Let CONNECTION_CLOSE reach the peer before closing its UDP socket.
		e.packet.Close()
		<-e.done
	})
	return nil
}
func dialQUIC(ctx, parent context.Context, raw net.Conn, config *tls.Config, options ...quicOptions) (*quicConn, error) {
	if config == nil || len(config.NextProtos) == 0 {
		raw.Close()
		return nil, errors.New("QUIC client requires TLS and ALPN")
	}
	if len(options) > 0 && (options[0].discoverMTU || options[0].packetSize != 0) {
		if err := quicDontFragment(raw); err != nil {
			raw.Close()
			return nil, err
		}
	}
	cid, dcid := make([]byte, 8), make([]byte, 8)
	rand.Read(cid)
	rand.Read(dcid)
	readDone := make(chan struct{})
	conn, err := newQUICConn(parent, config, raw.LocalAddr(), raw.RemoteAddr(), cid, dcid, dcid, nil, false, func(b []byte) error { _, err := raw.Write(b); return err }, func() { raw.Close(); <-readDone }, options...)
	if err != nil {
		raw.Close()
		return nil, err
	}
	go func() {
		defer close(readDone)
		buffer := make([]byte, 65535)
		for {
			n, err := raw.Read(buffer)
			if err != nil {
				conn.cancel()
				return
			}
			conn.queuePacket(buffer[:n], nil)
		}
	}()
	go conn.run()
	select {
	case <-conn.ready:
		return conn, nil
	case <-conn.done:
		return nil, conn.err()
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	}
}
