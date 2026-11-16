package native

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const brookQUICDatagramLimit = 1197

// Brook closes the connection with each stream. UDP also needs separate
// connections because its datagrams have no association identifier.
type brookQUICPacket struct {
	client                      *quicTransportClient
	conn                        *quicConn
	mu                          sync.Mutex
	readDeadline, writeDeadline time.Time
	readWake, writeWake         chan struct{}
	once                        sync.Once
}

func (r *Runtime) brookQUICPacketClient(ctx context.Context, o Outbound, address string) (net.Conn, error) {
	encoded, err := encodeAddress(address)
	if err != nil {
		return nil, err
	}
	c, err := r.quicTransports[o.Tag].brookConnection(ctx)
	if err != nil {
		return nil, err
	}
	return r.own(&brookPacketConn{Conn: c, password: o.Password, options: o.BrookOptions, address: encoded, replay: &r.replay})
}

func (p *quicTransportClient) brookConnection(ctx context.Context) (*brookQUICPacket, error) {
	p.mu.Lock()
	if len(p.packets) >= 128 {
		p.mu.Unlock()
		return nil, errors.New("Brook QUIC connection limit reached")
	}
	q, err := p.connect(ctx)
	if err != nil {
		p.mu.Unlock()
		return nil, err
	}
	c := &brookQUICPacket{client: p, conn: q, readWake: make(chan struct{}), writeWake: make(chan struct{})}
	if p.packets == nil {
		p.packets = make(map[*brookQUICPacket]struct{})
	}
	p.packets[c] = struct{}{}
	p.mu.Unlock()
	return c, nil
}

type brookQUICStream struct {
	*quicStream
	owner *brookQUICPacket
}

func (s *brookQUICStream) Close() error {
	s.quicStream.Close()
	return s.owner.Close()
}

func (c *brookQUICPacket) Read(b []byte) (int, error) {
	for {
		c.mu.Lock()
		deadline, changed := c.readDeadline, c.readWake
		c.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		var packet []byte
		var err error
		select {
		case packet = <-c.conn.datagrams:
		case <-c.conn.done:
			err = c.conn.err()
		case <-changed:
		case <-timeout:
			err = os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
		if err != nil {
			return 0, err
		}
		if packet != nil {
			if len(packet) > brookQUICDatagramLimit {
				continue
			}
			if len(packet) > len(b) {
				return 0, io.ErrShortBuffer
			}
			return copy(b, packet), nil
		}
	}
}

func (c *brookQUICPacket) Write(b []byte) (int, error) {
	if len(b) > min(brookQUICDatagramLimit, c.conn.datagramLimit()) {
		return 0, errors.New("Brook QUIC datagram exceeds limit; enable udp_over_stream for large packets")
	}
	deadline, _, _ := c.writeState()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	op := newQUICOperation('d', nil)
	op.data = append([]byte{}, b...)
	if err := c.conn.do(c.conn.ctx, op, c).err; err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *brookQUICPacket) writeState() (time.Time, <-chan struct{}, <-chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeDeadline, c.writeWake, c.conn.done
}

func (c *brookQUICPacket) Close() error {
	c.once.Do(func() {
		c.conn.Close()
		c.client.mu.Lock()
		delete(c.client.packets, c)
		c.client.mu.Unlock()
	})
	return nil
}

func (c *brookQUICPacket) LocalAddr() net.Addr  { return c.conn.local }
func (c *brookQUICPacket) RemoteAddr() net.Addr { return c.conn.remote }
func (c *brookQUICPacket) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	close(c.readWake)
	c.readWake = make(chan struct{})
	c.mu.Unlock()
	return nil
}
func (c *brookQUICPacket) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	close(c.writeWake)
	c.writeWake = make(chan struct{})
	c.mu.Unlock()
	return nil
}
func (c *brookQUICPacket) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (r *Runtime) serveBrookQUICPackets(in Inbound, q *quicConn) {
	flows := newUDPFlows(r)
	defer flows.Close()
	for {
		packet, err := q.ReceiveDatagram(q.ctx)
		if err != nil {
			return
		}
		if len(packet) > brookQUICDatagramLimit {
			continue
		}
		r.brookDatagram(in, flows, packet, q.remote, q.local, func(packet []byte) error {
			if len(packet) > brookQUICDatagramLimit {
				return errors.New("Brook QUIC reply exceeds datagram limit")
			}
			return q.SendDatagram(q.ctx, packet)
		})
	}
}
