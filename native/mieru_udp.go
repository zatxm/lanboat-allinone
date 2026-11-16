package native

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type mieruListener struct {
	r      *Runtime
	in     Inbound
	packet net.PacketConn
	mu     sync.Mutex
	peers  map[string]*mieruCarrier
	closed bool
}

func (l *mieruListener) close() {
	l.packet.Close()
	l.mu.Lock()
	l.closed = true
	peers := make([]*mieruCarrier, 0, len(l.peers))
	for _, m := range l.peers {
		peers = append(peers, m)
	}
	l.mu.Unlock()
	for _, m := range peers {
		m.close()
	}
}
func (l *mieruListener) run() {
	if udp, ok := l.packet.(*net.UDPConn); ok {
		_ = udp.SetReadBuffer(1 << 20)
	}
	defer l.close()
	tickDone := make(chan struct{})
	var worker sync.WaitGroup
	worker.Add(1)
	defer func() { close(tickDone); worker.Wait() }()
	// One maintenance clock per listening socket, rather than one per UDP peer.
	go func() {
		defer worker.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				l.mu.Lock()
				peers := make([]*mieruCarrier, 0, len(l.peers))
				for k, m := range l.peers {
					if m.closed.Load() {
						delete(l.peers, k)
						continue
					}
					peers = append(peers, m)
				}
				l.mu.Unlock()
				for _, m := range peers {
					m.tick(now)
				}
			case <-tickDone:
				return
			case <-l.r.ctx.Done():
				return
			}
		}
	}()
	b := make([]byte, 2048)
	for {
		n, from, e := l.packet.ReadFrom(b)
		if e != nil {
			return
		}
		key := from.String()
		l.mu.Lock()
		m := l.peers[key]
		if m != nil && m.closed.Load() {
			delete(l.peers, key)
			m = nil
		}
		l.mu.Unlock()
		var f mieruFrame
		if m == nil {
			first, u, a, e := mieruDecodePacket(b[:n], l.r.mieruUsers[l.in.Tag], nil)
			if e != nil || first.kind != 2 || first.seq != 0 {
				continue
			}
			if e = l.r.replay.claimFor(mieruReplayKey(b[:n]), 2*time.Minute); e != nil {
				continue
			}
			raw := &mieruPacketPeer{listener: l, remote: from}
			m = newMieruCarrier(l.r, raw, true, false, &l.in, l.in.MieruOptions, l.in.MTU)
			m.user = u
			m.recv.key = a
			m.key = a
			l.mu.Lock()
			if len(l.peers) >= 128 || l.closed {
				l.mu.Unlock()
				m.close()
				continue
			}
			l.peers[key] = m
			l.mu.Unlock()
			f = first
		} else {
			f, e = m.decodePacket(b[:n])
			if e != nil {
				continue
			}
		}
		m.last.Store(time.Now().UnixNano())
		if e = m.handle(f); e != nil {
			m.close()
		}
	}
}

type mieruPacketPeer struct {
	listener *mieruListener
	remote   net.Addr
}

func (p *mieruPacketPeer) Write(b []byte) (int, error) { return p.listener.packet.WriteTo(b, p.remote) }
func (p *mieruPacketPeer) Read([]byte) (int, error) {
	return 0, errors.New("Mieru peer is owned by packet dispatcher")
}
func (p *mieruPacketPeer) Close() error                     { return nil }
func (p *mieruPacketPeer) LocalAddr() net.Addr              { return p.listener.packet.LocalAddr() }
func (p *mieruPacketPeer) RemoteAddr() net.Addr             { return p.remote }
func (p *mieruPacketPeer) SetDeadline(time.Time) error      { return nil }
func (p *mieruPacketPeer) SetReadDeadline(time.Time) error  { return nil }
func (p *mieruPacketPeer) SetWriteDeadline(time.Time) error { return nil }

func (r *Runtime) serveMieruPackets(p *mieruFlow, q request) {
	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()
	var mu, writeMu sync.Mutex
	routes := map[string]net.Conn{}
	var workers sync.WaitGroup
	defer func() {
		cancel()
		mu.Lock()
		for _, c := range routes {
			c.Close()
		}
		mu.Unlock()
		workers.Wait()
	}()
	for {
		p.SetReadDeadline(time.Now().Add(r.udpTimeoutFor(q.inbound, udpTimeout)))
		packet, e := mieruReadDatagram(p)
		if e != nil {
			return
		}
		if len(packet) < 3 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
			return
		}
		reader := bytes.NewReader(packet[3:])
		address, e := readAddress(reader)
		if e != nil {
			return
		}
		payload := packet[len(packet)-reader.Len():]
		mu.Lock()
		conn := routes[address]
		full := len(routes) >= 32
		mu.Unlock()
		if conn == nil {
			if full {
				continue
			}
			request := q
			request.network = "udp"
			request.address = address
			conn, e = r.routeDial(ctx, request)
			if e != nil {
				continue
			}
			mu.Lock()
			routes[address] = conn
			mu.Unlock()
			workers.Add(1)
			go func(c net.Conn, target string) {
				defer workers.Done()
				defer c.Close()
				defer func() {
					mu.Lock()
					if routes[target] == c {
						delete(routes, target)
					}
					mu.Unlock()
				}()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				b := make([]byte, 65535)
				for {
					c.SetReadDeadline(time.Now().Add(r.udpTimeoutFor(q.inbound, udpTimeout)))
					n, e := c.Read(b)
					if e != nil {
						return
					}
					out := &mieruPacketStream{Conn: p, address: target}
					writeMu.Lock()
					_, e = out.Write(b[:n])
					writeMu.Unlock()
					if e != nil {
						return
					}
				}
			}(conn, address)
		}
		if _, e = conn.Write(payload); e != nil {
			conn.Close()
		}
	}
}

var _ net.Conn = (*mieruPacketPeer)(nil)
var _ io.ReadWriter = (*mieruPacketStream)(nil)
