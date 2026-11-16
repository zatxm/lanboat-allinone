package native

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

type trustICMPMux struct {
	conn        net.Conn
	mu, writeMu sync.Mutex
	next        uint32
	pending     map[uint32]chan [22]byte
	done        chan struct{}
	once        sync.Once
}

func (m *trustICMPMux) close() { m.once.Do(func() { close(m.done); m.conn.Close() }) }
func (m *trustICMPMux) receive() {
	defer m.close()
	for {
		var b [22]byte
		m.conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		if _, e := io.ReadFull(m.conn, b[:]); e != nil {
			return
		}
		id := uint32(binary.BigEndian.Uint16(b[:2]))<<16 | uint32(binary.BigEndian.Uint16(b[20:]))
		m.mu.Lock()
		reply := m.pending[id]
		m.mu.Unlock()
		if reply != nil {
			select {
			case reply <- b:
			default:
			}
		}
	}
}
func (c *trustClient) exchangeICMP(ctx context.Context, destination netip.Addr, request []byte, ttl byte) (icmpResponse, error) {
	if len(request) < 8 || len(request) > 65515 || ttl == 0 || !destination.IsValid() || destination.Unmap().String() == "0.0.0.1" {
		return icmpResponse{}, errors.New("invalid TrustTunnel ICMP echo")
	}
	c.muxMu.Lock()
	m := c.icmp
	if m != nil {
		select {
		case <-m.done:
			m = nil
		default:
		}
	}
	if m == nil {
		conn, e := c.connect(ctx, "_icmp")
		if e != nil {
			c.muxMu.Unlock()
			return icmpResponse{}, e
		}
		m = &trustICMPMux{conn: conn, pending: map[uint32]chan [22]byte{}, done: make(chan struct{})}
		c.icmp = m
		go m.receive()
	}
	c.muxMu.Unlock()
	m.mu.Lock()
	if len(m.pending) >= 64 || m.next == ^uint32(0) {
		m.mu.Unlock()
		return icmpResponse{}, errors.New("TrustTunnel ICMP capacity reached")
	}
	m.next++
	id := m.next
	reply := make(chan [22]byte, 1)
	m.pending[id] = reply
	m.mu.Unlock()
	defer func() { m.mu.Lock(); delete(m.pending, id); m.mu.Unlock() }()
	var b [23]byte
	binary.BigEndian.PutUint16(b[:2], uint16(id>>16))
	trustPutIP(b[2:18], destination)
	binary.BigEndian.PutUint16(b[18:20], uint16(id))
	b[20] = ttl
	binary.BigEndian.PutUint16(b[21:], uint16(len(request)-8))
	m.writeMu.Lock()
	d := time.Now().Add(handshakeTimeout)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(d) {
		d = deadline
	}
	m.conn.SetWriteDeadline(d)
	e := writeAll(m.conn, b[:])
	m.writeMu.Unlock()
	if e != nil {
		m.close()
		return icmpResponse{}, e
	}
	select {
	case <-ctx.Done():
		return icmpResponse{}, ctx.Err()
	case <-m.done:
		return icmpResponse{}, net.ErrClosed
	case b := <-reply:
		source := trustIP(b[2:18])
		kind, code := b[18], b[19]
		echo := byte(0)
		if destination.Is6() {
			echo = 129
		}
		if source.Is4() != destination.Is4() || kind != echo && !icmpError(kind, destination.Is6()) || kind == echo && (code != 0 || source != destination) {
			return icmpResponse{}, errors.New("invalid TrustTunnel ICMP reply")
		}
		// The wire carries only echo length. Restore this caller's payload and ID.
		data := append([]byte{}, request...)
		data[0], data[1], data[2], data[3] = kind, code, 0, 0
		if icmpError(kind, destination.Is6()) {
			data = data[:8]
			clear(data[4:8])
		}
		if destination.Is4() {
			binary.BigEndian.PutUint16(data[2:], checksum(data, 0))
		}
		return icmpResponse{source: source, data: data}, nil
	}
}
func (r *Runtime) serveTrustICMP(conn net.Conn, q request) error {
	ctx, cancel := context.WithCancel(r.ctx)
	slots := make(chan struct{}, 32)
	var workers sync.WaitGroup
	defer workers.Wait()
	defer cancel()
	var writeMu sync.Mutex
	for {
		var b [23]byte
		conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		if _, e := io.ReadFull(conn, b[:]); e != nil {
			return e
		}
		destination := trustIP(b[2:18])
		size := int(binary.BigEndian.Uint16(b[21:]))
		if b[20] == 0 || size > 65507 || destination.IsUnspecified() || destination.IsMulticast() {
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			child, stop := context.WithTimeout(ctx, 7*time.Second)
			defer stop()
			request := make([]byte, 8+size)
			request[0] = 8
			if destination.Is6() {
				request[0] = 128
			}
			copy(request[4:6], b[:2])
			copy(request[6:8], b[18:20])
			reply := func(source netip.Addr, kind, code byte) {
				var out [22]byte
				copy(out[:2], b[:2])
				trustPutIP(out[2:18], source)
				out[18], out[19] = kind, code
				copy(out[20:], b[18:20])
				writeMu.Lock()
				defer writeMu.Unlock()
				conn.SetWriteDeadline(time.Now().Add(handshakeTimeout))
				_ = writeAll(conn, out[:])
			}
			query := q
			query.network = "icmp"
			query.address = net.JoinHostPort(destination.String(), "0")
			query.metadata.Protocol = "icmp"
			query, tag, e := r.routeTarget(child, query)
			if errors.Is(e, errICMPReply) {
				kind := byte(0)
				if destination.Is6() {
					kind = 129
				}
				reply(destination, kind, 0)
				return
			}
			if errors.Is(e, ErrRejected) {
				kind, code := byte(3), byte(1)
				if destination.Is6() {
					kind, code = 1, 3
				}
				reply(destination, kind, code)
				return
			}

			if e != nil {
				return
			}
			for range 32 {
				g := r.groups[tag]
				if g == nil {
					break
				}
				tag = *g.selected.Load()
			}
			host, _, _ := net.SplitHostPort(query.address)
			dest, e := netip.ParseAddr(host)
			if e != nil || dest.Is4() != destination.Is4() {
				return
			}
			var response icmpResponse
			switch r.outbounds[tag].Type {
			case "direct":
				response, e = r.directICMPExchange(child, dest, request, int(b[20]), r.outbounds[tag].DialOptions.routeNetwork(query.networkContext(child)))
			case "wireguard":
				var peer *wgPeer
				peer, e = r.wireGuardSession(child, tag, dest)
				if e == nil {
					response, e = peer.stack.exchangeICMP(child, dest, request, b[20])
				}
			case "trusttunnel":
				response, e = r.trustClients[tag].exchangeICMP(child, dest, request, b[20])
			default:
				return
			}
			if e != nil || len(response.data) < 8 {
				return
			}
			reply(response.source, response.data[0], response.data[1])
		}()
	}
}
