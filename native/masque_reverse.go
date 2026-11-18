package native

import (
	"context"
	"encoding/binary"
	"errors"
	"math/bits"
	"net"
	"net/netip"
	"sync"
	"time"
)

var errMasquePaused = errors.New("MASQUE endpoint disconnected on demand")

type masqueServer struct {
	nat       *masqueNAT
	system    *masqueSystemInterface
	closing   bool
	mu        sync.Mutex
	address   []netip.Prefix
	sessions  map[*masqueFlow]*masqueIP
	allocated map[*masqueFlow][]netip.Addr
	owners    map[netip.Addr]*masqueFlow
}

func newMasqueServer(in Inbound) *masqueServer {
	s := &masqueServer{sessions: map[*masqueFlow]*masqueIP{}, allocated: map[*masqueFlow][]netip.Addr{}, owners: map[netip.Addr]*masqueFlow{}}
	for _, text := range in.serverAddress {
		p, _ := netip.ParsePrefix(text)
		s.address = append(s.address, p)
	}
	return s
}

func (s *masqueServer) allocate(f *masqueFlow) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return nil, net.ErrClosed
	}
	if len(s.allocated) >= 256 {
		return nil, errors.New("MASQUE endpoint session capacity reached")
	}
	var addresses []netip.Addr
	var assigned []string
	for _, prefix := range s.address {
		count := len(addresses)
		last := prefixLast(prefix)
		a := prefix.Addr().Next()
		for range 258 {
			if !a.IsValid() || !prefix.Contains(a) {
				a = prefix.Masked().Addr()
			}
			reserved := prefix.Bits() < prefix.Addr().BitLen()-1 && (a == prefix.Masked().Addr() || a.Is4() && a == last)
			if a != prefix.Addr() && !a.IsUnspecified() && !reserved && s.owners[a] == nil {
				addresses = append(addresses, a)
				assigned = append(assigned, netip.PrefixFrom(a, a.BitLen()).String())
				break
			}
			a = a.Next()
		}
		if len(addresses) == count {
			return nil, errors.New("MASQUE endpoint address pool exhausted")
		}
	}
	s.allocated[f] = addresses
	for _, address := range addresses {
		s.owners[address] = f
	}
	return assigned, nil
}

func (s *masqueServer) attach(f *masqueFlow, p *masqueIP) {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		f.Close()
		return
	}
	s.sessions[f] = p
	s.mu.Unlock()
}
func (s *masqueServer) remove(f *masqueFlow) {
	s.mu.Lock()
	delete(s.sessions, f)
	for _, address := range s.allocated[f] {
		delete(s.owners, address)
	}
	delete(s.allocated, f)
	s.mu.Unlock()
}

func masqueRouteWidth(route masqueRoute) (uint64, uint64) {
	if route.first.Is4() {
		a, b := route.first.As4(), route.last.As4()
		return 0, uint64(binary.BigEndian.Uint32(b[:]) - binary.BigEndian.Uint32(a[:]))
	}
	a, b := route.first.As16(), route.last.As16()
	lo, borrow := bits.Sub64(binary.BigEndian.Uint64(b[8:]), binary.BigEndian.Uint64(a[8:]), 0)
	hi, _ := bits.Sub64(binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(a[:8]), borrow)
	return hi, lo
}

func (s *masqueServer) peer(destination netip.Addr, protocol byte) (*masqueIP, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var chosen *masqueIP
	var high, low uint64
	ambiguous := false
	for f, p := range s.sessions {
		if f.isClosed() {
			continue
		}
		p.mu.Lock()
		for _, route := range p.routes {
			if !masqueRouteContains(route, destination, protocol) {
				continue
			}
			hi, lo := masqueRouteWidth(route)
			if chosen == nil || hi < high || hi == high && lo < low {
				chosen, high, low, ambiguous = p, hi, lo, false
			} else if hi == high && lo == low && chosen != p {
				ambiguous = true
			}
		}
		p.mu.Unlock()
	}
	if chosen == nil || ambiguous {
		return nil, ErrRejected
	}
	return chosen, nil
}

func (s *masqueServer) dial(ctx context.Context, r *Runtime, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := r.resolver.lookupReal(ctx, host)
	if err != nil {
		return nil, err
	}
	protocol := byte(6)
	if network == "udp" {
		protocol = 17
	}
	for _, ip := range ips {
		p, e := s.peer(ip, protocol)
		if e != nil {
			continue
		}
		conn, e := p.stack.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if e != nil {
			return nil, e
		}
		return r.own(conn)
	}
	return nil, ErrRejected
}

func (c *masqueClient) disconnect() {
	c.mu.Lock()
	c.paused = true
	m := c.session
	c.session = nil
	c.ip.Store(nil)
	c.mu.Unlock()
	if m != nil {
		m.close()
		m.workers.Wait()
	}
}

func (c *masqueClient) maintain() {
	delay := time.Second
	for c.runtime.ctx.Err() == nil {
		ctx, cancel := context.WithTimeout(c.runtime.ctx, handshakeTimeout)
		p, err := c.ipSessionMode(ctx, true)
		cancel()
		if err == nil {
			delay = time.Second
			select {
			case <-p.flow.done:
			case <-c.wake:
			case <-c.runtime.ctx.Done():
				return
			}
			continue
		}
		if !errors.Is(err, errMasquePaused) && c.outbound.system && c.runtime.ctx.Err() == nil {
			logWarn(c.runtime.logger, err, c.runtime.outboundLabel(c.outbound.Tag), ": connect system interface")
		}
		var retry <-chan time.Time
		var timer *time.Timer
		if !errors.Is(err, errMasquePaused) {
			timer = time.NewTimer(delay)
			retry = timer.C
			delay = min(delay*2, 30*time.Second)
		}
		select {
		case <-retry:
		case <-c.wake:
		case <-c.runtime.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func serverNAT(s *masqueServer) *masqueNAT {
	if s == nil {
		return nil
	}
	return s.nat
}
