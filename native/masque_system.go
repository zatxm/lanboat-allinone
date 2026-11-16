package native

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
)

// System mode exposes an endpoint to host sockets. It deliberately does not
// install a default route, enable IP forwarding or change the host's DNS.
// Core API flows retain their private stack and take precedence in rawPacket.
type masqueSystemInterface struct {
	tun       *tunTunnel
	addresses []netip.Addr
	client    *masqueIP
	server    *masqueServer
	jobs      sync.WaitGroup
	buffered  atomic.Int64
}

var masqueInterfaceID atomic.Uint32

func newMasqueSystem(r *Runtime, tag, name string, mtu int, prefixes []string) (*masqueSystemInterface, error) {
	if name != "" {
		if _, err := net.InterfaceByName(name); err == nil {
			return nil, fmt.Errorf("MASQUE interface %q already exists", name)
		}
	} else if runtime.GOOS == "linux" {
		name = "masque%d"
	} else if runtime.GOOS != "darwin" {
		name = fmt.Sprintf("masque%d", masqueInterfaceID.Add(1))
	}
	if mtu == 0 {
		mtu = 1280
	}
	t, err := openTUN(r, Inbound{Type: "tun", Tag: tag, InterfaceName: name, MTU: mtu, Address: prefixes, DNSMode: "disabled", exclusiveTUN: true})
	if err != nil {
		return nil, fmt.Errorf("MASQUE system interface: %w", err)
	}
	t.ctx, t.cancel = context.WithCancel(r.ctx)
	s := &masqueSystemInterface{tun: t}
	for _, text := range prefixes {
		prefix, _ := netip.ParsePrefix(text)
		s.addresses = append(s.addresses, prefix.Addr())
	}
	return s, nil
}

func (s *masqueSystemInterface) start() {
	s.jobs.Add(1)
	go func() {
		defer s.jobs.Done()
		buffer := make([]byte, 65575)
		for {
			n, err := s.tun.device.Read(buffer)
			if err != nil {
				return
			}
			packet, err := parseTunPacket(buffer[:n])
			if err != nil {
				continue
			}
			p := s.client
			if s.server != nil {
				p = s.server.systemPeer(packet.destination, packet.protocol)
			}
			if p != nil {
				p.enqueueSystem(s, packet.data)
			}
		}
	}()
}

func (s *masqueSystemInterface) close() { s.tun.close(); s.jobs.Wait() }

func (p *masqueIP) enqueueSystem(s *masqueSystemInterface, b []byte) {
	p.systemOutputMu.Lock()
	defer p.systemOutputMu.Unlock()
	if p.systemOutputClosed || p.flow.isClosed() {
		return
	}
	if !p.systemOutputStarted {
		p.systemQueue = make(chan []byte, 32)
		p.systemOutputStarted = true
		if !p.flow.session.goWork(func() { p.sendSystem(s) }) {
			p.systemOutputClosed = true
			return
		}
	}
	if p.systemQueued+len(b) > 128<<10 || len(p.systemQueue) == cap(p.systemQueue) {
		return
	}
	for {
		used := s.buffered.Load()
		if used+int64(len(b)) > 2<<20 {
			return
		}
		if s.buffered.CompareAndSwap(used, used+int64(len(b))) {
			break
		}
	}
	p.systemQueued += len(b)
	p.systemQueue <- slices.Clone(b)
}

func (p *masqueIP) sendSystem(s *masqueSystemInterface) {
	defer func() {
		p.systemOutputMu.Lock()
		defer p.systemOutputMu.Unlock()
		p.systemOutputClosed = true
		for {
			select {
			case b := <-p.systemQueue:
				p.systemQueued -= len(b)
				s.buffered.Add(-int64(len(b)))
			default:
				return
			}
		}
	}()
	for {
		select {
		case <-p.flow.done:
			return
		case b := <-p.systemQueue:
			_ = p.writePacket(b)
			p.systemOutputMu.Lock()
			p.systemQueued -= len(b)
			p.systemOutputMu.Unlock()
			s.buffered.Add(-int64(len(b)))
		}
	}
}

func (s *masqueServer) closeSystem() {
	s.mu.Lock()
	s.closing = true
	var flows []*masqueFlow
	for f := range s.sessions {
		flows = append(flows, f)
	}
	s.mu.Unlock()
	// Cancel slow per-session writers before tearing down the shared device.
	for _, f := range flows {
		f.Close()
	}
	s.system.close()
}

func (p *masqueIP) useSystem(s *masqueSystemInterface) {
	p.system.Store(s)
	// Reserve API source ports in the kernel too, so a simultaneous host socket
	// cannot create an identical five-tuple and steal the private stack's replies.
	p.stack.peer.reservePort = reserveSystemPort
	p.stack.peer.rawInput = func(packet tunPacket) bool {
		if s := p.system.Load(); s != nil {
			_ = s.tun.writePacket(packet.data)
		}
		return true
	}
}

func (p *masqueIP) openSystem() error {
	p.systemMu.Lock()
	defer p.systemMu.Unlock()
	if p.flow.isClosed() || p.runtime.ctx.Err() != nil {
		return net.ErrClosed
	}
	if p.system.Load() != nil {
		return nil
	}
	addresses := slices.Clone(p.addresses())
	if len(addresses) == 0 {
		return errors.New("MASQUE system interface requires an assigned address")
	}
	var prefixes []string
	for _, ip := range addresses {
		prefixes = append(prefixes, netip.PrefixFrom(ip, ip.BitLen()).String())
	}
	o := p.client.outbound
	s, err := newMasqueSystem(p.runtime, o.Tag, o.interfaceName, o.MTU, prefixes)
	if err != nil {
		return err
	}
	s.client = p
	p.system.Store(s)
	s.start()
	// Assignment can be withdrawn while the OS is creating the interface.
	if p.flow.isClosed() || !slices.Equal(addresses, p.addresses()) {
		p.system.Store(nil)
		s.close()
		return net.ErrClosed
	}
	return nil
}

func (p *masqueIP) closeSystem() {
	if p.client == nil {
		return // Server interfaces belong to the runtime, not an individual session.
	}
	p.systemMu.Lock()
	defer p.systemMu.Unlock()
	if s := p.system.Swap(nil); s != nil {
		s.close()
	}
}

// An advertised subnet cannot impersonate another session's allocated address.
func (s *masqueServer) systemSource(owner *masqueIP, source netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f := s.owners[source]; f != nil {
		return s.sessions[f] == owner
	}
	for _, prefix := range s.address {
		if source == prefix.Addr() {
			return false
		}
	}
	return true
}

func (s *masqueServer) systemPeer(destination netip.Addr, protocol byte) *masqueIP {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return nil
	}
	if f := s.owners[destination]; f != nil {
		p := s.sessions[f]
		if f.isClosed() {
			p = nil
		}
		s.mu.Unlock()
		return p
	}
	s.mu.Unlock()
	p, _ := s.peer(destination, protocol)
	return p
}
