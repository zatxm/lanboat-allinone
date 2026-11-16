package native

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type tsPeer struct {
	c              *tailscaleClient
	id             int64
	public         []byte
	key            string
	addr           net.Addr
	wg             *wgPeer
	mu             sync.Mutex
	direct         netip.AddrPort
	directAt       time.Time
	probeAt        time.Time
	probes         map[[12]byte]time.Time
	indices        [3]uint32
	pathChanged    chan struct{}
	relay          atomic.Pointer[tsRelayPath]
	relayRequested time.Time
	relayAttempt   int
	disco          string
}

func (c *tailscaleClient) peer(n tsNode) (*tsPeer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	current, ok := c.nodes[n.ID]
	if !ok || current.Key != n.Key || current.restricted() || current.Expired || c.self.lockInvalid || !current.KeyExpiry.IsZero() && time.Now().After(current.KeyExpiry) {
		return nil, errors.New("Tailscale peer was removed or expired")
	}
	if p := c.peers[n.Key]; p != nil {
		return p, nil
	}
	if len(c.peers) >= 4096 {
		return nil, errors.New("Tailscale active peer limit reached")
	}
	pub, e := tsPublic(n.Key, "nodekey")
	if e != nil {
		return nil, e
	}
	local := make([]string, 0, len(c.self.Addresses))
	for _, a := range c.self.Addresses {
		local = append(local, a.String())
	}
	allowed := []string{"0.0.0.0/0", "::/0"}
	inbound := ""
	if c.o.AdvertiseExitNode || len(c.o.AdvertiseRoutes) > 0 || c.peerAPI != nil || c.ssh != nil {
		inbound = c.o.Tag
	}
	wg, e := newWGPeer(c.r, tsPrivateBase64(c.nodeKey), base64.StdEncoding.EncodeToString(pub), "", local, allowed, inbound, 1280, 25)
	if e != nil {
		return nil, e
	}
	p := &tsPeer{c: c, id: n.ID, key: n.Key, disco: n.DiscoKey, public: pub, wg: wg, probes: map[[12]byte]time.Time{}, pathChanged: make(chan struct{}, 1)}
	p.addr = streamAddr("tailscale:" + strconv.FormatInt(n.ID, 10))
	wg.remote = p.addr
	wg.sender = func(b []byte, _ net.Addr) error { return p.send(b) }
	wg.indexChanged = p.syncIndices
	wg.stack.peer.sendIP = func(b []byte) error { return tsSendIP(wg, b) }
	wg.stack.peer.ensure = p.ensure
	wg.ownsSource = func(ip netip.Addr) bool { return c.ownsSource(n.ID, ip) }
	wg.stack.peer.acceptPacket = c.acceptsPacket
	if c.o.SystemInterface {
		wg.stack.peer.rawInput = func(packet tunPacket) bool {
			if s := c.system.Load(); s != nil {
				return s.receive(packet)
			}
			return true
		}
	}
	wg.stack.peer.tcpService = c.tcpService
	wg.stack.flows.timeout, _ = optionDuration(c.o.UDPTimeout, 5*time.Minute)
	wg.stack.peer.udpIdleTimeout = wg.stack.flows.timeout
	c.peers[n.Key] = p
	go wg.maintain()
	return p, nil
}

func (p *tsPeer) ensure(ctx context.Context) error {
	if n, ok := p.node(); ok && n.derp() == 0 && !p.c.o.ForceDERP {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		p.probe(n)
		for {
			p.mu.Lock()
			ready := p.direct.IsValid() && time.Since(p.directAt) < 30*time.Second
			if path := p.relay.Load(); path != nil {
				path.mu.Lock()
				ready = ready || path.selected.IsValid() && time.Since(path.verifiedAt) < min(path.description.idle, 30*time.Second)
				path.mu.Unlock()
			}
			p.mu.Unlock()
			if ready {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-p.c.ctx.Done():
				return net.ErrClosed
			case <-p.wg.done:
				return net.ErrClosed
			case <-p.pathChanged:
			case <-ticker.C:
				if n, ok = p.node(); !ok {
					return net.ErrClosed
				}
				if n.derp() != 0 {
					return p.wg.ensure(ctx)
				}
				p.probe(n)
			}
		}
	}
	return p.wg.ensure(ctx)
}

func tsSendIP(p *wgPeer, b []byte) error {
	// Tailscale1.104 userspace rejects fragmented IPv6 UDP before reassembly.
	// A complete WireGuard record keeps datagram semantics and checksum validation.
	if len(b) > 1280 && b[0]>>4 == 6 && b[6] == 17 {
		if len(b) > 65504 {
			return errors.New("Tailscale IPv6 UDP payload exceeds 65456 bytes")
		}
		p.writeMu.Lock()
		defer p.writeMu.Unlock()
		return p.sendEncrypted(b)
	}
	return p.sendIP(b)
}

func (p *tsPeer) node() (tsNode, bool) {
	p.c.mu.Lock()
	defer p.c.mu.Unlock()
	n, ok := p.c.nodes[p.id]
	return n, ok && n.Key == p.key
}

func (p *tsPeer) send(b []byte) error {
	if p.c.ctx.Err() != nil {
		return net.ErrClosed
	}
	p.c.mu.Lock()
	self := p.c.self
	p.c.mu.Unlock()
	if self.Expired || !self.KeyExpiry.IsZero() && time.Now().After(self.KeyExpiry) {
		return errors.New("Tailscale node key expired")
	}
	n, ok := p.node()
	if !ok {
		return errors.New("Tailscale peer has been removed")
	}
	if n.Expired || !n.KeyExpiry.IsZero() && time.Now().After(n.KeyExpiry) {
		return errors.New("Tailscale peer key expired")
	}
	if !p.c.o.ForceDERP {
		p.mu.Lock()
		direct, at := p.direct, p.directAt
		p.mu.Unlock()
		if direct.IsValid() && time.Since(at) < 30*time.Second {
			_, e := p.c.udp.WriteToUDPAddrPort(b, direct)
			if e == nil {
				return nil
			}
		}
		p.probe(n)
		if path := p.relay.Load(); path != nil && path.send(b) {
			return nil
		}
	}
	id := n.derp()
	if id == 0 {
		return errors.New("Tailscale peer has no home DERP")
	}
	d, e := p.c.derp(id)
	if e != nil {
		return e
	}
	return d.send(p.public, b)
}

func (p *tsPeer) syncIndices(current, previous, pending uint32) error {
	p.c.mu.Lock()
	defer p.c.mu.Unlock()
	if p.c.peers[p.key] != p {
		return net.ErrClosed
	}
	indices := [3]uint32{current, previous, pending}
	for _, index := range indices {
		if index != 0 && p.c.indices[index] != nil && p.c.indices[index] != p {
			return errors.New("Tailscale WireGuard index collision")
		}
	}
	for _, index := range p.indices {
		if p.c.indices[index] == p {
			delete(p.c.indices, index)
		}
	}
	p.indices = indices
	for _, index := range indices {
		if index != 0 {
			p.c.indices[index] = p
		}
	}
	return nil
}

func (p *tsPeer) probe(n tsNode) {
	p.mu.Lock()
	if time.Since(p.probeAt) < 3*time.Second {
		p.mu.Unlock()
		return
	}
	p.probeAt = time.Now()
	p.mu.Unlock()
	p.probeRelay(n)
	pub, e := tsPublic(n.DiscoKey, "discokey")
	if e != nil {
		return
	}
	box, e := tsBoxKey(p.c.discoKey, pub)
	if e != nil {
		return
	}
	for _, endpoint := range n.Endpoints {
		if !endpoint.IsValid() || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() || endpoint.Port() == 0 {
			continue
		}
		var id [12]byte
		rand.Read(id[:])
		message := append([]byte{1, 0}, id[:]...)
		message = append(message, p.c.nodeKey.PublicKey().Bytes()...)
		packet := append([]byte("TS💬"), p.c.discoKey.PublicKey().Bytes()...)
		packet = append(packet, tsBoxSeal(box, message)...)
		p.mu.Lock()
		for k, t := range p.probes {
			if time.Since(t) > 10*time.Second {
				delete(p.probes, k)
			}
		}
		p.probes[id] = time.Now()
		p.mu.Unlock()
		_, _ = p.c.udp.WriteToUDPAddrPort(packet, endpoint)
	}
}

func (c *tailscaleClient) readUDP() {
	buffer := make([]byte, 65535)
	for {
		n, remote, e := c.udp.ReadFromUDPAddrPort(buffer)
		if e != nil {
			return
		}
		if c.o.ForceDERP {
			continue
		}
		b := buffer[:n]
		remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
		if c.receiveRelay(b, remote) {
			continue
		}
		if c.handleSTUN(b, remote) {
			continue
		}
		if bytes.HasPrefix(b, []byte("TS💬")) {
			c.receiveDisco(0, b, remote)
			continue
		}
		c.receiveWG(b, remote)
	}
}

func (c *tailscaleClient) receiveWG(b []byte, remote netip.AddrPort) {
	if len(b) < 8 {
		return
	}
	kind := binary.LittleEndian.Uint32(b)
	if kind == 1 {
		pub, _, _, _, e := wgReadInitiationKind(c.nodeKey, b, 1)
		if e != nil {
			return
		}
		c.mu.Lock()
		node := c.nodes[c.nodeKeys[[32]byte(pub)]]
		c.mu.Unlock()
		if node.ID == 0 {
			return
		}
		p, e := c.peer(node)
		if e != nil {
			return
		}
		p.wg.handle(b, p.addr)
		return
	}
	offset := 4
	if kind == 2 {
		if len(b) < 12 {
			return
		}
		offset = 8
	}
	c.mu.Lock()
	p := c.indices[binary.LittleEndian.Uint32(b[offset:])]
	c.mu.Unlock()
	if p != nil {
		p.wg.handle(b, p.addr)
	}
}

func (c *tailscaleClient) receiveDERP(region int, public, b []byte) {
	if bytes.HasPrefix(b, []byte("TS💬")) {
		c.receiveDisco(region, b, netip.AddrPort{})
		return
	}
	c.mu.Lock()
	node := c.nodes[c.nodeKeys[[32]byte(public)]]
	c.mu.Unlock()
	if node.ID == 0 {
		return
	}
	p, e := c.peer(node)
	if e != nil {
		return
	}
	p.wg.handle(b, p.addr)
}

func (c *tailscaleClient) receiveDisco(region int, b []byte, remote netip.AddrPort) {
	c.receiveDiscoVia(region, b, remote, nil)
}
func (c *tailscaleClient) receiveDiscoVia(region int, b []byte, remote netip.AddrPort, path *tsRelayPath) {
	if len(b) < 78 {
		return
	}
	c.mu.Lock()
	n := c.nodes[c.discoKeys[[32]byte(b[6:38])]]
	c.mu.Unlock()
	if n.ID == 0 {
		return
	}
	if path != nil && (path.peer.id != n.ID || !bytes.Equal(b[6:38], path.peerDisco[:])) {
		return
	}
	box, e := tsBoxKey(c.discoKey, b[6:38])
	if e != nil {
		return
	}
	m, e := tsBoxOpen(box, b[38:])
	if e != nil || len(m) < 2 || m[1] != 0 {
		return
	}
	if m[0] == 8 && region != 0 && c.relay != nil {
		c.relay.request(n, m)
		return
	}
	if region != 0 && (m[0] == 7 || m[0] == 9) {
		c.receiveRelayDescription(n, m)
		return
	}
	p, e := c.peer(n)
	if e != nil {
		return
	}
	switch m[0] {
	case 1:
		if len(m) < 14 || !remote.IsValid() || c.o.ForceDERP {
			return
		}
		if len(m) >= 46 && !bytes.Equal(m[14:46], p.public) {
			return
		}
		pong := append([]byte{2, 0}, m[2:14]...)
		ip := remote.Addr().As16()
		pong = append(pong, ip[:]...)
		pong = binary.BigEndian.AppendUint16(pong, remote.Port())
		packet := append([]byte("TS💬"), c.discoKey.PublicKey().Bytes()...)
		packet = append(packet, tsBoxSeal(box, pong)...)
		if path != nil {
			packet = tsGeneve(path.description.vni, false, packet)
		}
		_, _ = c.udp.WriteToUDPAddrPort(packet, remote)
		if path == nil {
			p.probe(n)
		}
	case 2:
		if len(m) < 32 || !remote.IsValid() || c.o.ForceDERP {
			return
		}
		var id [12]byte
		copy(id[:], m[2:14])
		if path != nil {
			path.mu.Lock()
			probe, ok := path.probes[id]
			delete(path.probes, id)
			if ok && probe.endpoint == remote && time.Since(probe.at) < 10*time.Second {
				rtt := time.Since(probe.at)
				if remote == path.selected || !path.selected.IsValid() || time.Since(path.verifiedAt) >= min(path.description.idle, 30*time.Second) || rtt < path.rtt {
					path.selected = remote
					path.verifiedAt = time.Now()
					path.rtt = rtt
					signalQUIC(p.pathChanged)
				}
			}
			path.mu.Unlock()
			return
		}
		p.mu.Lock()
		at, ok := p.probes[id]
		delete(p.probes, id)
		if ok && time.Since(at) < 10*time.Second {
			p.direct = remote
			p.directAt = time.Now()
			select {
			case p.pathChanged <- struct{}{}:
			default:
			}
		}
		p.mu.Unlock()
	case 3:
		if region == 0 || c.o.ForceDERP {
			return
		}
		p.probe(n)
	}
}

func (c *tailscaleClient) maintain() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case now := <-ticker.C:
			c.expirePeers(now)
			if c.o.SystemInterface {
				if e := c.syncSystemInterface(); e != nil {
					c.fail(e)
					c.cancel()
					return
				}
			}
		}
		c.mu.Lock()
		c.pruneRelayPathsLocked()
		home := c.home
		c.mu.Unlock()
		if home != 0 {
			_, _ = c.derp(home)
		}
		if !c.o.ForceDERP {
			c.probeSTUN()
		}
		select {
		case <-c.stunChanged:
			_ = c.updateEndpoints()
		default:
		}
	}
}

func (c *tailscaleClient) expirePeers(now time.Time) {
	c.mu.Lock()
	var expired []*wgPeer
	selfExpired := c.self.Expired || c.self.lockInvalid || !c.self.KeyExpiry.IsZero() && !now.Before(c.self.KeyExpiry)
	for key, p := range c.peers {
		n, ok := c.nodes[p.id]
		if selfExpired || !ok || n.Expired || !n.KeyExpiry.IsZero() && !now.Before(n.KeyExpiry) {
			delete(c.peers, key)
			for _, index := range p.indices {
				delete(c.indices, index)
			}
			expired = append(expired, p.wg)
		}
	}
	c.mu.Unlock()
	for _, p := range expired {
		p.close()
	}
}

// A transaction-bound STUN response only updates our own public endpoint.
func (c *tailscaleClient) probeSTUN() {
	if c.o.ForceDERP || c.ctx.Err() != nil {
		return
	}
	c.mu.Lock()
	var nodes []tsDERPNode
	for _, r := range c.regions {
		for _, n := range r.Nodes {
			if n.STUNPort >= 0 {
				nodes = append(nodes, n)
				break
			}
		}
	}
	c.mu.Unlock()
	for _, n := range nodes[:min(len(nodes), 3)] {
		host := n.HostName
		if net.ParseIP(n.IPv4) != nil {
			host = n.IPv4
		}
		port := n.STUNPort
		if port == 0 {
			port = 3478
		}
		if port < 1 || port > 65535 {
			continue
		}
		ctx, cancel := context.WithTimeout(c.ctx, time.Second)
		ips, e := c.r.directIPs(ctx, host)
		cancel()
		if e != nil || len(ips) == 0 {
			continue
		}
		var id [12]byte
		rand.Read(id[:])
		b := []byte{0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42}
		b = append(b, id[:]...)
		c.mu.Lock()
		for k, t := range c.stun {
			if time.Since(t) > 30*time.Second {
				delete(c.stun, k)
			}
		}
		c.stun[id] = time.Now()
		c.mu.Unlock()
		_, _ = c.udp.WriteToUDPAddrPort(b, netip.AddrPortFrom(ips[0], uint16(port)))
	}
}

func (c *tailscaleClient) handleSTUN(b []byte, _ netip.AddrPort) bool {
	if len(b) < 20 || binary.BigEndian.Uint32(b[4:8]) != 0x2112a442 {
		return false
	}
	if binary.BigEndian.Uint16(b) != 0x0101 {
		return true
	}
	var id [12]byte
	copy(id[:], b[8:20])
	c.mu.Lock()
	at, ok := c.stun[id]
	delete(c.stun, id)
	c.mu.Unlock()
	if !ok || time.Since(at) > 30*time.Second || int(binary.BigEndian.Uint16(b[2:4])) != len(b)-20 {
		return true
	}
	for pos := 20; pos+4 <= len(b); {
		typ, n := binary.BigEndian.Uint16(b[pos:]), int(binary.BigEndian.Uint16(b[pos+2:]))
		pos += 4
		if pos+n > len(b) {
			return true
		}
		v := b[pos : pos+n]
		pos += (n + 3) &^ 3
		if typ != 0x20 || n < 8 {
			continue
		}
		port := binary.BigEndian.Uint16(v[2:4]) ^ 0x2112
		size := 4
		if v[1] == 2 {
			size = 16
		} else if v[1] != 1 {
			continue
		}
		if n != size+4 {
			continue
		}
		mask := append([]byte{0x21, 0x12, 0xa4, 0x42}, id[:]...)
		ipb := make([]byte, size)
		for i := range size {
			ipb[i] = v[i+4] ^ mask[i]
		}
		ip, ok := netip.AddrFromSlice(ipb)
		if !ok || !ip.IsGlobalUnicast() || port == 0 {
			continue
		}
		endpoint := netip.AddrPortFrom(ip.Unmap(), port)
		c.mu.Lock()
		changed := !slices.Contains(c.endpoints, endpoint)
		if changed {
			if len(c.endpoints) > 64 {
				c.endpoints = c.endpoints[:64]
			}
			c.endpoints = append(c.endpoints, endpoint)
		}
		c.mu.Unlock()
		if changed {
			select {
			case c.stunChanged <- struct{}{}:
			default:
			}
		}
	}
	return true
}

func tsVerifyDERPPin(cs tls.ConnectionState, pin string) error {
	want, e := hex.DecodeString(pin)
	if e != nil || len(want) != 32 || len(cs.PeerCertificates) == 0 {
		return errors.New("invalid DERP certificate pin")
	}
	got := sha256.Sum256(cs.PeerCertificates[0].Raw)
	if subtle.ConstantTimeCompare(want, got[:]) != 1 {
		return errors.New("DERP certificate pin mismatch")
	}
	return nil
}
