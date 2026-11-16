package native

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"
)

type tsRelayDescription struct {
	server     [32]byte
	clients    [2][32]byte
	lamport    uint64
	vni        uint32
	bind, idle time.Duration
	endpoints  []netip.AddrPort
}

func tsParseRelayDescription(b []byte) (tsRelayDescription, error) {
	var d tsRelayDescription
	if len(b) < 142 || (len(b)-124)%18 != 0 || len(b) > 124+18*8 {
		return d, errors.New("invalid relay description length")
	}
	copy(d.server[:], b[:32])
	copy(d.clients[0][:], b[32:64])
	copy(d.clients[1][:], b[64:96])
	d.lamport = binary.BigEndian.Uint64(b[96:])
	d.vni = binary.BigEndian.Uint32(b[104:])
	d.bind = time.Duration(binary.BigEndian.Uint64(b[108:]))
	d.idle = time.Duration(binary.BigEndian.Uint64(b[116:]))
	if d.server == [32]byte{} || d.clients[0] == [32]byte{} || d.clients[1] == [32]byte{} || d.clients[0] == d.clients[1] || d.lamport == 0 || d.vni == 0 || d.vni > 0xffffff || d.bind <= 0 || d.bind > 24*time.Hour || d.idle <= 0 || d.idle > 24*time.Hour {
		return d, errors.New("invalid relay description")
	}
	for b = b[124:]; len(b) > 0; b = b[18:] {
		ip := netip.AddrFrom16([16]byte(b[:16])).Unmap()
		port := binary.BigEndian.Uint16(b[16:])
		if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || port == 0 {
			return d, errors.New("invalid relay endpoint")
		}
		ep := netip.AddrPortFrom(ip, port)
		if !slices.Contains(d.endpoints, ep) {
			d.endpoints = append(d.endpoints, ep)
		}
	}
	return d, nil
}
func (d tsRelayDescription) marshal() []byte {
	b := append([]byte(nil), d.server[:]...)
	b = append(b, d.clients[0][:]...)
	b = append(b, d.clients[1][:]...)
	b = binary.BigEndian.AppendUint64(b, d.lamport)
	b = binary.BigEndian.AppendUint32(b, d.vni)
	b = binary.BigEndian.AppendUint64(b, uint64(d.bind))
	b = binary.BigEndian.AppendUint64(b, uint64(d.idle))
	for _, ep := range d.endpoints {
		ip := ep.Addr().As16()
		b = append(b, ip[:]...)
		b = binary.BigEndian.AppendUint16(b, ep.Port())
	}
	return b
}

type tsRelayPathKey struct {
	endpoint netip.AddrPort
	vni      uint32
}
type tsRelayRequest struct {
	peer        *tsPeer
	serverID    int64
	serverKey   string
	serverDisco string
	sent        time.Time
}
type tsRelayCandidate struct {
	endpoint   netip.AddrPort
	generation uint32
	answered   bool
	pingAt     time.Time
}
type tsRelayProbe struct {
	endpoint netip.AddrPort
	at       time.Time
}
type tsRelayPath struct {
	peer                           *tsPeer
	description                    tsRelayDescription
	peerDisco                      [32]byte
	serverID                       int64
	serverKey                      string
	serverDisco                    string
	mu                             sync.Mutex
	candidates                     []tsRelayCandidate
	probes                         map[[12]byte]tsRelayProbe
	selected                       netip.AddrPort
	verifiedAt, probeAt, bindUntil time.Time
	rtt                            time.Duration
}

func tsRandomID() uint32 {
	var b [4]byte
	for {
		rand.Read(b[:])
		if n := binary.BigEndian.Uint32(b[:]); n != 0 {
			return n
		}
	}
}
func (c *tailscaleClient) relayEnabledLocked() bool {
	_, disabled := c.self.CapMap["disable-relay-client"]
	return !disabled && !c.o.ForceDERP && !c.self.Expired && (c.self.KeyExpiry.IsZero() || time.Now().Before(c.self.KeyExpiry))
}
func (c *tailscaleClient) relayServerAllowedLocked(server tsNode) bool {
	if server.ID == 0 || server.Hostinfo == nil || !server.Hostinfo.PeerRelay || server.Expired || server.restricted() || !server.KeyExpiry.IsZero() && time.Now().After(server.KeyExpiry) {
		return false
	}
	for _, a := range c.self.Addresses {
		if c.peerCapabilityLocked(a.Addr(), server.Addresses, "tailscale.com/cap/relay-target") {
			return true
		}
	}
	return false
}
func (p *tsPeer) probeRelay(n tsNode) {
	if path := p.relay.Load(); path != nil {
		path.probe()
	}
	c := p.c
	c.mu.Lock()
	if !c.relayEnabledLocked() || c.peers[p.key] != p {
		c.mu.Unlock()
		return
	}
	if path := p.relay.Load(); path != nil {
		path.mu.Lock()
		active := path.selected.IsValid() && time.Since(path.verifiedAt) < min(path.description.idle, 30*time.Second) || time.Now().Before(path.bindUntil)
		path.mu.Unlock()
		if active {
			c.mu.Unlock()
			return
		}
	}
	if time.Since(p.relayRequested) < 10*time.Second {
		c.mu.Unlock()
		return
	}
	p.relayRequested = time.Now()
	var servers []int64
	for id, server := range c.nodes {
		if c.relayServerAllowedLocked(server) {
			servers = append(servers, id)
		}
	}
	if len(servers) == 0 {
		c.mu.Unlock()
		return
	}
	slices.Sort(servers)
	server := c.nodes[servers[p.relayAttempt%len(servers)]]
	p.relayAttempt++
	remote, e := tsPublic(n.DiscoKey, "discokey")
	if e != nil {
		c.mu.Unlock()
		return
	}
	if c.relayRequests == nil {
		c.relayRequests = map[uint32]tsRelayRequest{}
	}
	for id, request := range c.relayRequests {
		if time.Since(request.sent) > 30*time.Second {
			delete(c.relayRequests, id)
		}
	}
	if len(c.relayRequests) >= 4096 {
		c.mu.Unlock()
		return
	}
	generation := tsRandomID()
	for c.relayRequests[generation].peer != nil {
		generation = tsRandomID()
	}
	c.relayRequests[generation] = tsRelayRequest{peer: p, serverID: server.ID, serverKey: server.Key, serverDisco: server.DiscoKey, sent: time.Now()}
	c.mu.Unlock()
	m := append([]byte{8, 0}, c.discoKey.PublicKey().Bytes()...)
	m = append(m, remote...)
	m = binary.BigEndian.AppendUint32(m, generation)
	c.spawn(func() { _ = c.sendDisco(server, m) })
}
func (c *tailscaleClient) receiveRelayDescription(sender tsNode, m []byte) {
	if c.o.ForceDERP || len(m) < 2 || m[1] != 0 {
		return
	}
	var p *tsPeer
	var data []byte
	serverID := int64(0)
	serverKey := ""
	serverDisco := ""
	if m[0] == 9 {
		if len(m) < 6 {
			return
		}
		gen := binary.BigEndian.Uint32(m[2:])
		c.mu.Lock()
		request, ok := c.relayRequests[gen]
		current := c.nodes[sender.ID]
		if !ok || request.serverID != sender.ID || request.serverKey != current.Key || request.serverDisco != current.DiscoKey || time.Since(request.sent) > 30*time.Second || !c.relayEnabledLocked() || !c.relayServerAllowedLocked(current) {
			c.mu.Unlock()
			return
		}
		delete(c.relayRequests, gen)
		c.mu.Unlock()
		p = request.peer
		data = m[6:]
		serverID = sender.ID
		serverKey = sender.Key
		serverDisco = sender.DiscoKey
	} else if m[0] == 7 {
		var e error
		p, e = c.peer(sender)
		if e != nil {
			return
		}
		data = m[2:]
	} else {
		return
	}
	d, e := tsParseRelayDescription(data)
	if e != nil {
		return
	}
	node, ok := p.node()
	if !ok {
		return
	}
	remote, e := tsPublic(node.DiscoKey, "discokey")
	if e != nil {
		return
	}
	self := [32]byte(c.discoKey.PublicKey().Bytes())
	if !(d.clients[0] == self && d.clients[1] == [32]byte(remote) || d.clients[1] == self && d.clients[0] == [32]byte(remote)) {
		return
	}
	path := &tsRelayPath{peer: p, description: d, peerDisco: [32]byte(remote), serverID: serverID, serverKey: serverKey, serverDisco: serverDisco, probes: map[[12]byte]tsRelayProbe{}, bindUntil: time.Now().Add(d.bind)}
	for _, ep := range d.endpoints {
		path.candidates = append(path.candidates, tsRelayCandidate{endpoint: ep, generation: tsRandomID()})
	}
	c.mu.Lock()
	if !c.relayEnabledLocked() || c.peers[p.key] != p {
		c.mu.Unlock()
		return
	}
	if old := p.relay.Load(); old != nil {
		if old.description.server == d.server && old.description.lamport > d.lamport {
			c.mu.Unlock()
			return
		}
		if old.description.server == d.server && old.description.lamport == d.lamport {
			same := bytes.Equal(old.description.marshal(), d.marshal())
			c.mu.Unlock()
			if same {
				old.probe()
			}
			return
		}
		c.removeRelayPathLocked(old)
	}
	if c.relayPaths == nil {
		c.relayPaths = map[tsRelayPathKey]*tsRelayPath{}
	}
	if len(c.relayPaths)+len(d.endpoints) > 32768 {
		c.mu.Unlock()
		return
	}
	for _, ep := range d.endpoints {
		key := tsRelayPathKey{ep, d.vni}
		if other := c.relayPaths[key]; other != nil {
			c.mu.Unlock()
			return
		}
	}
	for _, ep := range d.endpoints {
		c.relayPaths[tsRelayPathKey{ep, d.vni}] = path
	}
	p.relay.Store(path)
	c.mu.Unlock()
	path.probe()
	if m[0] == 9 {
		message := append([]byte{7, 0}, d.marshal()...)
		c.spawn(func() { _ = c.sendDisco(node, message) })
	}
}
func (c *tailscaleClient) removeRelayPathLocked(path *tsRelayPath) {
	for _, ep := range path.description.endpoints {
		key := tsRelayPathKey{ep, path.description.vni}
		if c.relayPaths[key] == path {
			delete(c.relayPaths, key)
		}
	}
	path.peer.relay.CompareAndSwap(path, nil)
}
func (c *tailscaleClient) pruneRelayPathsLocked() {
	for _, path := range c.relayPaths {
		n, ok := c.nodes[path.peer.id]
		remote, e := tsPublic(n.DiscoKey, "discokey")
		valid := c.relayEnabledLocked() && ok && e == nil && [32]byte(remote) == path.peerDisco && c.peers[path.peer.key] == path.peer
		if valid && path.serverID != 0 {
			server, exists := c.nodes[path.serverID]
			valid = exists && server.Key == path.serverKey && server.DiscoKey == path.serverDisco && c.relayServerAllowedLocked(server)
		}
		if !valid {
			c.removeRelayPathLocked(path)
		}
	}
	for gen, request := range c.relayRequests {
		server := c.nodes[request.serverID]
		if !c.relayEnabledLocked() || c.peers[request.peer.key] != request.peer || time.Since(request.sent) > 30*time.Second || server.Key != request.serverKey || server.DiscoKey != request.serverDisco || !c.relayServerAllowedLocked(server) {
			delete(c.relayRequests, gen)
		}
	}
}
func (path *tsRelayPath) writeControl(ep netip.AddrPort, m []byte) {
	c := path.peer.c
	box, e := tsBoxKey(c.discoKey, path.description.server[:])
	if e != nil {
		return
	}
	b := append([]byte("TS💬"), c.discoKey.PublicKey().Bytes()...)
	b = append(b, tsBoxSeal(box, m)...)
	_, _ = c.udp.WriteToUDPAddrPort(tsGeneve(path.description.vni, true, b), ep)
}
func (path *tsRelayPath) probe() {
	path.mu.Lock()
	if time.Since(path.probeAt) < 3*time.Second {
		path.mu.Unlock()
		return
	}
	path.probeAt = time.Now()
	verified := path.selected.IsValid() && time.Since(path.verifiedAt) < min(path.description.idle, 30*time.Second)
	candidates := slices.Clone(path.candidates)
	for id, probe := range path.probes {
		if time.Since(probe.at) > 10*time.Second {
			delete(path.probes, id)
		}
	}
	path.mu.Unlock()
	for _, candidate := range candidates {
		if !candidate.answered || !verified {
			message := binary.BigEndian.AppendUint32([]byte{4, 0}, path.description.vni)
			message = binary.BigEndian.AppendUint32(message, candidate.generation)
			message = append(message, path.peerDisco[:]...)
			message = append(message, make([]byte, 32)...)
			path.writeControl(candidate.endpoint, message)
		}
		if candidate.answered {
			path.ping(candidate.endpoint)
		}
	}
}
func (path *tsRelayPath) ping(ep netip.AddrPort) {
	c := path.peer.c
	var id [12]byte
	rand.Read(id[:])
	path.mu.Lock()
	allowed := false
	for i := range path.candidates {
		candidate := &path.candidates[i]
		if candidate.endpoint == ep && time.Since(candidate.pingAt) >= time.Second {
			candidate.pingAt = time.Now()
			allowed = true
			break
		}
	}
	if !allowed || len(path.probes) >= 128 {
		path.mu.Unlock()
		return
	}
	path.probes[id] = tsRelayProbe{ep, time.Now()}
	path.mu.Unlock()
	m := append([]byte{1, 0}, id[:]...)
	m = append(m, c.nodeKey.PublicKey().Bytes()...)
	box, e := tsBoxKey(c.discoKey, path.peerDisco[:])
	if e != nil {
		return
	}
	wire := append([]byte("TS💬"), c.discoKey.PublicKey().Bytes()...)
	wire = append(wire, tsBoxSeal(box, m)...)
	_, _ = c.udp.WriteToUDPAddrPort(tsGeneve(path.description.vni, false, wire), ep)
}
func (path *tsRelayPath) send(b []byte) bool {
	path.mu.Lock()
	endpoint, at := path.selected, path.verifiedAt
	path.mu.Unlock()
	if !endpoint.IsValid() || time.Since(at) > min(path.description.idle, 30*time.Second) {
		return false
	}
	_, e := path.peer.c.udp.WriteToUDPAddrPort(tsGeneve(path.description.vni, false, b), endpoint)
	return e == nil
}
func (c *tailscaleClient) receiveRelay(b []byte, remote netip.AddrPort) bool {
	if len(b) < 8 || b[0] != 0 || (binary.BigEndian.Uint16(b[2:]) != 0x7a11 && binary.BigEndian.Uint16(b[2:]) != 0x7a12) {
		return false
	}
	if b[1]&0x7f != 0 || b[7] != 0 {
		return true
	}
	vni := uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6])
	c.mu.Lock()
	path := c.relayPaths[tsRelayPathKey{remote, vni}]
	valid := path != nil && c.peers[path.peer.key] == path.peer && c.relayEnabledLocked()
	c.mu.Unlock()
	if !valid {
		return true
	}
	payload := b[8:]
	if b[1] == 0x80 && binary.BigEndian.Uint16(b[2:]) == 0x7a11 {
		if len(payload) != 152 || !bytes.Equal(payload[:6], []byte("TS💬")) || !bytes.Equal(payload[6:38], path.description.server[:]) {
			return true
		}
		box, e := tsBoxKey(c.discoKey, path.description.server[:])
		if e != nil {
			return true
		}
		m, e := tsBoxOpen(box, payload[38:])
		if e != nil || len(m) != 74 || m[0] != 5 || m[1] != 0 || binary.BigEndian.Uint32(m[2:]) != vni || !bytes.Equal(m[10:42], path.peerDisco[:]) {
			return true
		}
		path.mu.Lock()
		matched := false
		for i, candidate := range path.candidates {
			if candidate.endpoint == remote && candidate.generation == binary.BigEndian.Uint32(m[6:]) {
				path.candidates[i].answered = true
				matched = true
				break
			}
		}
		path.mu.Unlock()
		if matched {
			m[0] = 6
			path.writeControl(remote, m)
			path.ping(remote)
		}
	} else if b[1] == 0 {
		if binary.BigEndian.Uint16(b[2:]) == 0x7a11 && bytes.HasPrefix(payload, []byte("TS💬")) {
			c.receiveDiscoVia(0, payload, remote, path)
		} else if binary.BigEndian.Uint16(b[2:]) == 0x7a12 {
			if len(payload) < 8 {
				return true
			}
			kind := binary.LittleEndian.Uint32(payload)
			if kind == 1 {
				pub, _, _, _, e := wgReadInitiationKind(c.nodeKey, payload, 1)
				if e != nil || !bytes.Equal(pub, path.peer.public) {
					return true
				}
			} else {
				offset := 4
				if kind == 2 {
					offset = 8
				}
				if kind < 2 || kind > 4 || len(payload) < offset+4 {
					return true
				}
				c.mu.Lock()
				owner := c.indices[binary.LittleEndian.Uint32(payload[offset:])]
				c.mu.Unlock()
				if owner != path.peer {
					return true
				}
			}
			path.peer.wg.handle(payload, path.peer.addr)
		}
	}
	return true
}
