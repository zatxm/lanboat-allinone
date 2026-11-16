package native

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

type tsRelayAllocation struct {
	keys      [2][32]byte
	endpoints [2]netip.AddrPort
	vni       uint32
	lamport   uint64
	expires   time.Time
	last      [2]time.Time
	owner     int64
}
type tsRelayServer struct {
	disco       *ecdh.PrivateKey
	c           *tailscaleClient
	udp         *net.UDPConn
	endpoints   []netip.AddrPort
	mu          sync.Mutex
	allocations map[uint32]*tsRelayAllocation
	next        uint64
	secret      [32]byte
	done        chan struct{}
}

func (c *tailscaleClient) startRelay() error {
	socket, e := c.listenPacket(c.o.RelayServerPort)
	if e != nil {
		return e
	}
	s := &tsRelayServer{c: c, udp: socket.(*net.UDPConn), allocations: map[uint32]*tsRelayAllocation{}, done: make(chan struct{})}
	s.disco, _ = ecdh.X25519().GenerateKey(rand.Reader)
	rand.Read(s.secret[:])
	for _, raw := range c.o.RelayServerStaticEndpoints {
		ep, _ := netip.ParseAddrPort(raw)
		s.endpoints = append(s.endpoints, ep)
	}
	if len(s.endpoints) == 0 {
		s.endpoints = tsLocalEndpoints(c.o.RelayServerPort)
	}
	c.relay = s
	go func() { defer close(s.done); s.run() }()
	return nil
}
func (s *tsRelayServer) close() { s.udp.Close(); <-s.done }
func (s *tsRelayServer) authorized(n tsNode) bool {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	if s.c.self.Expired || s.c.self.lockInvalid || !s.c.self.KeyExpiry.IsZero() && time.Now().After(s.c.self.KeyExpiry) {
		return false
	}
	if _, disabled := s.c.self.CapMap["disable-relay-server"]; disabled {
		return false
	}
	current, ok := s.c.nodes[n.ID]
	if !ok || current.restricted() || current.DiscoKey != n.DiscoKey || current.Expired || !current.KeyExpiry.IsZero() && time.Now().After(current.KeyExpiry) {
		return false
	}
	for _, a := range current.Addresses {
		if s.c.peerCapabilityLocked(a.Addr(), s.c.self.Addresses, "tailscale.com/cap/relay") {
			return true
		}
	}
	return false
}
func (s *tsRelayServer) allocate(keys [2][32]byte, owner int64) (*tsRelayAllocation, error) {
	if keys[0] == [32]byte{} || keys[1] == [32]byte{} || keys[0] == keys[1] {
		return nil, errors.New("invalid relay keys")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	count := 0
	for vni, a := range s.allocations {
		if now.After(a.expires) {
			delete(s.allocations, vni)
			continue
		}
		if a.owner == owner {
			count++
		}
		if a.keys == keys || a.keys[0] == keys[1] && a.keys[1] == keys[0] {
			copy := *a
			return &copy, nil
		}
	}
	if len(s.allocations) >= 4096 || count >= 64 {
		return nil, errors.New("relay allocation limit")
	}
	var vni uint32
	for {
		var b [4]byte
		rand.Read(b[:])
		vni = binary.BigEndian.Uint32(b[:]) & 0xffffff
		if vni != 0 && s.allocations[vni] == nil {
			break
		}
	}
	s.next++
	a := &tsRelayAllocation{keys: keys, vni: vni, owner: owner, lamport: s.next, expires: now.Add(time.Minute)}
	s.allocations[vni] = a
	copy := *a
	return &copy, nil
}
func (s *tsRelayServer) request(n tsNode, m []byte) {
	if len(m) != 70 || !s.authorized(n) {
		return
	}
	var keys [2][32]byte
	copy(keys[0][:], m[2:34])
	copy(keys[1][:], m[34:66])
	key, e := tsPublic(n.DiscoKey, "discokey")
	if e != nil || keys[0] != [32]byte(key) && keys[1] != [32]byte(key) {
		return
	}
	a, e := s.allocate(keys, n.ID)
	if e != nil {
		return
	}
	reply := append([]byte{9, 0}, m[66:70]...)
	reply = append(reply, s.description(a)...)
	_ = s.c.sendDisco(n, reply)
}
func (s *tsRelayServer) description(a *tsRelayAllocation) []byte {
	b := append([]byte(nil), s.disco.PublicKey().Bytes()...)
	b = append(b, a.keys[0][:]...)
	b = append(b, a.keys[1][:]...)
	b = binary.BigEndian.AppendUint64(b, a.lamport)
	b = binary.BigEndian.AppendUint32(b, a.vni)
	b = binary.BigEndian.AppendUint64(b, uint64(time.Minute))
	b = binary.BigEndian.AppendUint64(b, uint64(time.Minute))
	for _, ep := range s.endpoints {
		ip := ep.Addr().As16()
		b = append(b, ip[:]...)
		b = binary.BigEndian.AppendUint16(b, ep.Port())
	}
	return b
}
func (c *tailscaleClient) sendDisco(n tsNode, m []byte) error {
	remote, e := tsPublic(n.DiscoKey, "discokey")
	if e != nil {
		return e
	}
	box, e := tsBoxKey(c.discoKey, remote)
	if e != nil {
		return e
	}
	wire := append([]byte("TS💬"), c.discoKey.PublicKey().Bytes()...)
	wire = append(wire, tsBoxSeal(box, m)...)
	public, e := tsPublic(n.Key, "nodekey")
	if e != nil {
		return e
	}
	d, e := c.derp(n.derp())
	if e != nil {
		return e
	}
	return d.send(public, wire)
}
func tsGeneve(vni uint32, control bool, data []byte) []byte {
	b := make([]byte, 8, len(data)+8)
	binary.BigEndian.PutUint16(b[2:], 0x7a12)
	if bytes.HasPrefix(data, []byte("TS💬")) {
		binary.BigEndian.PutUint16(b[2:], 0x7a11)
	}
	if control {
		b[1] = 0x80
		binary.BigEndian.PutUint16(b[2:], 0x7a11)
	}
	b[4], b[5], b[6] = byte(vni>>16), byte(vni>>8), byte(vni)
	return append(b, data...)
}
func (s *tsRelayServer) challenge(remote netip.AddrPort, key []byte, common []byte, epoch int64) []byte {
	h := hmac.New(sha256.New, s.secret[:])
	h.Write([]byte(remote.String()))
	h.Write(key)
	h.Write(common[:40])
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(epoch))
	h.Write(b[:])
	return h.Sum(nil)
}
func (s *tsRelayServer) run() {
	buffer := make([]byte, 65536)
	for {
		n, remote, e := s.udp.ReadFromUDPAddrPort(buffer)
		if e != nil {
			return
		}
		s.receive(buffer[:n], remote)
	}
}
func (s *tsRelayServer) receive(b []byte, remote netip.AddrPort) {
	if len(b) < 8 || b[0] != 0 || b[1]&0x7f != 0 || b[7] != 0 {
		return
	}
	vni := uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6])
	protocol := binary.BigEndian.Uint16(b[2:])
	payload := b[8:]
	s.mu.Lock()
	a := s.allocations[vni]
	if a == nil || time.Now().After(a.expires) {
		delete(s.allocations, vni)
		s.mu.Unlock()
		return
	}
	snapshot := *a
	s.mu.Unlock()
	s.c.mu.Lock()
	node, exists := s.c.nodes[snapshot.owner]
	s.c.mu.Unlock()
	ownerKey, keyErr := tsPublic(node.DiscoKey, "discokey")
	if !exists || keyErr != nil || [32]byte(ownerKey) != snapshot.keys[0] && [32]byte(ownerKey) != snapshot.keys[1] || !s.authorized(node) {
		s.mu.Lock()
		delete(s.allocations, vni)
		s.mu.Unlock()
		return
	}
	if b[1] == 0 && (protocol == 0x7a12 || protocol == 0x7a11) {
		// Binding proves address ownership; opaque WireGuard packets stay end-to-end encrypted.
		if len(payload) == 0 {
			return
		}
		dst := netip.AddrPort{}
		if remote == snapshot.endpoints[0] {
			dst = snapshot.endpoints[1]
		} else if remote == snapshot.endpoints[1] {
			dst = snapshot.endpoints[0]
		}
		if !dst.IsValid() {
			return
		}
		s.mu.Lock()
		if current := s.allocations[vni]; current == a {
			side := 0
			if remote == current.endpoints[1] {
				side = 1
			}
			current.touch(side)
		}
		s.mu.Unlock()
		_, _ = s.udp.WriteToUDPAddrPort(b, dst)
		return
	}
	if b[1] != 0x80 || protocol != 0x7a11 || len(payload) != 152 || !bytes.Equal(payload[:6], []byte("TS💬")) {
		return
	}
	key := [32]byte(payload[6:38])
	side := -1
	for i, k := range snapshot.keys {
		if k == key {
			side = i
		}
	}
	if side < 0 {
		return
	}
	box, e := tsBoxKey(s.disco, key[:])
	if e != nil {
		return
	}
	m, e := tsBoxOpen(box, payload[38:])
	if e != nil || len(m) != 74 || m[1] != 0 || binary.BigEndian.Uint32(m[2:]) != vni || binary.BigEndian.Uint32(m[6:]) == 0 || !bytes.Equal(m[10:42], snapshot.keys[1-side][:]) {
		return
	}
	epoch := time.Now().Unix() / 30
	switch m[0] {
	case 4:
		reply := append([]byte(nil), m...)
		reply[0] = 5
		copy(reply[42:], s.challenge(remote, key[:], m[2:], epoch))
		wire := append([]byte("TS💬"), s.disco.PublicKey().Bytes()...)
		wire = append(wire, tsBoxSeal(box, reply)...)
		_, _ = s.udp.WriteToUDPAddrPort(tsGeneve(vni, true, wire), remote)
	case 6:
		if !hmac.Equal(m[42:], s.challenge(remote, key[:], m[2:], epoch)) && !hmac.Equal(m[42:], s.challenge(remote, key[:], m[2:], epoch-1)) {
			return
		}
		s.mu.Lock()
		if current := s.allocations[vni]; current == a {
			current.endpoints[side] = remote
			current.touch(side)
		}
		s.mu.Unlock()
	}
}

func (a *tsRelayAllocation) touch(side int) {
	a.last[side] = time.Now()
	if a.endpoints[0].IsValid() && a.endpoints[1].IsValid() {
		old := a.last[0]
		if a.last[1].Before(old) {
			old = a.last[1]
		}
		a.expires = old.Add(time.Minute)
	}
}
