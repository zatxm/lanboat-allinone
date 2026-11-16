package native

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type keyLines []string

func (k *keyLines) UnmarshalJSON(b []byte) error {
	var text string
	if json.Unmarshal(b, &text) == nil {
		*k = []string{text}
		return nil
	}
	return json.Unmarshal(b, (*[]string)(k))
}
func (k keyLines) MarshalJSON() ([]byte, error) {
	if len(k) == 1 && !strings.Contains(k[0], "BEGIN") {
		return json.Marshal(k[0])
	}
	return json.Marshal([]string(k))
}

type WireGuardPeer struct {
	Address                     string   `json:"address,omitempty"`
	Port                        uint16   `json:"port,omitempty"`
	PersistentKeepaliveInterval int      `json:"persistent_keepalive_interval,omitempty"`
	Reserved                    []byte   `json:"reserved,omitempty"`
	PublicKey                   string   `json:"public_key"`
	PreSharedKey                string   `json:"pre_shared_key,omitempty"`
	AllowedIPs                  []string `json:"allowed_ips,omitempty"`
}
type WireGuardOptions struct {
	WGObfs                      *WGObfsOptions    `json:"wgobfs,omitempty"`
	Amnezia                     *AmneziaWGOptions `json:"amnezia,omitempty"`
	PublicKey                   string            `json:"peer_public_key,omitempty"`
	PreSharedKey                string            `json:"pre_shared_key,omitempty"`
	LocalAddress                []string          `json:"local_address,omitempty"`
	Peers                       []WireGuardPeer   `json:"peers,omitempty"`
	Reserved                    []byte            `json:"reserved,omitempty"`
	PersistentKeepaliveInterval int               `json:"persistent_keepalive_interval,omitempty"`
}

func (o WireGuardOptions) validate(private keyLines, server bool, mtu int) error {
	if _, err := newWGObfuscation(o.Amnezia, o.WGObfs, mtu); err != nil {
		return err
	}
	if _, e := wgKey(strings.Join(private, "")); e != nil {
		return e
	}
	if len(o.Reserved) != 0 && (len(o.Reserved) != 3 || o.Reserved[0]|o.Reserved[1]|o.Reserved[2] != 0) {
		return errors.New("standard WireGuard reserved bytes must be 0,0,0")
	}
	if o.PersistentKeepaliveInterval < 0 || o.PersistentKeepaliveInterval > 65535 {
		return errors.New("WireGuard keepalive must be 0-65535 seconds")
	}
	peers := o.Peers
	if !server && len(peers) == 0 {
		peers = []WireGuardPeer{{PublicKey: o.PublicKey, PreSharedKey: o.PreSharedKey}}
	}
	if len(peers) == 0 || len(peers) > 128 {
		return errors.New("WireGuard requires 1-128 peers")
	}
	seen := map[string]bool{}
	for _, p := range peers {
		if p.Address != "" || p.Port != 0 || p.PersistentKeepaliveInterval != 0 || len(p.Reserved) != 0 {
			return errors.New("per-peer transport options require a WireGuard endpoint")
		}
		if _, e := wgKey(p.PublicKey); e != nil {
			return e
		}
		if seen[p.PublicKey] {
			return errors.New("duplicate WireGuard peer")
		}
		seen[p.PublicKey] = true
		if p.PreSharedKey != "" {
			if _, e := wgKey(p.PreSharedKey); e != nil {
				return e
			}
		}
		if server && len(p.AllowedIPs) == 0 {
			return errors.New("WireGuard inbound peer requires allowed_ips")
		}
		for _, a := range p.AllowedIPs {
			if _, e := netip.ParsePrefix(a); e != nil {
				return e
			}
		}
	}
	for _, a := range o.LocalAddress {
		if _, e := netip.ParsePrefix(a); e != nil {
			return e
		}
	}
	if !server && len(o.LocalAddress) == 0 {
		return errors.New("WireGuard outbound requires local_address")
	}
	return nil
}

type wgClient struct {
	runtime  *Runtime
	outbound Outbound
	mu       sync.Mutex
	peer     *wgPeer
}
type wgPeer struct {
	reserved               [3]byte
	obfs                   *wgObfuscation
	ownsSource             func(netip.Addr) bool
	lastInit, lastResponse []byte
	lastInitiation         time.Time
	runtime                *Runtime
	private                *ecdh.PrivateKey
	public, psk            []byte
	allowed                []netip.Prefix
	local                  []netip.Addr
	inbound                string
	mtu                    int
	mu                     sync.Mutex
	current, previous      *wgTransport
	handshake              *wgHandshake
	response               chan error
	lastStamp              []byte
	remote                 net.Addr
	sender                 func([]byte, net.Addr) error
	indexChanged           func(uint32, uint32, uint32) error
	handshakeMu            sync.Mutex
	done                   chan struct{}
	cancel                 context.CancelFunc
	once                   sync.Once
	stack                  *wgIPStack
	packetID               atomic.Uint32
	writeMu                sync.Mutex
	lastSent               time.Time
	keepalive              time.Duration
	nextKeepalive, keepDue time.Time
	udpWindow              int
	rekeying               atomic.Bool
}

func newWGPeer(r *Runtime, private keyLines, pub, psk string, local, allowed []string, inbound string, mtu, keepalive int, configure ...func(*ipEndpoint)) (*wgPeer, error) {
	key, e := wgKey(strings.Join(private, ""))
	if e != nil {
		return nil, e
	}
	priv, e := ecdh.X25519().NewPrivateKey(key)
	if e != nil {
		return nil, e
	}
	public, e := wgKey(pub)
	if e != nil {
		return nil, e
	}
	preshared := make([]byte, 32)
	if psk != "" {
		preshared, e = wgKey(psk)
		if e != nil {
			return nil, e
		}
	}
	if mtu == 0 {
		mtu = 1420
	}
	p := &wgPeer{runtime: r, private: priv, public: public, psk: preshared, inbound: inbound, mtu: mtu, done: make(chan struct{}), keepalive: time.Duration(keepalive) * time.Second}
	for _, a := range local {
		prefix, _ := netip.ParsePrefix(a)
		p.local = append(p.local, prefix.Addr())
	}
	for _, a := range allowed {
		prefix, _ := netip.ParsePrefix(a)
		p.allowed = append(p.allowed, prefix)
	}
	p.stack = newWGIPStack(p, configure...)
	return p, nil
}
func (c *wgClient) close() {
	c.mu.Lock()
	p := c.peer
	c.peer = nil
	c.mu.Unlock()
	if p != nil {
		p.close()
	}
}
func (c *wgClient) session(ctx context.Context) (*wgPeer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.peer != nil {
		return c.peer, nil
	}
	raw, e := c.runtime.endpoint(ctx, c.outbound, "udp")
	if e != nil {
		return nil, e
	}
	o := c.outbound
	pub, psk := o.PublicKey, o.PreSharedKey
	if len(o.Peers) > 0 {
		pub, psk = o.Peers[0].PublicKey, o.Peers[0].PreSharedKey
	}
	p, e := newWGPeer(c.runtime, o.PrivateKey, pub, psk, o.LocalAddress, nil, "", o.MTU, o.PersistentKeepaliveInterval)
	if e != nil {
		raw.Close()
		return nil, e
	}
	p.obfs, e = newWGObfuscation(o.Amnezia, o.WGObfs, o.MTU)
	if e != nil {
		raw.Close()
		return nil, e
	}
	p.remote = raw.RemoteAddr()
	p.sender = func(b []byte, _ net.Addr) error { _, e := raw.Write(b); return e }
	p.cancel = func() { raw.Close() }
	c.peer = p
	go func() {
		defer p.close()
		buffer := make([]byte, 65535)
		for {
			n, e := raw.Read(buffer)
			if e != nil {
				return
			}
			p.handle(buffer[:n], raw.RemoteAddr())
		}
	}()
	go p.maintain()
	return p, nil
}
func (c *wgClient) dial(ctx context.Context, network, address string) (net.Conn, error) {
	p, e := c.session(ctx)
	if e != nil {
		return nil, e
	}
	if e = p.ensure(ctx); e != nil {
		return nil, e
	}
	conn, e := p.stack.dial(ctx, network, address)
	if e != nil {
		return nil, e
	}
	return c.runtime.own(conn)
}
func (p *wgPeer) ensure(ctx context.Context) error {
	p.handshakeMu.Lock()
	defer p.handshakeMu.Unlock()
	p.mu.Lock()
	if p.current != nil && time.Since(p.current.at) < p.current.refreshTime() {
		p.mu.Unlock()
		return nil
	}
	s, e := wgInitiateKind(p.private, p.public, p.psk, p.header(1))
	if e != nil {
		p.mu.Unlock()
		return e
	}
	p.handshake = s
	if e = p.updateIndicesLocked(); e != nil {
		p.handshake = nil
		p.mu.Unlock()
		return e
	}
	p.response = make(chan error, 1)
	ready := p.response
	remote := p.remote
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		if p.handshake == s {
			p.handshake = nil
			_ = p.updateIndicesLocked()
		}
		p.mu.Unlock()
	}()
	v := p.v3()
	for attempt := range int(v.attempts.pick(5)) {
		p.mu.Lock()
		if attempt > 0 {
			var next *wgHandshake
			next, e = wgInitiateKind(p.private, p.public, p.psk, p.header(1))
			if e != nil {
				p.mu.Unlock()
				return e
			}
			if len(s.retryCookie) > 0 {
				next.retryCookie = s.retryCookie
				copy(next.message[132:], blake2s(next.message[:132], next.retryCookie, 16))
			}
			s = next
			p.handshake = s
			if e = p.updateIndicesLocked(); e != nil {
				p.mu.Unlock()
				return e
			}
		}
		message := append([]byte{}, s.message...)
		p.mu.Unlock()
		if e = p.obfs.decoys(ctx, func(b []byte) error { return p.sender(b, remote) }); e != nil {
			return e
		}
		if e = p.sender(p.obfs.wrap(1, message), remote); e != nil {
			return e
		}
		timer := time.NewTimer(time.Duration(v.retry.pick(1)) * time.Second)
		select {
		case e = <-ready:
			timer.Stop()
			if e != nil {
				return e
			}
			return p.sendEncrypted(nil)
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-p.done:
			timer.Stop()
			return net.ErrClosed
		case <-timer.C:
		}
	}
	return errors.New("WireGuard handshake timed out")
}

func (p *wgPeer) updateIndicesLocked() error {
	if p.indexChanged == nil {
		return nil
	}
	var current, previous, pending uint32
	if p.current != nil {
		current = p.current.local
	}
	if p.previous != nil {
		previous = p.previous.local
	}
	if p.handshake != nil {
		pending = p.handshake.index
	}
	return p.indexChanged(current, previous, pending)
}
func (p *wgPeer) respond(init []byte, remote net.Addr, stamp, ck, h []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if bytes.Equal(init, p.lastInit) && len(p.lastResponse) > 0 {
		p.sender(p.obfs.wrap(2, p.lastResponse), remote)
		return
	}
	if wgEqualTimestamp(stamp, p.lastStamp) {
		return
	}
	response, t, e := wgRespondKind(p.private, p.public, p.psk, ck, h, init, p.header(2))
	if e != nil {
		return
	}
	oldCurrent, oldPrevious := p.current, p.previous
	p.transportTimers(t)
	p.previous, p.current = p.current, t
	if p.updateIndicesLocked() != nil {
		p.current, p.previous = oldCurrent, oldPrevious
		return
	}
	p.lastStamp = append(p.lastStamp[:0], stamp...)
	p.lastInit = append(p.lastInit[:0], init...)
	p.lastResponse = append(p.lastResponse[:0], response...)
	p.remote = remote
	p.traversalLocked(time.Now())
	p.sender(p.obfs.wrap(2, response), remote)
}
func (p *wgPeer) handle(b []byte, remote net.Addr) {
	b, kind := p.obfs.decode(b)
	p.handlePacket(b, kind, remote)
}
func (p *wgPeer) handlePacket(b []byte, kind uint32, remote net.Addr) {
	if kind == 0 {
		return
	}
	if kind == 1 {
		p.mu.Lock()
		if time.Since(p.lastInitiation) < time.Second {
			p.mu.Unlock()
			return
		}
		p.lastInitiation = time.Now()
		p.mu.Unlock()
		pub, stamp, ck, h, e := wgReadInitiationKind(p.private, b, binary.LittleEndian.Uint32(b))
		if e != nil || !bytes.Equal(pub, p.public) {
			return
		}
		p.respond(b, remote, stamp, ck, h)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	switch kind {
	case 2:
		if p.handshake == nil {
			return
		}
		t, e := p.handshake.responseKind(b, binary.LittleEndian.Uint32(b))
		if e != nil {
			return
		}
		oldCurrent, oldPrevious := p.current, p.previous
		p.transportTimers(t)
		p.previous, p.current = p.current, t
		if p.updateIndicesLocked() != nil {
			p.current, p.previous = oldCurrent, oldPrevious
			return
		}
		p.remote = remote
		p.traversalLocked(time.Now())
		select {
		case p.response <- nil:
		default:
		}
	case 3:
		if p.handshake != nil {
			p.handshake.cookieKind(b, binary.LittleEndian.Uint32(b))
		}
	case 4:
		t := p.current
		if t == nil || len(b) < 8 {
			return
		}
		if binary.LittleEndian.Uint32(b[4:]) != t.local {
			t = p.previous
		}
		if t == nil {
			return
		}
		plain, e := t.openKind(b, binary.LittleEndian.Uint32(b))
		if e != nil {
			return
		}
		p.remote = remote
		p.traversalLocked(time.Now())
		p.udpWindow = max(p.udpWindow, len(b)+p.obfs.prefix(4))
		if len(plain) == 0 {
			return
		}
		packet, e := parseTunPacket(plain)
		if e != nil {
			return
		}
		if p.obfs != nil && p.keepDue.IsZero() {
			p.keepDue = time.Now().Add(time.Duration(p.v3().keepalive.pick(10)) * time.Second)
		}
		if len(p.allowed) > 0 {
			allowed := false
			for _, prefix := range p.allowed {
				if prefix.Contains(packet.source) {
					allowed = true
					break
				}
			}
			if !allowed || p.ownsSource != nil && !p.ownsSource(packet.source) {
				return
			}
		}
		p.mu.Unlock()
		p.stack.input(packet)
		p.mu.Lock()
	}
}
func (p *wgPeer) sendEncrypted(packet []byte) error {
	p.mu.Lock()
	t, remote := p.current, p.remote
	if t == nil || remote == nil {
		p.mu.Unlock()
		return errors.New("WireGuard peer has no session")
	}
	t.mu.Lock()
	confirmed := t.confirmed
	t.mu.Unlock()
	if !confirmed && p.previous != nil {
		t = p.previous
		t.mu.Lock()
		confirmed = t.confirmed
		t.mu.Unlock()
	}
	if !confirmed {
		p.mu.Unlock()
		return errors.New("WireGuard session awaits key confirmation")
	}
	p.lastSent = time.Now()
	p.keepDue = time.Time{}
	p.traversalLocked(p.lastSent)
	p.udpWindow = max(p.udpWindow, len(packet)+32+p.obfs.prefix(4))
	padding := p.contentPadding(len(packet) + 32 + p.obfs.prefix(4))
	p.mu.Unlock()
	suffix := 0
	if p.obfs != nil && p.obfs.mask != nil {
		suffix = 32
		if len(packet) > 160 {
			suffix = 8
		}
	}
	b, e := t.sealPadded(packet, p.header(4), p.obfs.prefix(4), suffix, padding)
	if e != nil {
		return e
	}
	if p.obfs != nil && p.obfs.mask != nil {
		b = p.obfs.mask.encode(b)
		if b == nil {
			return nil
		}
	}
	if p.obfs != nil && p.obfs.v3.key != nil {
		wgHeaderXOR(b[p.obfs.prefix(4):p.obfs.prefix(4)+16], p.obfs.v3.key, b[:12])
	}
	return p.sender(b, remote)
}
func (p *wgPeer) sendIP(packet []byte) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return writeIPFragments(packet, p.mtu, p.packetID.Add(1), p.sendEncrypted)
}
func (p *wgPeer) close() {
	p.once.Do(func() {
		close(p.done)
		if p.cancel != nil {
			p.cancel()
		}
		p.stack.close()
	})
}
func (p *wgPeer) maintain() {
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-p.runtime.ctx.Done():
			p.close()
			return
		case now := <-timer.C:
			p.stack.expire(now)
			p.mu.Lock()
			if p.previous != nil && now.Sub(p.previous.at) > p.previous.lifetime() {
				p.previous = nil
				_ = p.updateIndicesLocked()
			}
			keep := p.current != nil && (!p.nextKeepalive.IsZero() && !now.Before(p.nextKeepalive) || !p.keepDue.IsZero() && !now.Before(p.keepDue))
			rekey := p.current != nil && now.Sub(p.current.at) >= p.current.refreshTime() && (!p.lastSent.IsZero() && now.Sub(p.lastSent) < 30*time.Second || keep)
			p.mu.Unlock()
			if (keep || rekey) && p.rekeying.CompareAndSwap(false, true) {
				go func() {
					defer p.rekeying.Store(false)
					ctx, cancel := context.WithTimeout(p.runtime.ctx, handshakeTimeout)
					defer cancel()
					if p.ensure(ctx) == nil && keep {
						p.sendEncrypted(nil)
					}
				}()
			}
		}
	}
}

type wgListener struct {
	reservedHeader bool
	writer         func([]byte, net.Addr) error
	obfs           *wgObfuscation
	packet         net.PacketConn
	runtime        *Runtime
	private        *ecdh.PrivateKey
	peers          []*wgPeer
	mu             sync.Mutex
	tokens         int
	cookieTokens   int
	cookieSecret   [32]byte
	cookieAt       time.Time
	until          time.Time
	done           chan struct{}
	once           sync.Once
}

func (r *Runtime) listenWG(in Inbound) (*wgListener, error) {
	host := in.Listen
	if host == "" {
		host = "127.0.0.1"
	}
	packet, e := in.ListenOptions.listenPacket(r.ctx, "udp", portAddress(host, in.ListenPort))
	if e != nil {
		return nil, e
	}
	key, e := wgKey(strings.Join(in.PrivateKey, ""))
	if e != nil {
		packet.Close()
		return nil, e
	}
	private, e := ecdh.X25519().NewPrivateKey(key)
	if e != nil {
		packet.Close()
		return nil, e
	}
	l := &wgListener{packet: packet, runtime: r, private: private, done: make(chan struct{})}
	l.obfs, e = newWGObfuscation(in.Amnezia, in.WGObfs, in.MTU)
	if e != nil {
		packet.Close()
		return nil, e
	}
	for _, cfg := range in.Peers {
		p, e := newWGPeer(r, in.PrivateKey, cfg.PublicKey, cfg.PreSharedKey, in.Address, cfg.AllowedIPs, in.Tag, in.MTU, in.PersistentKeepaliveInterval)
		if e != nil {
			l.close()
			return nil, e
		}
		p.sender = func(b []byte, a net.Addr) error { _, e := packet.WriteTo(b, a); return e }
		p.obfs = l.obfs
		l.peers = append(l.peers, p)
	}
	for _, peer := range l.peers {
		peer.ownsSource = func(address netip.Addr) bool {
			var owner *wgPeer
			bits := -1
			for _, p := range l.peers {
				for _, prefix := range p.allowed {
					if prefix.Contains(address) && prefix.Bits() > bits {
						owner = p
						bits = prefix.Bits()
					}
				}
			}
			return owner == peer
		}
	}
	return l, nil
}
func (l *wgListener) run() {
	defer l.close()
	for _, p := range l.peers {
		go p.maintain()
	}
	buffer := make([]byte, 65535)
	for {
		n, remote, e := l.packet.ReadFrom(buffer)
		if e != nil {
			return
		}
		l.handleDatagram(buffer[:n], remote)
	}
}
func (l *wgListener) handleDatagram(raw []byte, remote net.Addr) {
	b, kind := l.obfs.decode(raw)
	if l.reservedHeader && len(raw) >= 4 {
		b, kind = raw, uint32(raw[0])
		if kind < 1 || kind > 4 {
			return
		}
	}
	if kind == 1 {
		if !l.allowInitiation(b, remote) {
			return
		}
		pub, stamp, ck, h, e := wgReadInitiationKind(l.private, b, binary.LittleEndian.Uint32(b))
		if e != nil {
			return
		}
		for _, p := range l.peers {
			if bytes.Equal(p.public, pub) {
				p.respond(b, remote, stamp, ck, h)
				break
			}
		}
		return
	}
	if (kind == 2 || kind == 3) && len(b) >= 12 {
		index := binary.LittleEndian.Uint32(b[8:])
		if kind == 3 {
			index = binary.LittleEndian.Uint32(b[4:])
		}
		for _, p := range l.peers {
			p.mu.Lock()
			valid := p.handshake != nil && p.handshake.index == index
			p.mu.Unlock()
			if valid {
				p.handlePacket(b, kind, remote)
				break
			}
		}
	}
	if kind == 4 && len(b) >= 8 {
		index := binary.LittleEndian.Uint32(b[4:])
		for _, p := range l.peers {
			p.mu.Lock()
			valid := p.current != nil && p.current.local == index || p.previous != nil && p.previous.local == index
			p.mu.Unlock()
			if valid {
				p.handlePacket(b, kind, remote)
				break
			}
		}
	}
}
func (p *wgPeer) header(kind uint32) uint32 {
	if p.reserved != ([3]byte{}) {
		return kind | uint32(p.reserved[0])<<8 | uint32(p.reserved[1])<<16 | uint32(p.reserved[2])<<24
	}
	return p.obfs.header(kind)
}
func (l *wgListener) writePacket(b []byte, a net.Addr) error {
	if l.writer != nil {
		return l.writer(b, a)
	}
	_, err := l.packet.WriteTo(b, a)
	return err
}
func (l *wgListener) close() {
	l.once.Do(func() {
		close(l.done)
		l.packet.Close()
		for _, p := range l.peers {
			p.close()
		}
	})
}
