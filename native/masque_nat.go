package native

import (
	"container/list"
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type masqueNATOptions struct {
	Timeout   string `json:"udp_timeout,omitempty"`
	Mapping   string `json:"udp_mapping,omitempty"`
	Filtering string `json:"udp_filtering,omitempty"`
	Maximum   int    `json:"udp_nat_max,omitempty"`
}

type masqueNATSettings struct {
	timeout            time.Duration
	mapping, filtering string
	maximum            int
}

func (o masqueNATOptions) settings() (*masqueNATSettings, error) {
	s := &masqueNATSettings{timeout: 5 * time.Minute, mapping: "endpoint_independent", filtering: "endpoint_independent", maximum: 4096}
	if o.Timeout != "" {
		d, err := time.ParseDuration(o.Timeout)
		if err != nil || d < 0 || d > 0 && d < time.Millisecond || d > 24*time.Hour {
			return nil, errors.New("MASQUE udp_timeout must be1ms-24h")
		}
		if d != 0 {
			s.timeout = d
		}
	}
	for _, v := range []struct {
		raw   string
		value *string
	}{{o.Mapping, &s.mapping}, {o.Filtering, &s.filtering}} {
		if v.raw == "" {
			continue
		}
		switch v.raw {
		case "endpoint_independent", "address_dependent", "address_and_port_dependent":
			*v.value = v.raw
		default:
			return nil, errors.New("invalid MASQUE UDP NAT mapping or filtering")
		}
	}
	if o.Maximum < 0 || o.Maximum > 65536 {
		return nil, errors.New("MASQUE udp_nat_max must be0-65536")
	}
	if o.Maximum != 0 {
		s.maximum = o.Maximum
	}
	return s, nil
}

type masqueNATKey struct {
	scope                     *masqueNATScope
	source, destination       netip.AddrPort
	rewrite                   netip.AddrPort
	outbound, member, carrier string
	family                    bool
	loopback                  bool
}

type masqueNAT struct {
	runtime  *Runtime
	settings masqueNATSettings
	mu       sync.Mutex
	entries  map[masqueNATKey]*masqueNATEntry
	lru      list.List
}

type masqueNATScope struct {
	table   *masqueNAT
	ctx     context.Context
	cancel  context.CancelFunc
	closed  bool // table.mu
	workers sync.WaitGroup
}

type masqueNATPermission struct {
	original netip.AddrPort
	until    time.Time
}

type masqueNATEntry struct {
	table    *masqueNAT
	key      masqueNATKey
	position *list.Element
	last     time.Time
	targets  map[netip.AddrPort]masqueNATPermission
	ctx      context.Context
	cancel   context.CancelFunc
	ready    chan struct{}
	conn     net.Conn
	packet   *net.UDPConn
	carrier  addressedUDP
	err      error
	reply    func([]byte, string) error
	target   netip.AddrPort
}

type masqueNATGroup struct {
	group  *outboundGroup
	member string
}

func newMasqueNAT(r *Runtime, s *masqueNATSettings) *masqueNAT {
	if s == nil {
		return nil
	}
	return &masqueNAT{runtime: r, settings: *s, entries: map[masqueNATKey]*masqueNATEntry{}}
}

func (n *masqueNAT) scope() *masqueNATScope {
	ctx, cancel := context.WithCancel(n.runtime.ctx)
	return &masqueNATScope{table: n, ctx: ctx, cancel: cancel}
}

func (e *masqueNATEntry) close() {
	e.cancel()
	select {
	case <-e.ready:
		if e.conn != nil {
			e.conn.Close()
		}
	default:
	}
}

func (n *masqueNAT) removeLocked(e *masqueNATEntry) {
	if n.entries[e.key] == e {
		delete(n.entries, e.key)
		n.lru.Remove(e.position)
	}
}

func (s *masqueNATScope) close() {
	n := s.table
	n.mu.Lock()
	s.closed = true
	s.cancel()
	var entries []*masqueNATEntry
	for _, e := range n.entries {
		if e.key.scope == s {
			n.removeLocked(e)
			entries = append(entries, e)
		}
	}
	n.mu.Unlock()
	for _, e := range entries {
		e.close()
	}
	s.workers.Wait()
}

// Every datagram is routed before association lookup. A permissive mapping
// must never let a previously allowed destination bypass a later reject rule.
func (s *masqueNATScope) send(q request, data []byte, reply func([]byte, string) error) error {
	n := s.table
	if s.ctx.Err() != nil {
		return net.ErrClosed
	}
	source, err := netip.ParseAddrPort(q.source)
	if err != nil {
		return err
	}
	original, err := netip.ParseAddrPort(q.address)
	if err != nil {
		return err
	}
	q.payload = data
	ctx, cancel := context.WithTimeout(s.ctx, handshakeTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, inboundRouteKey{}, true)
	q, tag, err := n.runtime.routeTarget(ctx, q)
	if errors.Is(err, errDNSRoute) {
		b, e := n.runtime.ExchangeDNS(WithMetadata(ctx, q.metadata), data, q.inbound)
		if e != nil {
			return e
		}
		return reply(b, original.String())
	}
	if err != nil {
		return err
	}
	leaf := tag
	var groups []masqueNATGroup
	for n.runtime.groups[leaf] != nil {
		g := n.runtime.groups[leaf]
		leaf = *g.selected.Load()
		groups = append(groups, masqueNATGroup{g, leaf})
	}
	outbound := n.runtime.outbounds[leaf]
	direct := outbound.Type == "direct"
	multi := multiTargetUDP(outbound)
	host, port, err := net.SplitHostPort(q.address)
	if err != nil {
		return err
	}
	var target netip.AddrPort
	if direct {
		if ref := n.runtime.outbounds[leaf].DomainResolver; ref != "" {
			var cancelRef context.CancelFunc
			ctx, cancelRef = ref.apply(ctx)
			defer cancelRef()
			ctx = context.WithValue(ctx, dnsBootstrapKey{}, ref.tag())
		}
		ips, e := n.runtime.directIPs(ctx, host)
		if e != nil {
			return e
		}
		if len(ips) == 0 {
			return errors.New("MASQUE UDP destination has no addresses")
		}
		number, _ := strconv.ParseUint(port, 10, 16)
		target = netip.AddrPortFrom(ips[0].Unmap(), uint16(number))
	} else {
		target = original
		if address, e := netip.ParseAddrPort(q.address); e == nil {
			target = netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
		} else {
			// A hostname rewrite keeps its remote DNS behavior and reply identity.
			multi = false
		}
	}
	key := masqueNATKey{scope: s, source: source, outbound: tag, member: leaf, family: target.Addr().Is6(), loopback: target.Addr().IsLoopback()}
	switch n.settings.mapping {
	case "address_dependent":
		key.destination = netip.AddrPortFrom(target.Addr(), 0)
	case "address_and_port_dependent":
		key.destination = target
	}
	if target != original {
		key.rewrite = original
	}
	if !direct && !multi {
		key.carrier = q.address
	}
	n.mu.Lock()
	if s.closed {
		n.mu.Unlock()
		return net.ErrClosed
	}
	e := n.entries[key]
	var evicted *masqueNATEntry
	create := e == nil
	if create {
		if len(n.entries) >= n.settings.maximum {
			evicted = n.lru.Back().Value.(*masqueNATEntry)
			n.removeLocked(evicted)
		}
		child, stop := context.WithCancel(s.ctx)
		e = &masqueNATEntry{table: n, key: key, ctx: child, cancel: stop, ready: make(chan struct{}), last: time.Now(), reply: reply, target: target, targets: map[netip.AddrPort]masqueNATPermission{}}
		e.position = n.lru.PushFront(e)
		n.entries[key] = e
		s.workers.Add(1)
	}
	now := time.Now()
	if target != original || n.settings.filtering != "endpoint_independent" {
		if _, exists := e.targets[target]; !exists && len(e.targets) >= 256 {
			var oldest netip.AddrPort
			var until time.Time
			for address, permission := range e.targets {
				if !oldest.IsValid() || permission.until.Before(until) {
					oldest, until = address, permission.until
				}
			}
			delete(e.targets, oldest)
		}
		e.targets[target] = masqueNATPermission{original: original, until: now.Add(n.settings.timeout)}
	}
	e.last = time.Now()
	n.lru.MoveToFront(e.position)
	n.mu.Unlock()
	if evicted != nil {
		evicted.close()
	}
	if create {
		e.open(ctx, q, tag, target, direct, multi, groups)
	}
	select {
	case <-e.ready:
	case <-e.ctx.Done():
		return net.ErrClosed
	}
	if e.err != nil {
		return e.err
	}
	if e.ctx.Err() != nil {
		return net.ErrClosed
	}
	_ = e.conn.SetReadDeadline(time.Now().Add(n.settings.timeout))
	_ = e.conn.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	var written int
	if direct {
		written, err = e.packet.WriteToUDPAddrPort(data, target)
	} else if e.carrier != nil {
		written, err = e.carrier.writePacket(data, target.String())
	} else {
		written, err = e.conn.Write(data)
	}
	n.runtime.up.Add(int64(written))
	if err != nil {
		e.report(err)
		n.mu.Lock()
		n.removeLocked(e)
		n.mu.Unlock()
		e.close()
	}
	return err
}

func (e *masqueNATEntry) open(ctx context.Context, q request, tag string, target netip.AddrPort, direct, multi bool, groups []masqueNATGroup) {
	n := e.table
	n.runtime.logInbound(&q)
	defer func() { n.runtime.logConnection(q, tag, e.conn, e.err) }()
	dial, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(e.ctx, cancel)
	if direct {
		network, local := "udp4", "0.0.0.0:0"
		if target.Addr().Is6() {
			network, local = "udp6", "[::]:0"
		}
		var packet net.PacketConn
		packet, e.err = n.runtime.listenPacketWithOptions(dial, n.runtime.outbounds[e.key.member].DialOptions.routeNetwork(q.networkContext(dial)), network, local, target.String())
		if e.err == nil {
			e.packet = packet.(*net.UDPConn)
			e.conn = e.packet
			// Transparent group wrappers own the same socket. Switching an
			// interrupting group must close it even while the mapping is idle.
			for i := len(groups) - 1; i >= 0; i-- {
				hop := groups[i]
				wrapped := &groupConn{Conn: e.conn, group: hop.group, member: hop.member}
				hop.group.mu.Lock()
				changed := hop.group.closed || *hop.group.selected.Load() != hop.member
				if !changed {
					hop.group.conns[wrapped] = true
					hop.group.lastUsed.Store(time.Now().UnixNano())
				}
				hop.group.mu.Unlock()
				if changed {
					e.conn.Close()
					e.err = errors.New("NAT group selection changed while opening socket")
					break
				}
				e.conn = wrapped
			}
		}
	} else {
		e.conn, e.err = n.runtime.dialOutbound(q.networkContext(dial), tag, "udp", q.address)
		if e.err == nil {
			for _, hop := range groups {
				if *hop.group.selected.Load() != hop.member {
					e.conn.Close()
					e.err = errors.New("NAT group selection changed while opening carrier")
					break
				}
			}
		}
		if e.err == nil && multi {
			e.carrier = udpCarrier(e.conn)
			if e.carrier == nil {
				e.conn.Close()
				e.err = errors.New("UDP carrier cannot change destination")
			}
		}
		if q.icmpError != nil {
			if e.err != nil {
				var cause *icmpFlowError
				if errors.As(e.err, &cause) {
					q.icmpError(cause)
				}
			} else {
				e.conn = &icmpErrorConn{Conn: e.conn, notify: q.icmpError}
			}
		}
	}
	stop()
	cancel()
	close(e.ready)
	if e.err != nil {
		n.mu.Lock()
		n.removeLocked(e)
		n.mu.Unlock()
		e.cancel()
		e.key.scope.workers.Done()
		return
	}
	if e.ctx.Err() != nil {
		e.conn.Close()
	}
	go e.read()
}

func (e *masqueNATEntry) read() {
	n := e.table
	defer e.key.scope.workers.Done()
	defer e.close()
	defer func() { n.mu.Lock(); n.removeLocked(e); n.mu.Unlock() }()
	for {
		n.mu.Lock()
		deadline := e.last.Add(n.settings.timeout)
		n.mu.Unlock()
		_ = e.conn.SetReadDeadline(deadline)
		var count int
		var from netip.AddrPort
		var err error
		var b []byte
		if e.packet != nil {
			err = masqueWaitPacket(e.packet)
			if err == nil {
				b = packetBuffers.Get().([]byte)
				count, from, err = e.packet.ReadFromUDPAddrPort(b)
				from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			}
		} else if e.carrier != nil {
			b = packetBuffers.Get().([]byte)
			var address string
			count, address, err = e.carrier.readPacket(b)
			if err == nil {
				from, err = netip.ParseAddrPort(address)
				if err != nil {
					packetBuffers.Put(b)
					continue
				}
				from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			}
		} else {
			b = packetBuffers.Get().([]byte)
			count, err = e.conn.Read(b)
			from = e.target
		}
		if err != nil {
			e.report(err)
			if b != nil {
				packetBuffers.Put(b)
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				n.mu.Lock()
				active := n.entries[e.key] == e && time.Now().Before(e.last.Add(n.settings.timeout))
				if !active {
					n.removeLocked(e)
				}
				n.mu.Unlock()
				if active {
					continue
				}
			}
			return
		}
		n.mu.Lock()
		permission, known := e.targets[from]
		known = known && time.Now().Before(permission.until)
		allowed := known || n.settings.filtering == "endpoint_independent"
		if !allowed && n.settings.filtering == "address_dependent" {
			for target, permission := range e.targets {
				if target.Addr() == from.Addr() && time.Now().Before(permission.until) {
					allowed = true
					break
				}
			}
		}
		if !known && from.Addr().Is4() != e.key.source.Addr().Is4() {
			allowed = false
		}
		if allowed {
			e.last = time.Now()
			if n.entries[e.key] == e {
				n.lru.MoveToFront(e.position)
			}
		}
		n.mu.Unlock()
		if !allowed {
			packetBuffers.Put(b)
			continue
		}
		if known {
			from = permission.original
		}
		n.runtime.down.Add(int64(count))
		err = e.reply(b[:count], from.String())
		packetBuffers.Put(b)
		if err != nil {
			return
		}
	}
}

func (e *masqueNATEntry) report(err error) {
	if c, ok := e.conn.(*icmpErrorConn); ok {
		c.report(err)
	}
}
