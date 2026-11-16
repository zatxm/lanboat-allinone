package native

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type ss2022Direct struct {
	conn    net.PacketConn
	dead    bool
	targets map[netip.AddrPort]time.Time
}

// A direct UDP session keeps its source port across destinations and client
// rebinding. Proxy outbounds continue through the normal routed associations.
func (r *Runtime) ss2022SendDirect(s *ss2022ServerSession, o Outbound, q request, data []byte, replies net.PacketConn, workers *sync.WaitGroup, count *int) (resultErr error) {
	defer func() {
		if resultErr != nil {
			r.logConnection(q, o.Tag, nil, resultErr)
		}
	}()
	ctx, cancel := context.WithTimeout(r.ctx, handshakeTimeout)
	defer cancel()
	if o.DomainResolver != "" {
		ctx = context.WithValue(ctx, dnsBootstrapKey{}, o.DomainResolver.options().Server)
		var cancelResolver context.CancelFunc
		ctx, cancelResolver = o.DomainResolver.apply(ctx)
		defer cancelResolver()
	}
	host, port, err := net.SplitHostPort(q.address)
	if err != nil {
		return err
	}
	ips, err := r.directIPs(ctx, host)
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return errors.New("Shadowsocks2022 destination has no addresses")
	}
	number, _ := strconv.ParseUint(port, 10, 16)
	target := netip.AddrPortFrom(ips[0].Unmap(), uint16(number))
	network, local := "udp4", "0.0.0.0:0"
	if target.Addr().Is6() {
		network, local = "udp6", "[::]:0"
	}
	class := o.Tag + ":" + network
	if target.Addr().IsLoopback() {
		class += "-loopback"
	}
	fresh := false
	s.mu.Lock()
	if s.direct == nil {
		s.direct = make(map[string]*ss2022Direct)
	}
	d := s.direct[class]
	if d != nil && d.dead {
		delete(s.direct, class)
		*count -= 1
		d = nil
	}
	if d == nil {
		if *count >= 256 {
			s.mu.Unlock()
			return errors.New("Shadowsocks2022 UDP socket limit reached")
		}
		conn, err := r.listenPacketWithOptions(ctx, o.DialOptions, network, local, target.String())
		if err != nil {
			s.mu.Unlock()
			return err
		}
		fresh = true
		d = &ss2022Direct{conn: conn, targets: map[netip.AddrPort]time.Time{}}
		s.direct[class] = d
		*count += 1
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer conn.Close()
			defer func() { s.mu.Lock(); d.dead = true; s.mu.Unlock() }()
			buffer := packetBuffers.Get().([]byte)
			defer packetBuffers.Put(buffer)
			for {
				n, from, err := conn.ReadFrom(buffer)
				if err != nil {
					return
				}
				source := from.(*net.UDPAddr).AddrPort()
				source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
				s.mu.Lock()
				until, known := d.targets[source]
				s.mu.Unlock()
				if !known || time.Now().After(until) {
					continue
				}
				r.down.Add(int64(n))
				if s.reply(replies, source.String(), buffer[:n]) != nil {
					return
				}
			}
		}()
	}
	now := time.Now()
	if _, exists := d.targets[target]; !exists && len(d.targets) >= 256 {
		for old, until := range d.targets {
			if now.After(until) {
				delete(d.targets, old)
			}
		}
		if len(d.targets) >= 256 {
			s.mu.Unlock()
			return errors.New("Shadowsocks2022 UDP destination limit reached")
		}
	}
	d.targets[target] = now.Add(time.Minute)
	_ = d.conn.SetReadDeadline(now.Add(time.Minute))
	_ = d.conn.SetWriteDeadline(now.Add(handshakeTimeout))
	s.mu.Unlock()
	if fresh {
		r.logInbound(&q)
		r.logConnection(q, o.Tag, nil, nil)
	}
	n, err := d.conn.WriteTo(data, net.UDPAddrFromAddrPort(target))
	r.up.Add(int64(n))
	return err
}
