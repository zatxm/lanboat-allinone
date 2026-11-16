package native

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

type dhcpDNSKey struct{}
type dhcpDNSState struct {
	servers []netip.Addr
	domains []string
	key     string
	until   time.Time
}
type dhcpDNSPath struct {
	iface net.Interface
	local netip.Addr
	key   string
}
type dhcpDNSDiscovery struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int
	state   dhcpDNSState
	err     error
}
type dhcpDNSClient struct {
	resolver *resolver
	mu       sync.Mutex
	pathKey  string
	state    dhcpDNSState
	pending  *dhcpDNSDiscovery
	workers  sync.WaitGroup
	closed   bool
}

func validateDHCPDNS(s DNSServer) error {
	if !reflect.DeepEqual(s, DNSServer{Type: s.Type, Tag: s.Tag, Interfaces: s.Interfaces, Detour: s.Detour, DomainResolver: s.DomainResolver}) {
		return errors.New("DHCP DNS discovers upstreams on its interface;server,TLS and unrelated options are not applicable")
	}
	if len(s.Interfaces) > 1 || len(s.Interfaces) == 1 && (len(s.Interfaces[0]) > 128 || strings.ContainsAny(s.Interfaces[0], "/\\\x00\r\n")) {
		return errors.New("DHCP DNS interface must be one interface name or empty for the default route")
	}
	return nil
}

func (r *resolver) dhcpPath(ctx context.Context, names []string) (dhcpDNSPath, error) {
	name := ""
	if len(names) == 1 {
		name = names[0]
	}
	if name == "" && r.runtime != nil {
		if r.runtime.config.Route.DefaultInterface != "" && !r.runtime.config.Route.AutoDetectInterface {
			name = r.runtime.config.Route.DefaultInterface
		} else if index := r.runtime.tunEgress4.Load(); index != 0 {
			iface, err := net.InterfaceByIndex(int(index))
			if err != nil {
				return dhcpDNSPath{}, err
			}
			name = iface.Name
		}
	}
	var routeIP netip.Addr
	if name == "" {
		// UDP connect performs a route lookup only; no packet is sent.
		dialer := net.Dialer{}
		if r.runtime != nil {
			dialer.Control = r.runtime.socketControl
		}
		c, err := dialer.DialContext(ctx, "udp4", "192.0.2.1:9")
		if err != nil {
			return dhcpDNSPath{}, fmt.Errorf("DHCP default IPv4 route: %w", err)
		}
		routeIP = c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
		c.Close()
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return dhcpDNSPath{}, err
	}
	for _, iface := range interfaces {
		if name != "" && iface.Name != name {
			continue
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) != 6 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return dhcpDNSPath{}, err
		}
		var local netip.Addr
		var prefixes []string
		for _, addr := range addresses {
			p, err := netip.ParsePrefix(addr.String())
			if err != nil || !p.Addr().Is4() || !p.Addr().IsGlobalUnicast() {
				continue
			}
			prefixes = append(prefixes, p.String())
			if !local.IsValid() || p.Addr() == routeIP {
				local = p.Addr()
			}
		}
		if !local.IsValid() || routeIP.IsValid() && local != routeIP {
			continue
		}
		slices.Sort(prefixes)
		return dhcpDNSPath{iface: iface, local: local, key: fmt.Sprintf("%s/%d/%s/%s/%v", iface.Name, iface.Index, iface.HardwareAddr, local, prefixes)}, nil
	}
	return dhcpDNSPath{}, errors.New("DHCP DNS requires an active Ethernet/Wi-Fi interface with an IPv4 address")
}

func (c *dhcpDNSClient) snapshot(ctx context.Context, names []string) (dhcpDNSState, error) {
	path, err := c.resolver.dhcpPath(ctx, names)
	if err != nil {
		return dhcpDNSState{}, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return dhcpDNSState{}, net.ErrClosed
	}
	if c.pathKey == path.key && time.Now().Before(c.state.until) {
		state := c.state
		c.mu.Unlock()
		return state, nil
	}
	if c.pending != nil && c.pathKey != path.key {
		c.pending.cancel()
		c.pending = nil
	}
	if c.pathKey != path.key {
		c.state = dhcpDNSState{}
	}
	p := c.pending
	if p == nil {
		call, cancel := context.WithTimeout(c.resolver.ctx, 5*time.Second)
		p = &dhcpDNSDiscovery{done: make(chan struct{}), cancel: cancel}
		c.pending, c.pathKey = p, path.key
		c.workers.Add(1)
		go func() {
			defer c.workers.Done()
			defer cancel()
			state, err := c.resolver.discoverDHCP(call, path)
			c.mu.Lock()
			p.state, p.err = state, err
			if c.pending == p {
				c.pending = nil
				if err == nil {
					c.state = state
				}
			}
			close(p.done)
			c.mu.Unlock()
		}()
	}
	p.waiters++
	c.mu.Unlock()
	select {
	case <-p.done:
		if p.err != nil {
			return dhcpDNSState{}, p.err
		}
		return p.state, nil
	case <-ctx.Done():
		c.mu.Lock()
		p.waiters--
		if p.waiters == 0 && c.pending == p {
			c.pending = nil
			p.cancel()
		}
		c.mu.Unlock()
		return dhcpDNSState{}, ctx.Err()
	}
}

func (c *dhcpDNSClient) close() {
	c.mu.Lock()
	c.closed = true
	if c.pending != nil {
		c.pending.cancel()
	}
	c.mu.Unlock()
	c.workers.Wait()
}

func dhcpDiscover(mac net.HardwareAddr) ([]byte, error) {
	query := make([]byte, 300)
	query[0], query[1], query[2], query[10] = 1, 1, 6, 128
	if _, err := rand.Read(query[4:8]); err != nil {
		return nil, err
	}
	copy(query[28:44], mac)
	copy(query[236:], []byte{99, 130, 83, 99, 53, 1, 1, 55, 3, 6, 15, 119, 255})
	return query, nil
}

func (r *resolver) discoverDHCP(ctx context.Context, path dhcpDNSPath) (dhcpDNSState, error) {
	query, err := dhcpDiscover(path.iface.HardwareAddr)
	if err != nil {
		return dhcpDNSState{}, err
	}
	var mark uint32
	if r.runtime != nil {
		mark = r.runtime.protectMark.Load()
		if mark == 0 {
			mark = uint32(r.runtime.config.Route.DefaultMark)
		}
	}
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var err error
		if e := raw.Control(func(fd uintptr) { err = dhcpSocketOptions(fd, path, mark) }); e != nil {
			return e
		}
		return err
	}}
	packets, err := lc.ListenPacket(ctx, "udp4", "0.0.0.0:68")
	if err != nil {
		return dhcpDNSState{}, fmt.Errorf("DHCP discovery socket: %w", err)
	}
	defer packets.Close()
	stop := context.AfterFunc(ctx, func() { packets.Close() })
	defer stop()
	conn := packets.(*net.UDPConn)
	buffer := make([]byte, 4096)
	started := time.Now()
	var sent time.Time
	for {
		if ctx.Err() != nil {
			return dhcpDNSState{}, ctx.Err()
		}
		if time.Since(sent) >= time.Second {
			binary.BigEndian.PutUint16(query[8:10], uint16(min(65535, time.Since(started)/time.Second)))
			if _, err := conn.WriteToUDPAddrPort(query, netip.MustParseAddrPort("255.255.255.255:67")); err != nil {
				return dhcpDNSState{}, err
			}
			sent = time.Now()
		}
		conn.SetReadDeadline(sent.Add(time.Second))
		n, peer, err := conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return dhcpDNSState{}, err
		}
		if peer.Port() != 67 || !peer.Addr().IsGlobalUnicast() || n == len(buffer) {
			continue
		}
		state, err := dhcpOffer(query, buffer[:n])
		if err != nil {
			continue
		}
		state.key = path.key + ":" + dnsNetworkKey(dnsNetworkState{addresses: state.servers, domains: state.domains})
		state.until = time.Now().Add(5 * time.Minute)
		return state, nil
	}
}

func dhcpOffer(query, offer []byte) (dhcpDNSState, error) {
	var state dhcpDNSState
	if len(query) < 44 || len(offer) < 240 || len(offer) > 4096 || offer[0] != 2 || offer[1] != 1 || offer[2] != 6 || !bytes.Equal(query[4:8], offer[4:8]) || !bytes.Equal(query[28:34], offer[28:34]) || !bytes.Equal(offer[236:240], []byte{99, 130, 83, 99}) {
		return state, errors.New("invalid DHCP offer identity")
	}
	options := map[byte][]byte{}
	parse := func(wire []byte, overloaded bool) error {
		for len(wire) > 0 {
			code := wire[0]
			wire = wire[1:]
			if code == 255 {
				return nil
			}
			if code == 0 {
				continue
			}
			if len(wire) < 1 || int(wire[0]) > len(wire)-1 {
				return errors.New("truncated DHCP option")
			}
			n := int(wire[0])
			data := wire[1 : n+1]
			wire = wire[n+1:]
			if overloaded && code == 52 {
				return errors.New("recursive DHCP overload")
			}
			switch code {
			case 6, 15, 53, 54, 119:
				options[code] = append(options[code], data...)
			case 52:
				if len(data) != 1 || data[0] < 1 || data[0] > 3 || options[52] != nil {
					return errors.New("invalid DHCP option overload")
				}
				options[52] = bytes.Clone(data)
			}
		}
		return errors.New("DHCP options missing end marker")
	}
	if err := parse(offer[240:], false); err != nil {
		return state, err
	}
	if overload := options[52]; len(overload) != 0 {
		if overload[0]&1 != 0 {
			if err := parse(offer[108:236], true); err != nil {
				return state, err
			}
		}
		if overload[0]&2 != 0 {
			if err := parse(offer[44:108], true); err != nil {
				return state, err
			}
		}
	}
	if !bytes.Equal(options[53], []byte{2}) || len(options[54]) != 4 {
		return state, errors.New("DHCP response must be an offer with server identifier")
	}
	server := netip.AddrFrom4([4]byte(options[54]))
	if !server.IsGlobalUnicast() {
		return state, errors.New("invalid DHCP server identifier")
	}
	addresses := options[6]
	if len(addresses) == 0 || len(addresses)%4 != 0 || len(addresses) > 256 {
		return state, errors.New("invalid DHCP DNS server option")
	}
	for len(addresses) != 0 {
		ip := netip.AddrFrom4([4]byte(addresses[:4]))
		addresses = addresses[4:]
		if !ip.IsGlobalUnicast() {
			return state, errors.New("invalid DHCP DNS address")
		}
		if !slices.Contains(state.servers, ip) {
			state.servers = append(state.servers, ip)
		}
	}
	if search := options[119]; len(search) != 0 {
		for offset := 0; offset < len(search); {
			name, end, err := dnsName(search, offset)
			if err != nil || end <= offset || !masqueDomain(name, false) {
				return state, errors.New("invalid DHCP search domain")
			}
			state.domains = append(state.domains, name)
			offset = end
		}
	} else if domain := options[15]; len(domain) != 0 {
		name := strings.TrimSuffix(strings.ToLower(string(domain)), ".")
		if !masqueDomain(name, false) {
			return state, errors.New("invalid DHCP domain name")
		}
		state.domains = []string{name}
	}
	return state, nil
}

func (r *resolver) exchangeDHCP(ctx context.Context, s DNSServer, query []byte) ([]byte, error) {
	state, ok := ctx.Value(dhcpDNSKey{}).(dhcpDNSState)
	if !ok {
		var err error
		state, err = r.dhcp[s.Tag].snapshot(ctx, s.Interfaces)
		if err != nil {
			return nil, err
		}
	}
	var last error
	for i, ip := range state.servers {
		call, cancel := ctx, func() {}
		if deadline, ok := ctx.Deadline(); ok {
			call, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(state.servers)-i))
		}
		reply, err := r.exchangeOn(call, DNSServer{Type: "udp", Server: ip.String(), Detour: s.Detour}, query)
		cancel()
		if err == nil {
			_, _, _, err = validateDNSQuestionResponse(query, reply)
		}
		if err == nil {
			return reply, nil
		}
		last = err
	}
	return nil, last
}
