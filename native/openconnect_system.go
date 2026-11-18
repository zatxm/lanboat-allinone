package native

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

func (o OpenConnectOptions) routeHeaders() http.Header {
	// Official clients compare the X-CSTP prefix literally despite HTTP casing rules.
	return http.Header{"X-CSTP-Split-Include": o.SplitInclude, "X-CSTP-Split-Exclude": o.SplitExclude}
}

// Servers use both CIDR lengths and dotted IPv4 netmasks on the wire.
func ocRoutePrefix(text string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(text)
	if err != nil {
		host, mask, ok := strings.Cut(text, "/")
		ip, ie := netip.ParseAddr(host)
		m, me := netip.ParseAddr(mask)
		if ok && ie == nil && me == nil && ip.Is4() && m.Is4() {
			ones, bits := net.IPMask(m.AsSlice()).Size()
			if bits == 32 {
				p, err = netip.PrefixFrom(ip, ones), nil
			}
		}
	}
	if err != nil || p.Addr().Is4In6() || p.Addr().Zone() != "" || p.Addr().IsMulticast() {
		return netip.Prefix{}, errors.New("invalid OpenConnect split route")
	}
	return p.Masked(), nil
}

func ocParseRoutes(h http.Header) (include, exclude []string, err error) {
	count := 0
	for name, values := range h {
		key := strings.ToLower(name)
		if key != "x-cstp-split-include" && key != "x-cstp-split-exclude" && key != "x-cstp-split-include-ip6" && key != "x-cstp-split-exclude-ip6" {
			continue
		}
		for _, value := range values {
			if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
				return nil, nil, errors.New("invalid OpenConnect split route header")
			}
			before := count
			for _, text := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
				count++
				if count > 128 || len(text) > 80 {
					return nil, nil, errors.New("OpenConnect split routes exceed limit")
				}
				p, e := ocRoutePrefix(text)
				if e != nil {
					return nil, nil, e
				}
				if strings.Contains(key, "include") {
					include = append(include, p.String())
				} else {
					exclude = append(exclude, p.String())
				}
			}
			if count == before {
				return nil, nil, errors.New("empty OpenConnect split route")
			}
		}
	}
	slices.Sort(include)
	slices.Sort(exclude)
	return slices.Compact(include), slices.Compact(exclude), nil
}

var ocInterfaceID atomic.Uint32

func (t *ocTunnel) systemConfig(o Outbound, headers http.Header, mtu int) (Inbound, error) {
	include, exclude, err := ocParseRoutes(headers)
	if err != nil {
		return Inbound{}, err
	}
	name := o.Name
	if name == "" && runtime.GOOS == "linux" {
		name = "oc%d"
	} else if name == "" && runtime.GOOS != "darwin" {
		name = fmt.Sprintf("oc%d", ocInterfaceID.Add(1))
	}
	in := Inbound{Type: "tun", Tag: o.Tag, InterfaceName: name, MTU: mtu, DNSMode: "disabled", AutoRoute: true, exclusiveTUN: true, endpointSystem: true, RouteAddress: include, RouteExcludeAddress: exclude}
	for _, ip := range t.local {
		if ip.Is6() && mtu < 1280 {
			return in, errors.New("OpenConnect IPv6 system interface requires MTU1280 or greater")
		}
		// Point-to-point assignments must not create an implicit connected subnet.
		in.Address = append(in.Address, netip.PrefixFrom(ip, ip.BitLen()).String())
	}
	if len(tunRoutePrefixes(in)) > 4096 {
		return in, errors.New("OpenConnect expanded split routes exceed limit")
	}
	return in, nil
}

func (t *ocTunnel) openSystem(o Outbound, headers http.Header, mtu int) error {
	in, err := t.systemConfig(o, headers, mtu)
	if err != nil {
		return err
	}
	if in.InterfaceName != "" {
		if _, err = net.InterfaceByName(in.InterfaceName); err == nil {
			return errors.New("OpenConnect system interface already exists")
		}
	}
	s, err := openTUN(t.r, in)
	if err != nil {
		return fmt.Errorf("OpenConnect system interface: %w", err)
	}
	s.ctx, s.cancel = context.WithCancel(t.ctx)
	if err = s.configureMonitor(); err != nil {
		s.close()
		return err
	}
	t.system = s
	t.stack.peer.reservePort = reserveSystemPort
	t.stack.peer.rawInput = func(p tunPacket) bool {
		_ = s.writePacket(p.data)
		return true
	}
	return nil
}

func (t *ocTunnel) startSystem() {
	s := t.system
	if s == nil {
		return
	}
	routes := s.routePlan(s.in)
	t.systemWorkers.Add(1)
	if s.monitor != nil {
		s.networkKey = s.physicalNetworkKey()
		t.systemWorkers.Add(2)
	}
	go func() {
		defer t.systemWorkers.Done()
		defer t.close()
		buffer := make([]byte, 65575)
		fragments := tunFragments{}
		for {
			n, err := s.device.Read(buffer)
			if err != nil {
				return
			}
			p, err := parseTunPacket(buffer[:n])
			if err != nil || !slices.Contains(t.local, p.source) || !slices.ContainsFunc(routes, func(r netip.Prefix) bool { return r.Contains(p.destination) }) {
				continue
			}
			// The kernel MTU can exceed DTLS's payload MTU. Reassemble before
			// re-fragmenting, preserving IPv4 offsets and avoiding nested IPv6 fragments.
			packet, err := fragments.assemble(p)
			if err != nil || packet == nil {
				continue
			}
			if err = t.stack.peer.sendIP(packet); err != nil {
				return
			}
		}
	}()
	if s.monitor != nil {
		go func() { defer t.systemWorkers.Done(); s.monitor() }()
		go func() {
			defer t.systemWorkers.Done()
			for {
				select {
				case <-t.done:
					return
				case <-s.networkEvents:
					s.platformMu.Lock()
					err := s.refreshEgress()
					changed := err == nil && s.physicalNetworkKey() != s.networkKey
					s.platformMu.Unlock()
					if changed {
						t.close()
						return
					}
				}
			}
		}()
	}
}

// Reserve API ports in the kernel so host sockets cannot steal their replies.
func reserveSystemPort(network string, ip netip.Addr) (io.Closer, uint16, error) {
	if network == "udp" {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IP(ip.AsSlice())})
		if err != nil {
			return nil, 0, err
		}
		return c, uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
	}
	c, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IP(ip.AsSlice())})
	if err != nil {
		return nil, 0, err
	}
	return c, uint16(c.Addr().(*net.TCPAddr).Port), nil
}

func (c *ocClient) runSystem() {
	retry := time.Second
	for {
		t, err := c.session(c.r.ctx)
		if err != nil {
			if c.r.ctx.Err() != nil {
				return
			}
			logWarn(c.r.logger, err, c.r.outboundLabel(c.o.Tag), ": connection failed")
			if ocSystemRetryable(err) {
				if !c.waitSystemRetry(retry) {
					return
				}
				retry = min(2*retry, 30*time.Second)
			} else {
				// Failed authentication requires an explicit retry, never an account-lockout loop.
				select {
				case <-c.r.ctx.Done():
					return
				case <-c.wake:
				}
			}
			continue
		}
		retry = time.Second
		// Consume this session's notification; subsequent explicit logins can wake us.
		select {
		case <-c.wake:
		default:
		}
		select {
		case <-c.r.ctx.Done():
			return
		case <-t.finished:
		}
		if !c.waitSystemRetry(time.Second) {
			return
		}
	}
}

func ocSystemRetryable(err error) bool {
	var operation *net.OpError
	var dns *net.DNSError
	// Only retry before authentication data could have reached the gateway.
	return errors.As(err, &operation) && operation.Op == "dial" || errors.As(err, &dns)
}

func (c *ocClient) waitSystemRetry(delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-c.r.ctx.Done():
		return false
	case <-c.wake:
		return true
	case <-timer.C:
		return true
	}
}
