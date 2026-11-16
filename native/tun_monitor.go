package native

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
)

// Coalesce pending link/address/route notifications without polling.
func (t *tunTunnel) watchNetwork(read func() error, events chan<- struct{}) {
	for {
		if read() != nil {
			return
		}
		select {
		case events <- struct{}{}:
		default:
		}
	}
}
func (t *tunTunnel) refreshNetworkDNS() {
	if t.namespace != nil {
		t.refreshNamespaceAddresses()
		return
	}
	servers := systemDNSBeforeTUN()
	dns := t.dnsAddresses()
	servers = slices.DeleteFunc(servers, func(v string) bool { host, _, _ := net.SplitHostPort(v); return slices.Contains(dns, host) })
	r := t.runtime.resolver
	r.mu.Lock()
	r.systemServers = servers
	r.mu.Unlock()
	r.localNetwork.invalidate()
	t.runtime.network.invalidate()
	var addresses []netip.Addr
	if all, e := net.InterfaceAddrs(); e == nil {
		for _, a := range all {
			if p, e := netip.ParsePrefix(a.String()); e == nil {
				addresses = append(addresses, p.Addr())
			}
		}
	}
	t.hostMu.Lock()
	t.hostAddresses = addresses
	t.hostMu.Unlock()
}

func (t *tunTunnel) physicalNetworkKey() string {
	if t.namespace != nil {
		return t.namespaceNetworkKey()
	}
	var parts []string
	all, _ := net.Interfaces()
	for _, iface := range all {
		if iface.Name == t.name || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, a := range addresses {
			parts = append(parts, fmt.Sprintf("%d/%s/%s", iface.Index, iface.Name, a))
		}
	}
	parts = append(parts, fmt.Sprintf("%d/%d/%d/%d", t.runtime.tunEgress4.Load(), t.runtime.tunEgress6.Load(), t.runtime.tunGateway4.Load(), t.runtime.tunGateway6.Load()))
	if runtime.GOOS == "linux" {
		for _, path := range []string{"/proc/net/route", "/proc/net/ipv6_route"} {
			f, e := os.Open(path)
			if e != nil {
				continue
			}
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				v := strings.Fields(scanner.Text())
				if len(v) >= 10 && strings.HasSuffix(path, "ipv6_route") {
					if v[1] == "00" && v[0] == strings.Repeat("0", 32) && v[9] != t.name && v[9] != "lo" {
						parts = append(parts, strings.Join([]string{v[9], v[4], v[5]}, "/"))
					}
				} else if len(v) >= 8 && v[1] == "00000000" && v[7] == "00000000" && v[0] != t.name && v[0] != "lo" {
					parts = append(parts, strings.Join([]string{v[0], v[2], v[6]}, "/"))
				}
			}
			f.Close()
		}
	}
	slices.Sort(parts)
	return strings.Join(parts, "\n")
}

// Reset reusable outbound sessions after the physical network changes. A new
// stream must not inherit a cached socket still bound to the previous interface.
func (r *Runtime) resetNetworkTransports() {
	for _, client := range r.genericMuxClients {
		client.reset()
	}
	for _, p := range r.cloakClients {
		p.reset()
	}
	for _, p := range r.cloakServers {
		p.reset()
	}
	for _, c := range r.kcpClients {
		c.reset()
	}
	r.closeKCP(true)
	r.closeMKCP(true)
	for _, c := range r.mieruClients {
		c.reset()
	}
	for _, c := range r.xhttpClients {
		c.reset()
	}
	for _, c := range r.ocClients {
		c.reset()
	}
	for _, c := range r.masqueClients {
		c.reset()
	}
	for _, c := range r.trojanMuxClients {
		c.reset()
	}
	for _, c := range r.sudokuMuxClients {
		c.reset()
	}
	for _, c := range r.sudokuReverseClients {
		c.reset()
	}
	for _, c := range r.proxyMuxClients {
		c.reset()
	}
	for _, c := range r.trustClients {
		c.reset()
	}
	for _, c := range r.quicClients {
		c.close()
	}
	for _, c := range r.quicTransports {
		c.close()
	}
	for _, e := range r.wgEndpoints {
		e.reset(true)
	}
	for _, c := range r.wgClients {
		c.close()
	}
	for _, c := range r.sshClients {
		c.close()
	}
	for _, c := range r.anyClients {
		c.stopSessions(false)
	}
	for _, c := range r.snellClients {
		c.clear(false)
	}
	for _, c := range r.httpClients {
		c.CloseIdleConnections()
	}
	dns := r.resolver
	for _, c := range dns.quicDNS {
		c.close()
	}
	for _, c := range dns.clients {
		c.CloseIdleConnections()
	}
	if dns.http != nil {
		dns.http.CloseIdleConnections()
	}
}

func tunGatewayKey(address []byte) uint64 {
	var sum uint64 = 14695981039346656037
	for _, b := range address {
		sum ^= uint64(b)
		sum *= 1099511628211
	}
	return sum
}
