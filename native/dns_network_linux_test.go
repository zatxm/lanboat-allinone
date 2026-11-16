//go:build linux

package native

import (
	"net/netip"
	"testing"
)

func TestDNSNetworkPreMatch(t *testing.T) {
	r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "local", Tag: "system"}}}, Route: Route{Rules: []Rule{{DNSSearchDomain: map[string][]string{"system": {"corp.example"}}, Action: "reject", Method: "drop"}}}})
	r.resolver.localNetwork.read = func() dnsNetworkState { return dnsNetworkState{domains: []string{"corp.example"}} }
	tunnel := &tunTunnel{runtime: r}
	packet := makeUDPPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("203.0.113.9"), 12345, 443, []byte("network snapshot"))
	if _, drop := tunnel.preMatchPacket(packet); !drop {
		t.Fatal("TUN pre-match ignored DNS network condition")
	}
	r.resolver.localNetwork.mu.Lock()
	r.resolver.localNetwork.read = func() dnsNetworkState { return dnsNetworkState{} }
	r.resolver.localNetwork.mu.Unlock()
	r.resolver.localNetwork.invalidate()
	if _, drop := tunnel.preMatchPacket(packet); drop {
		t.Fatal("TUN pre-match retained withdrawn DNS configuration")
	}
}
