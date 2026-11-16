package native

import "testing"

func TestMultipleProtocolInbounds(t *testing.T) {
	var inbounds []Inbound
	for _, kind := range []string{"socks", "shadowsocks", "trojan"} {
		in := testInbound(t, kind)
		in.Tag = kind
		inbounds = append(inbounds, in)
	}
	server := newTestRuntime(t, Config{Inbounds: inbounds})
	addresses := map[string]bool{}
	for _, in := range inbounds {
		t.Run(in.Tag, func(t *testing.T) {
			address := server.Address(in.Tag)
			if address == "" || addresses[address] {
				t.Fatal("inbounds must have separate listening ports", address)
			}
			addresses[address] = true
			client := newTestRuntime(t, Config{Outbounds: []Outbound{testOutbound(t, in, address)}})
			assertTCP(t, client)
			assertUDP(t, client)
		})
	}
}
