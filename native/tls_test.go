package native

import (
	"context"
	"testing"
)

func TestTLSCertificateVerification(t *testing.T) {
	for _, kind := range []string{"socks", "http", "vless", "vmess", "trojan", "anytls", "relay"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, kind)
			in.TLS = certificate(t)
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.TLS = TLSOptions{Enabled: true, ServerName: "example.com", Certificate: in.TLS.Certificate}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			if kind != "http" {
				assertUDPSizes(t, client, []int{1, 511, 4096})
			}
			out.TLS.ServerName = "wrong-certificate.example"
			wrong := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			c, err := wrong.Dial(context.Background(), "tcp", "example.com:443")
			if err == nil {
				c.Close()
				t.Fatal("TLS hostname mismatch was accepted")
			}
		})
	}
}
