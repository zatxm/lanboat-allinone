package native

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

func mkcpReferencePair(t *testing.T, kind, header, envelope, side string) *Runtime {
	t.Helper()
	in := testInbound(t, kind)
	o := &MKCPOptions{PacketEncoding: envelope}
	o.Header.Type = header
	var masks []any
	if header != "none" {
		h := header
		if h == "wechat-video" {
			h = "wechat"
		}
		masks = append(masks, map[string]any{"type": "header-" + h, "settings": map[string]any{"domain": "www.example.com"}})
	}
	if envelope == "seed" {
		seed := "独立mKCP"
		o.PacketEncoding = "legacy"
		o.Seed = &seed
		masks = append(masks, map[string]any{"type": "mkcp-aes128gcm", "settings": map[string]any{"password": seed}})
	} else if envelope == "legacy" {
		masks = append(masks, map[string]any{"type": "mkcp-original"})
	}
	in.Transport = Transport{Type: "mkcp", KCP: o}
	stream := map[string]any{"network": "kcp", "kcpSettings": map[string]any{"mtu": 1350, "tti": 50, "uplinkCapacity": 5, "downlinkCapacity": 20}, "finalmask": map[string]any{"udp": masks}}
	if in.TLS.Enabled {
		stream["security"] = "tls"
		stream["tlsSettings"] = map[string]any{"certificates": []any{map[string]any{"certificate": in.TLS.Certificate, "key": in.TLS.Key}}}
	}
	cfg := map[string]any{"log": map[string]any{"loglevel": "warning"}}
	if side == "client" {
		port := unusedPort(t)
		ready := unusedPort(t, port)
		cfg["inbounds"] = []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": kind, "settings": xhttpXraySettings(in, port, false), "streamSettings": stream}, map[string]any{"listen": "127.0.0.1", "port": ready, "protocol": "socks", "settings": map[string]any{}}}
		cfg["outbounds"] = []any{map[string]any{"protocol": "freedom"}}
		xrayMuxReference(t, cfg, ready)
		out := testOutbound(t, in, portAddress("127.0.0.1", port))
		out.Transport = in.Transport
		return newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	port := unusedPort(t)
	out := testOutbound(t, in, s.Address("server"))
	if in.TLS.Enabled {
		block, _ := pem.Decode([]byte(in.TLS.Certificate[0]))
		pin := sha256.Sum256(block.Bytes)
		stream["tlsSettings"] = map[string]any{"serverName": "example.com", "pinnedPeerCertSha256": hex.EncodeToString(pin[:])}
	}
	cfg["inbounds"] = []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"udp": true}}}
	cfg["outbounds"] = []any{map[string]any{"protocol": kind, "settings": xhttpXraySettings(in, out.ServerPort, true), "streamSettings": stream}}
	xrayMuxReference(t, cfg, port)
	return newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "front", Server: "127.0.0.1", ServerPort: port}}})
}

func TestMKCPReference(t *testing.T) {
	for _, header := range []string{"none", "srtp", "utp", "wechat-video", "dtls", "wireguard", "dns"} {
		for _, envelope := range []string{"legacy", "seed", "raw"} {
			for _, side := range []string{"client", "server"} {
				t.Run(header+"/"+envelope+"/"+side, func(t *testing.T) {
					c := mkcpReferencePair(t, "vless", header, envelope, side)
					assertTCP(t, c)
					assertUDPSizes(t, c, []int{1, 511, 4096})
				})
			}
		}
	}
}

func TestMKCPReferenceProtocols(t *testing.T) {
	for _, kind := range []string{"vmess", "trojan", "shadowsocks"} {
		for _, side := range []string{"client", "server"} {
			t.Run(kind+"/"+side, func(t *testing.T) {
				c := mkcpReferencePair(t, kind, "dns", "seed", side)
				assertTCP(t, c)
				if kind != "shadowsocks" {
					assertUDPSizes(t, c, []int{1, 4096})
				}
			})
		}
	}
}
