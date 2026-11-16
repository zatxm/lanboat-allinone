package native

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"testing"
)

func xhttpXraySettings(in Inbound, port uint16, client bool) map[string]any {
	settings := map[string]any{}
	if in.Type == "vless" || in.Type == "vmess" {
		user := map[string]any{"id": testUUID}
		if in.Type == "vless" {
			if client {
				user["encryption"] = "none"
			} else {
				settings["decryption"] = "none"
			}
		} else if client {
			user["security"] = "auto"
		}
		if client {
			settings["vnext"] = []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{user}}}
		} else {
			settings["clients"] = []any{user}
		}
	} else if client {
		server := map[string]any{"address": "127.0.0.1", "port": port, "password": "private"}
		if in.Type == "shadowsocks" {
			server["method"] = in.Method
		}
		settings["servers"] = []any{server}
	} else if in.Type == "trojan" {
		settings["clients"] = []any{map[string]any{"password": "private"}}
	} else {
		settings["method"] = in.Method
		settings["password"] = "private"
	}
	return settings
}
func xhttpReferencePair(t *testing.T, kind, mode string, version int, side string, x XHTTPOptions, extra map[string]any) *Runtime {
	t.Helper()
	in := testInbound(t, kind)
	x.Mode = mode
	in.Transport = Transport{Type: "xhttp", Path: "/native-xhttp", XHTTPOptions: x}
	stream := map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": "/native-xhttp", "mode": mode, "extra": extra}}
	if version > 1 {
		in.TLS = certificate(t)
		alpn := []string{"h2"}
		if version == 3 {
			alpn = []string{"h3"}
			in.TLS.ALPN = alpn
		}
		stream["security"] = "tls"
		stream["tlsSettings"] = map[string]any{"alpn": alpn, "certificates": []any{map[string]any{"certificate": in.TLS.Certificate, "key": in.TLS.Key}}}
	} else {
		in.TLS = TLSOptions{}
	}
	cfg := map[string]any{"log": map[string]any{"loglevel": "warning"}}
	if side == "client" {
		port := unusedPort(t)
		ready := unusedPort(t, port)
		cfg["inbounds"] = []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": kind, "settings": xhttpXraySettings(in, port, false), "streamSettings": stream}, map[string]any{"listen": "127.0.0.1", "port": ready, "protocol": "socks", "settings": map[string]any{}}}
		cfg["outbounds"] = []any{map[string]any{"protocol": "freedom"}}
		xrayMuxReference(t, cfg, ready)
		o := testOutbound(t, in, portAddress("127.0.0.1", port))
		o.Transport = in.Transport
		if version == 3 {
			o.TLS.ALPN = []string{"h3"}
		}
		return newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	// Pick the subprocess port after the native listener binds its automatic port.
	port := unusedPort(t)
	o := testOutbound(t, in, s.Address("server"))
	settings := xhttpXraySettings(in, o.ServerPort, true)
	if version > 1 {
		block, _ := pem.Decode([]byte(in.TLS.Certificate[0]))
		pin := sha256.Sum256(block.Bytes)
		stream["tlsSettings"] = map[string]any{"alpn": []string{"h2"}, "serverName": "example.com", "pinnedPeerCertSha256": hex.EncodeToString(pin[:])}
		if version == 3 {
			stream["tlsSettings"].(map[string]any)["alpn"] = []string{"h3"}
		}
	}
	cfg["inbounds"] = []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"udp": true}}}
	cfg["outbounds"] = []any{map[string]any{"protocol": kind, "settings": settings, "streamSettings": stream}}
	xrayMuxReference(t, cfg, port)
	return newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "front", Server: "127.0.0.1", ServerPort: port}}})
}
func TestXHTTPReference(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		for _, mode := range []string{"auto", "packet-up", "stream-up", "stream-one"} {
			for _, side := range []string{"client", "server"} {
				t.Run(fmt.Sprintf("h%d/%s/%s", version, mode, side), func(t *testing.T) {
					c := xhttpReferencePair(t, "vless", mode, version, side, XHTTPOptions{}, map[string]any{})
					assertTCP(t, c)
					assertUDPSizes(t, c, []int{1, 511, 1400})
				})
			}
		}
	}
}
func TestXHTTPReferencePlacements(t *testing.T) {
	for _, place := range []string{"query", "header", "cookie"} {
		for _, side := range []string{"client", "server"} {
			t.Run(place+"/"+side, func(t *testing.T) {
				x := XHTTPOptions{SessionPlacement: place, SeqPlacement: place, UplinkDataPlacement: place, ScMinPostsIntervalMs: "0"}
				if place == "query" {
					x.UplinkDataPlacement = "body"
				}
				extra := map[string]any{"sessionPlacement": place, "seqPlacement": place, "uplinkDataPlacement": x.UplinkDataPlacement, "scMinPostsIntervalMs": 0}
				c := xhttpReferencePair(t, "vless", "packet-up", 2, side, x, extra)
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{1, 1400})
			})
		}
	}
	for _, place := range []string{"queryInHeader", "header", "query", "cookie"} {
		for _, side := range []string{"client", "server"} {
			t.Run("padding/"+place+"/"+side, func(t *testing.T) {
				x := XHTTPOptions{XPaddingObfsMode: true, XPaddingPlacement: place, XPaddingKey: "custom_pad", XPaddingHeader: "X-Pad", XPaddingMethod: "tokenish", XPaddingBytes: "100-101"}
				extra := map[string]any{"xPaddingObfsMode": true, "xPaddingPlacement": place, "xPaddingKey": "custom_pad", "xPaddingHeader": "X-Pad", "xPaddingMethod": "tokenish", "xPaddingBytes": "100-101"}
				c := xhttpReferencePair(t, "vless", "stream-one", 2, side, x, extra)
				assertTCP(t, c)
			})
		}
	}
}
func TestXHTTPReferenceProtocols(t *testing.T) {
	for _, kind := range []string{"vmess", "trojan", "shadowsocks"} {
		for _, side := range []string{"client", "server"} {
			t.Run(kind+"/"+side, func(t *testing.T) {
				c := xhttpReferencePair(t, kind, "stream-one", 2, side, XHTTPOptions{}, map[string]any{})
				assertTCP(t, c)
				if kind != "shadowsocks" {
					assertUDPSizes(t, c, []int{1, 1400})
				}
			})
		}
	}
}

func TestXHTTPReferenceMethods(t *testing.T) {
	for _, method := range []string{"PUT", "GET"} {
		for _, side := range []string{"client", "server"} {
			t.Run(method+"/"+side, func(t *testing.T) {
				x := XHTTPOptions{UplinkHTTPMethod: method, ScMinPostsIntervalMs: "0"}
				if method == "GET" {
					x.UplinkDataPlacement = "header"
				}
				placement := "body"
				if method == "GET" {
					placement = "header"
				}
				c := xhttpReferencePair(t, "vless", "packet-up", 2, side, x, map[string]any{"uplinkHTTPMethod": method, "uplinkDataPlacement": placement, "scMinPostsIntervalMs": 0})
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{1, 1400})
			})
		}
	}
}

func TestXHTTPReferencePaddingDefaults(t *testing.T) {
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			c := xhttpReferencePair(t, "vless", "packet-up", 2, side, XHTTPOptions{XPaddingObfsMode: true}, map[string]any{"xPaddingObfsMode": true})
			assertTCP(t, c)
		})
	}
}
