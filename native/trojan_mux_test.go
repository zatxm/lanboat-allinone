package native

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestTrojanMuxIndependent(t *testing.T) {
	for _, transport := range []string{"", "ws", "httpupgrade", "http", "grpc"} {
		for _, encrypted := range []bool{false, true} {
			t.Run(fmt.Sprint(transport, "/", encrypted), func(t *testing.T) {
				in := testInbound(t, "trojan")
				in.Transport = Transport{Type: transport}
				if encrypted {
					in.Shadowsocks = trojanSSOptions("aes-128-gcm")
				}
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out := testOutbound(t, in, server.Address("server"))
				out.Transport, out.Shadowsocks = in.Transport, in.Shadowsocks
				out.Multiplex.Enabled = true
				out.Multiplex.Protocol = "trojan-go"
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, client)
				s := client.trojanMuxClients["proxy"].current
				assertUDPSizes(t, client, []int{0, 1, 511, 4096, 60000})
				assertTCP(t, client)
				if client.trojanMuxClients["proxy"].current != s {
					t.Fatal("session not reused")
				}
				client.resetNetworkTransports()
				assertTCP(t, client)
				if client.trojanMuxClients["proxy"].current == s {
					t.Fatal("network reset reused closed session")
				}
			})
		}
	}
}

func TestTrojanMuxReference(t *testing.T) {
	for _, transport := range []string{"", "ws"} {
		for _, encrypted := range []bool{false, true} {
			for _, direction := range []string{"client", "server"} {
				t.Run(fmt.Sprint(transport, "/", encrypted, "/", direction), func(t *testing.T) {
					in := testInbound(t, "trojan")
					in.Transport = Transport{Type: transport}
					if transport != "" {
						in.Transport.Path = "/mux-test"
					}
					if encrypted {
						in.Shadowsocks = trojanSSOptions("aes-128-gcm")
					}
					port := unusedPort(t)
					cfg := map[string]any{"local_addr": "127.0.0.1", "local_port": port, "password": []string{"private"}, "disable_http_check": true, "mux": map[string]any{"enabled": true, "concurrency": -1}, "websocket": map[string]any{"enabled": transport != "", "path": "/mux-test", "host": "example.com"}}
					if encrypted {
						cfg["shadowsocks"] = map[string]any{"enabled": true, "method": "AES-128-GCM", "password": in.Shadowsocks.Password}
					}
					var client *Runtime
					if direction == "client" {
						dir := t.TempDir()
						cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
						if e := os.WriteFile(cert, []byte(strings.Join(in.TLS.Certificate, "\n")), 0600); e != nil {
							t.Fatal(e)
						}
						if e := os.WriteFile(key, []byte(strings.Join(in.TLS.Key, "\n")), 0600); e != nil {
							t.Fatal(e)
						}
						cfg["run_type"], cfg["remote_addr"], cfg["remote_port"] = "server", "127.0.0.1", 80
						cfg["ssl"] = map[string]any{"cert": cert, "key": key, "alpn": []string{"http/1.1"}}
						trojanGoReference(t, cfg, port)
						out := testOutbound(t, in, portAddress("127.0.0.1", port))
						out.Transport, out.Shadowsocks = in.Transport, in.Shadowsocks
						out.Multiplex.Enabled = true
						out.Multiplex.Protocol = "trojan-go"
						client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
					} else {
						server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						host, p, _ := net.SplitHostPort(server.Address("server"))
						value, _ := strconv.Atoi(p)
						cfg["run_type"], cfg["remote_addr"], cfg["remote_port"] = "client", host, value
						cfg["ssl"] = map[string]any{"verify": false, "verify_hostname": false, "sni": "example.com"}
						trojanGoReference(t, cfg, port)
						client = newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "front", Server: "127.0.0.1", ServerPort: port}}})
					}
					assertTCP(t, client)
					assertUDPSizes(t, client, []int{1, 511, 4096})
					assertTCP(t, client)
				})
			}
		}
	}
}

func TestTrojanMuxPreservesReject(t *testing.T) {
	in := testInbound(t, "trojan")
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "block", Tag: "deny"}}})
	out := testOutbound(t, in, server.Address("server"))
	out.Multiplex.Enabled = true
	out.Multiplex.Protocol = "trojan-go"
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	c, e := client.Dial(context.Background(), "tcp", "127.0.0.1:80")
	if e != nil {
		return
	}
	defer c.Close()
	if _, e = c.Read(make([]byte, 1)); e == nil {
		t.Fatal("rejected route succeeded")
	}
}
