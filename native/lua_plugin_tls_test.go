package native

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func luaTLSProxy(t *testing.T) (Inbound, *Runtime) {
	t.Helper()
	in := testInbound(t, "http")
	in.TLS = certificate(t)
	return in, newTestRuntime(t, Config{Inbounds: []Inbound{in}})
}
func TestLuaNodeTLSAfterPlugins(t *testing.T) {
	for _, plugin := range []SIP003Options{
		{Plugin: "obfs-local", PluginOpts: "obfs=http;obfs-host=example.com"},
		{Plugin: "obfs-local", PluginOpts: "obfs=tls;obfs-host=example.com"},
		{Plugin: "v2ray-plugin", PluginOpts: "mode=websocket;path=/lua;host=example.com;mux=0"},
	} {
		t.Run(plugin.Plugin+plugin.PluginOpts, func(t *testing.T) {
			serverOpts := certificate(t)
			serverTLS, e := serverOpts.config(true, "")
			if e != nil {
				t.Fatal(e)
			}
			p := plugin
			if e = p.prepare("shadowsocks", Transport{}, TLSOptions{}, true); e != nil {
				t.Fatal(e)
			}
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			router := newTestRuntime(t, Config{})
			var workers sync.WaitGroup
			done := make(chan struct{})
			t.Cleanup(func() { listener.Close(); <-done; workers.Wait() })
			go func() {
				defer close(done)
				for {
					raw, e := listener.Accept()
					if e != nil {
						return
					}
					workers.Go(func() {
						defer raw.Close()
						raw.SetDeadline(time.Now().Add(5 * time.Second))
						wire, e := p.wrap(raw, true)
						if e != nil {
							return
						}
						if p.plugin.transport.Type != "" {
							wire, e = acceptTransport(&bufferedConn{Conn: wire, reader: bufio.NewReader(wire)}, p.plugin.transport)
							if e != nil {
								return
							}
						}
						secure := tls.Server(wire, serverTLS)
						if e = secure.Handshake(); e != nil {
							return
						}
						router.serveProtocol(Inbound{Type: "http", Users: []User{{Username: "client", Password: "private"}}}, secure, raw.RemoteAddr().String())
					})
				}
			}()
			out := luaOutbound(t, Inbound{Type: "http"}, listener.Addr().String(), "http-backend.lua")
			out.SIP003Options = plugin
			out.TLS = TLSOptions{Enabled: true, ServerName: "example.com", Certificate: serverOpts.Certificate}
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, c)
			out.TLS.ServerName = "wrong.example"
			bad := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			conn, e := bad.Dial(context.Background(), "tcp", "example.com:443")
			if conn != nil {
				conn.Close()
			}
			if e == nil {
				t.Fatal("plugin bypassed node TLS hostname verification")
			}
		})
	}
}
func TestLuaNodeTLSAfterKCPTUN(t *testing.T) {
	if os.Getenv("LANBOAT_TEST_KCPTUN") == "" {
		t.Fatal("LANBOAT_TEST_KCPTUN required")
	}
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			in, server := luaTLSProxy(t)
			_, reader := kcpReference(t, "-mode=server", "-version="+fmt.Sprint(version), "-target="+server.Address("server"))
			address, e := reader.ReadString('\n')
			if e != nil {
				t.Fatal(e)
			}
			out := luaOutbound(t, in, strings.TrimSpace(address), "http-backend.lua")
			out.TLS = TLSOptions{Enabled: true, ServerName: "example.com", Certificate: in.TLS.Certificate}
			out.Plugin = "kcptun"
			out.PluginOpts = fmt.Sprintf("key=private;version=%d;nocomp=true", version)
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, c)
			c.resetNetworkTransports()
			assertTCP(t, c)
		})
	}
}
func TestLuaNodeTLSAfterCloak(t *testing.T) {
	if os.Getenv("LANBOAT_TEST_CLOAK") == "" {
		t.Fatal("LANBOAT_TEST_CLOAK required")
	}
	in, server := luaTLSProxy(t)
	address, opts := cloakReferenceServer(t, server.Address("server"), "direct")
	out := luaOutbound(t, in, address, "http-backend.lua")
	out.TLS = TLSOptions{Enabled: true, ServerName: "example.com", Certificate: in.TLS.Certificate}
	out.Plugin = "cloak"
	out.PluginOpts = opts
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	assertTCP(t, c)
}
func TestLuaNodeTLSAfterShadowTLS(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			coverVersion := uint16(tls.VersionTLS13)
			if version == 1 {
				coverVersion = tls.VersionTLS12
			}
			cover, _ := shadowCover(t, coverVersion)
			inner := testInbound(t, "http")
			inner.TLS = certificate(t)
			outer := Inbound{Type: "shadowtls", Tag: "outer", Listen: "127.0.0.1", Version: fmt.Sprint(version), Detour: "server", ShadowTLSOptions: ShadowTLSOptions{Handshake: &cover, StrictMode: version == 3}}
			if version == 2 {
				outer.Password = "transport-secret"
			}
			if version == 3 {
				outer.Users = []User{{Password: "transport-secret"}}
			}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{inner, outer}})
			out := luaOutbound(t, inner, s.Address("outer"), "http-backend.lua")
			out.TLS = TLSOptions{Enabled: true, ServerName: "example.com", Certificate: inner.TLS.Certificate}
			out.Plugin = "shadow-tls"
			out.PluginOpts = fmt.Sprintf("version=%d;host=example.com;skip-cert-verify=true", version)
			if version > 1 {
				out.PluginOpts += ";password=transport-secret"
			}
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, c)
			raw, _ := json.Marshal(c.config)
			if _, e := Parse(raw); e != nil {
				t.Fatal("reload", e)
			}
			// An insecure cover handshake must not disable inner certificate validation.
			out.TLS.Certificate = nil
			bad := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			conn, e := bad.Dial(context.Background(), "tcp", "example.com:443")
			if conn != nil {
				conn.Close()
			}
			if e == nil {
				t.Fatal("cover insecurity leaked into node TLS")
			}
		})
	}
}
