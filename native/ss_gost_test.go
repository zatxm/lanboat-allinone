package native

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var gostPluginModes = []string{"mws", "mwss", "mtls", "ws", "wss", "tls"}

func gostPluginOptions(mode string) string {
	text := "mode=" + mode
	if strings.Contains(mode, "ws") {
		text += ";path=/plugin;host=example.com"
	}
	return text
}

func gostPluginSecure(mode string) bool {
	return mode == "mtls" || mode == "tls" || strings.HasSuffix(mode, "wss")
}

func TestGOSTPluginIndependent(t *testing.T) {
	for _, mode := range gostPluginModes {
		for _, method := range []string{"aes-256-cfb", "aes-128-gcm", "2022-blake3-aes-128-gcm"} {
			t.Run(mode+"/"+method, func(t *testing.T) {
				in := testInbound(t, "shadowsocks")
				in.Method = method
				if isSS2022(method) {
					in.Password = "BwcHBwcHBwcHBwcHBwcHBw=="
				}
				if gostPluginSecure(mode) {
					in.TLS = certificate(t)
				}
				in.SIP003Options = SIP003Options{Plugin: "gost", PluginOpts: gostPluginOptions(mode)}
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				o := testOutbound(t, in, s.Address("server"))
				o.Password = in.Password
				o.SIP003Options = in.SIP003Options
				c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{0, 1, 511, 4096, 60000})
				assertTCP(t, c)
				for _, r := range []*Runtime{c, s} {
					b, e := json.Marshal(r.config)
					if e != nil {
						t.Fatal(e)
					}
					if _, e = Parse(b); e != nil {
						t.Fatal("config cannot reload", e)
					}
				}
				if strings.HasPrefix(mode, "m") {
					pool := c.proxyMuxClients[o.Tag]
					first := pool.current
					assertTCP(t, c)
					if first != pool.current {
						t.Fatal("GOST did not reuse session")
					}
					c.resetNetworkTransports()
					assertTCP(t, c)
					if first == pool.current {
						t.Fatal("network reset kept old session")
					}
				}
			})
		}
	}
}

func TestGOSTPluginReference(t *testing.T) {
	for _, mode := range gostPluginModes {
		for _, side := range []string{"client", "server"} {
			t.Run(mode+"/"+side, func(t *testing.T) {
				in := testInbound(t, "shadowsocks")
				address := portAddress("127.0.0.1", unusedPort(t))
				params := url.Values{"path": {"/plugin"}, "host": {"example.com"}, "serverName": {"example.com"}, "secure": {"false"}, "mux.version": {"1"}}
				var c *Runtime
				if side == "client" {
					s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					startGOST(t, "-L", "tcp+"+mode+"://"+address+"/"+s.Address("server")+"?"+params.Encode())
					waitPort(t, address)
					o := testOutbound(t, in, address)
					o.SIP003Options = SIP003Options{Plugin: "gost", PluginOpts: gostPluginOptions(mode)}
					if gostPluginSecure(mode) {
						o.PluginOpts += ";skip-cert-verify=true"
					}
					c = newTestRuntime(t, Config{Outbounds: []Outbound{o}})
				} else {
					in.SIP003Options = SIP003Options{Plugin: "gost", PluginOpts: gostPluginOptions(mode)}
					if gostPluginSecure(mode) {
						in.TLS = certificate(t)
					}
					s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					startGOST(t, "-L", "tcp://"+address+"/"+s.Address("server"), "-F", "forward+"+mode+"://"+s.Address("server")+"?"+params.Encode())
					waitPort(t, address)
					o := testOutbound(t, in, address)
					o.TLS = TLSOptions{}
					c = newTestRuntime(t, Config{Outbounds: []Outbound{o}})
				}
				assertTCP(t, c)
				assertTCP(t, c)
			})
		}
	}
}

func TestGOSTPluginConcurrentAuthenticationAndClose(t *testing.T) {
	for _, mode := range []string{"mws", "mwss", "mtls"} {
		t.Run(mode, func(t *testing.T) {
			in := testInbound(t, "shadowsocks")
			in.SIP003Options = SIP003Options{Plugin: "gost", PluginOpts: gostPluginOptions(mode)}
			if gostPluginSecure(mode) {
				in.TLS = certificate(t)
			}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			o := testOutbound(t, in, s.Address("server"))
			o.SIP003Options = in.SIP003Options
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			target := relayEchoTCP(t)
			var workers sync.WaitGroup
			for i := range 24 {
				workers.Go(func() {
					conn, err := c.Dial(context.Background(), "tcp", target)
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					data := bytes.Repeat([]byte{byte(i)}, 70000)
					if err = writeAll(conn, data); err != nil {
						t.Error(err)
						return
					}
					reply := make([]byte, len(data))
					if _, err = io.ReadFull(conn, reply); err != nil || !bytes.Equal(data, reply) {
						t.Error("corrupted parallel stream", err)
					}
				})
			}
			workers.Wait()
			pool := c.proxyMuxClients[o.Tag]
			if len(pool.all) != 1 {
				t.Fatal("unexpected pool size", len(pool.all))
			}
			// A logical stream with a different SS key shares the same transport pool.
			bad, err := pool.dial(context.Background(), "tcp", target)
			if err != nil {
				t.Fatal(err)
			}
			bad.SetDeadline(time.Now().Add(time.Second))
			key, _ := newSSKey(o.Method, "wrong")
			secured := newSSConn(bad, key, &replayWindow{})
			destination, _ := encodeAddress(target)
			_ = writeAll(secured, destination)
			if _, err = secured.Read(make([]byte, 1)); err == nil {
				t.Fatal("wrong SS key accepted")
			}
			bad.Close()
			assertTCP(t, c)
			active, err := c.Dial(context.Background(), "tcp", target)
			if err != nil {
				t.Fatal(err)
			}
			if err = c.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = active.Read(make([]byte, 1)); err == nil {
				t.Fatal("runtime close retained active stream")
			}
		})
	}
}

func TestGOSTPluginEndpointAndTLSValidation(t *testing.T) {
	for _, mode := range []string{"ws", "mws", "tls", "mtls", "wss", "mwss"} {
		t.Run(mode, func(t *testing.T) {
			in := testInbound(t, "shadowsocks")
			in.SIP003Options = SIP003Options{Plugin: "gost", PluginOpts: gostPluginOptions(mode)}
			if gostPluginSecure(mode) {
				in.TLS = certificate(t)
			}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			host, port, _ := net.SplitHostPort(s.Address("server"))
			o := testOutbound(t, in, "127.0.0.2:1")
			o.SIP003Options = SIP003Options{Plugin: "gost-plugin", PluginOpts: gostPluginOptions(mode) + ";server=" + host + ";port=" + port}
			if gostPluginSecure(mode) {
				o.TLS.RecordFragment = true
				o.TLS.Insecure = false
				o.TLS.Certificate = in.TLS.Certificate
				o.TLS.ServerName = "example.com"
			}
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			assertTCP(t, c)
			if !gostPluginSecure(mode) {
				return
			}
			o.PluginOpts += ";sni=wrong.example"
			bad := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			if conn, err := bad.Dial(context.Background(), "tcp", relayEchoTCP(t)); err == nil {
				conn.Close()
				t.Fatal("GOST bypassed TLS hostname check")
			}
		})
	}
	for _, text := range []string{"mode=unknown", "mode=tls;path=/path", "mode=ws;sni=server", "mode=mws;skip-cert-verify=true", "port=0", "port=65536", "port=-1", "server=bad host", "server=bad@host", "mode=ws;path=relative", "mode=ws;host=bad host", "unknown=1", "mode=tls;skip-cert-verify=maybe"} {
		p := SIP003Options{Plugin: "gost", PluginOpts: text}
		if p.prepare("shadowsocks", Transport{}, TLSOptions{}, false) == nil {
			t.Fatal("accepted invalid GOST options", strconv.Quote(text))
		}
	}
}

func TestEmptyUDPDatagrams(t *testing.T) {
	for _, kind := range []string{"socks", "shadowsocks", "shadowsocksr"} {
		protocols := []string{""}
		if kind == "shadowsocksr" {
			protocols = SSRProtocols()
		}
		for _, protocol := range protocols {
			t.Run(kind+"/"+protocol, func(t *testing.T) {
				in := testInbound(t, kind)
				if kind == "shadowsocksr" {
					in.Method, in.Password, in.Protocol = "aes-256-cfb", "private", protocol
				}
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				o := testOutbound(t, in, s.Address("server"))
				o.Protocol = protocol
				c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
				assertUDPSizes(t, c, []int{0, 1, 0, 511})
			})
		}
	}
}
