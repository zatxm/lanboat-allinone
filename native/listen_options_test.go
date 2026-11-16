package native

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

func TestListenOptionsValidation(t *testing.T) {
	for _, field := range []string{`"tcp_keep_alive":"0s"`, `"tcp_keep_alive_interval":"bad"`, `"disable_tcp_keep_alive":true,"tcp_keep_alive":"5s"`, `"bind_interface":"a\u0000b"`, `"routing_mark":"0x100000000"`, `"inet4_bind_address":"127.0.0.1"`, `"connect_timeout":"2s"`} {
		if _, err := Parse([]byte(`{"inbounds":[{"type":"mixed",` + field + `}]}`)); err == nil {
			t.Fatal("bad listener accepted", field)
		}
	}
	for _, raw := range []string{
		`{"inbounds":[{"type":"mixed","tcp_keep_alive":"5s","tcp_keep_alive_interval":"2s","tcp_multi_path":true,"reuse_addr":true}]}`,
		`{"inbounds":[{"type":"direct","reuse_addr":true,"tcp_fast_open":true,"udp_fragment":true}]}`,
	} {
		if _, err := Parse([]byte(raw)); err != nil {
			t.Fatal(err, raw)
		}
	}
	if _, err := Parse([]byte(`{"inbounds":[{"type":"tun","reuse_addr":true}]}`)); err == nil {
		t.Fatal("socket options accepted on tun device")
	}
	in := Inbound{Type: "mixed", Tag: "bad", Listen: "127.0.0.1", ListenOptions: ListenOptions{BindInterface: "lanboat-missing-interface"}}
	raw, _ := json.Marshal(Config{Inbounds: []Inbound{in}})
	r, err := New(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err = r.Start(); err == nil {
		t.Fatal("missing interface silently bypassed")
	}
}

func TestListenOptionsCarrierTraffic(t *testing.T) {
	for _, kind := range []string{"socks", "http", "shadowsocks", "trojan", "vless", "vmess", "anytls", "relay", "brook", "hysteria2", "tuic"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, kind)
			if kind == "hysteria2" {
				in.TLS = certificate(t)
				in.Users = []User{{Password: "private"}}
			}
			if kind == "tuic" {
				in.TLS = certificate(t)
				in.Users = []User{{UUID: testUUID, Password: "private"}}
			}
			in.ListenOptions = ListenOptions{ReuseAddr: true, TCPFastOpen: true, TCPKeepAlive: "6s", TCPKeepAliveInterval: "2s"}
			yes := true
			in.UDPFragment = &yes
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			client := newTestRuntime(t, Config{Outbounds: []Outbound{testOutbound(t, in, server.Address(in.Tag))}})
			assertTCP(t, client)
			if kind != "http" {
				sizes := []int{0, 1, 511, 4096, 60000}
				// VMess reserves empty frames for EOF and bounds UDP to one chunk.
				if kind == "vmess" {
					sizes = sizes[1:4]
				}
				assertUDPSizes(t, client, sizes)
			}
		})
	}
}

func TestListenOptionsInboundBindingIsolation(t *testing.T) {
	in := Inbound{Type: "mixed", Tag: "local", Listen: "127.0.0.1"}
	r := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Route: Route{DefaultInterface: "lanboat-no-egress"}})
	c, err := net.DialTimeout("tcp", r.Address("local"), time.Second)
	if err != nil {
		t.Fatal("listener inherited outbound binding", err)
	}
	c.Close()
}

func TestListenOptionsKeepAliveTraffic(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		o := ListenOptions{DisableTCPKeepAlive: disabled}
		l, err := o.listen(context.Background(), "tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		c, err := net.Dial("tcp4", l.Addr().String())
		if err != nil {
			l.Close()
			t.Fatal(err)
		}
		peer, err := l.Accept()
		l.Close()
		if err != nil {
			c.Close()
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		peer.SetDeadline(time.Now().Add(time.Second))
		if err = writeAll(c, []byte("alive")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 5)
		if _, err = io.ReadFull(peer, b); err != nil || string(b) != "alive" {
			t.Fatal(string(b), err)
		}
		c.Close()
		peer.Close()
	}
}

func TestListenOptionsPluginAndPairedPaths(t *testing.T) {
	for _, carrier := range []string{"kcptun", "mkcp", "naive-h2", "naive-h3", "openconnect", "mieru-udp", "snell5"} {
		t.Run(carrier, func(t *testing.T) {
			in := testInbound(t, "vless")
			switch carrier {
			case "kcptun":
				in = testInbound(t, "shadowsocks")
				in.Plugin = "kcptun"
				in.PluginOpts = "key=private;crypt=aes;nocomp=true"
			case "mkcp":
				in.Transport = Transport{Type: "mkcp"}
			case "naive-h2", "naive-h3":
				in = testInbound(t, "http")
				in.Type = "naive"
				in.TLS = certificate(t)
			case "mieru-udp":
				in = testInbound(t, "socks")
				in.Type = "mieru"
				in.Network = "udp"
			case "snell5":
				in = Inbound{Type: "snell", Tag: "server", Listen: "127.0.0.1", Version: "5", Password: "private"}
			case "openconnect":
				in = testInbound(t, "socks")
				in.Type = "openconnect"
				in.TLS = certificate(t)
			}
			fragment := true
			in.ListenOptions = ListenOptions{ReuseAddr: true, TCPKeepAlive: "7s", TCPKeepAliveInterval: "2s", UDPFragment: &fragment}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address(in.Tag))
			out.Plugin, out.PluginOpts, out.Transport = in.Plugin, in.PluginOpts, in.Transport
			out.Version, out.Network = in.Version, in.Network
			if carrier == "naive-h2" || carrier == "naive-h3" {
				out.QUIC = carrier == "naive-h3"
				out.UDPOverTCP = true
			}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			if carrier == "openconnect" {
				tun, err := client.ocClients["proxy"].session(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				ocWaitDTLS(t, tun)
			}
			assertTCP(t, client)
			if carrier != "kcptun" {
				assertUDPSizes(t, client, []int{1, 511, 4096})
			}
		})
	}
}

func TestListenOptionsMASQUEEndpoint(t *testing.T) {
	server := masqueEndpointRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": []int{2, 3}, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "users": []User{{Username: "client", Password: "private"}}, "tls": certificate(t), "path": "/vpn/{target}/{ipproto}/", "reuse_addr": true, "tcp_keep_alive": "7s", "tcp_keep_alive_interval": "2s", "udp_fragment": true})
	got := server.config.Inbounds[0].ListenOptions
	if !got.ReuseAddr || got.TCPKeepAlive != "7s" || got.UDPFragment == nil || !*got.UDPFragment {
		t.Fatal("endpoint lost listen options", got)
	}
	for _, version := range []int{2, 3} {
		client := masqueEndpointClient(t, server, version, true)
		assertTCP(t, client)
		assertUDPSizes(t, client, []int{1, 511, 4096})
	}
	if _, err := Parse([]byte(`{"endpoints":[{"type":"masque-server","listen":"127.0.0.1","connect_timeout":"1s"}]}`)); err == nil {
		t.Fatal("server accepted client-only timeout")
	}
}

func TestListenUDPTimeoutExpiry(t *testing.T) {
	for _, kind := range []string{"socks", "shadowsocks"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, kind)
			in.UDPTimeout = "80ms"
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			client := newTestRuntime(t, Config{Outbounds: []Outbound{testOutbound(t, in, server.Address(in.Tag))}})
			target := echoUDP(t)
			conn, err := client.Dial(context.Background(), "udp", target)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			exchange := func() {
				conn.SetDeadline(time.Now().Add(time.Second))
				if _, err := conn.Write([]byte("live")); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 4)
				n, err := conn.Read(b)
				if err != nil || string(b[:n]) != "live" {
					t.Fatal(string(b[:n]), err)
				}
			}
			count := func() int {
				server.mu.Lock()
				defer server.mu.Unlock()
				n := 0
				for c := range server.connections {
					if c.RemoteAddr().Network() == "udp" && c.RemoteAddr().String() == target {
						n++
					}
				}
				return n
			}
			exchange()
			if count() != 1 {
				t.Fatal("UDP mapping not created")
			}
			until := time.Now().Add(time.Second)
			for count() != 0 && time.Now().Before(until) {
				time.Sleep(time.Millisecond)
			}
			if count() != 0 {
				t.Fatal("configured UDP timeout ignored")
			}
			exchange()
			if count() != 1 {
				t.Fatal("expired mapping did not reopen")
			}
		})
	}
	for _, value := range []string{"0s", "-1s", "bad"} {
		raw := []byte(`{"inbounds":[{"type":"socks","udp_timeout":"` + value + `"}]}`)
		if _, err := Parse(raw); err == nil {
			t.Fatal("invalid UDP timeout accepted", value)
		}
	}
}

func TestListenDatagramTimeoutCountsBothDirections(t *testing.T) {
	a, client := net.Pipe()
	b, target := net.Pipe()
	defer client.Close()
	defer target.Close()
	r := newTestRuntime(t, Config{})
	done := make(chan error, 1)
	go func() { done <- r.relayDatagrams(a, b, 80*time.Millisecond) }()
	drained := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, target); close(drained) }()
	client.SetWriteDeadline(time.Now().Add(time.Second))
	until := time.Now().Add(240 * time.Millisecond)
	for time.Now().Before(until) {
		if _, err := client.Write([]byte("one-way")); err != nil {
			t.Fatal("active one-way traffic expired", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	client.Close()
	<-done
	target.Close()
	<-drained
}
