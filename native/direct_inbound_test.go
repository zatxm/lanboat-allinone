package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDirectInboundConfiguration(t *testing.T) {
	for _, extra := range []string{``, `,"network":"tcp"`, `,"network":"udp","udp_timeout":"1s"`, `,"override_address":"::1","override_port":53`, `,"override_address":"resolver.example"`} {
		if _, err := Parse([]byte(`{"inbounds":[{"type":"direct","tag":"in"` + extra + `}]}`)); err != nil {
			t.Fatal(extra, err)
		}
	}
	for _, extra := range []string{`,"network":"quic"`, `,"override_port":65536`, `,"override_address":"bad/host"`, `,"password":"ignored"`, `,"transport":{"type":"ws"}`, `,"tls":{"enabled":true}`, `,"udp_timeout":"-1s"`} {
		if _, err := Parse([]byte(`{"inbounds":[{"type":"direct","tag":"in"` + extra + `}]}`)); err == nil {
			t.Fatal("accepted", extra)
		}
	}
	if _, err := Parse([]byte(`{"inbounds":[{"type":"socks","override_address":"localhost"}]}`)); err == nil {
		t.Fatal("unrelated inbound accepted destination override")
	}
	for _, tc := range []struct {
		address, override, want string
		port                    uint16
	}{
		{"127.0.0.1:10", "", "127.0.0.1:10", 0},
		{"127.0.0.1:10", "::1", "[::1]:10", 0},
		{"[::1]:10", "", "[::1]:53", 53},
		{"127.0.0.1:10", "target.example", "target.example:53", 53},
	} {
		local, _ := net.ResolveTCPAddr("tcp", tc.address)
		if got := (Inbound{OverrideAddress: tc.override, OverridePort: tc.port}).directTarget(local); got != tc.want {
			t.Fatal(got, tc.want)
		}
	}
}

func directTestInbound(address, network string) Inbound {
	host, port, _ := net.SplitHostPort(address)
	n, _ := shadowPort(port)
	return Inbound{Type: "direct", Tag: "tunnel", Listen: host, Network: network, OverrideAddress: host, OverridePort: n}
}

func directTransfer(t *testing.T, network, address string, size int) {
	t.Helper()
	c, err := net.DialTimeout(network, address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	want := bytes.Repeat([]byte{0, 19, 255, 42}, (size+3)/4)[:size]
	if _, err = c.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, max(1, size))
	if network == "tcp" {
		_, err = io.ReadFull(c, got[:size])
	} else {
		var n int
		n, err = c.Read(got)
		got = got[:n]
	}
	if err != nil || !bytes.Equal(want, got[:size]) {
		t.Fatalf("%s transfer:%d,%v", network, len(got), err)
	}
}

func TestDirectInbound(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, network := range []string{"tcp", "udp", ""} {
			t.Run(host+"/"+network, func(t *testing.T) {
				// One echo port for both transports also exercises ephemeral paired binding.
				l, err := net.Listen("tcp", portAddress(host, 0))
				if err != nil {
					t.Fatal(err)
				}
				l, p, err := bindPairedUDP(l, true)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { l.Close(); p.Close() })
				go func() {
					for {
						c, e := l.Accept()
						if e != nil {
							return
						}
						go func() { defer c.Close(); io.Copy(c, c) }()
					}
				}()
				go func() {
					b := make([]byte, 65535)
					for {
						n, peer, e := p.ReadFrom(b)
						if e != nil {
							return
						}
						p.WriteTo(b[:n], peer)
					}
				}()
				in := directTestInbound(l.Addr().String(), network)
				r := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				if network != "udp" {
					directTransfer(t, "tcp", r.Address(in.Tag), 70000)
				}
				if network != "tcp" {
					for _, size := range []int{0, 1, 1400, 60000} {
						directTransfer(t, "udp", r.Address(in.Tag), size)
					}
				}
				if network == "udp" && r.listeners[in.Tag] != nil {
					t.Fatal("UDP-only inlet opened TCP")
				}
				if network == "tcp" && r.directPackets[in.Tag] != nil {
					t.Fatal("TCP-only inlet opened UDP")
				}
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
				// Only assert release of sockets owned by this inbound. A UDP-only
				// port can legitimately share its number with an unrelated TCP listener.
				if network != "udp" {
					l2, e := net.Listen("tcp", r.Address(in.Tag))
					if e != nil {
						t.Fatal("TCP port not released", e)
					}
					l2.Close()
				}
				if network != "tcp" {
					p2, e := net.ListenPacket("udp", r.Address(in.Tag))
					if e != nil {
						t.Fatal("UDP port not released", e)
					}
					p2.Close()
				}
			})
		}
	}
}

func TestDirectInboundUDPSharedPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, reserved, err := bindPairedUDP(listener, true)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	reserved.Close()
	in := directTestInbound(echoUDP(t), "udp")
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	in.ListenPort, _ = shadowPort(port)
	r := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	directTransfer(t, "udp", r.Address(in.Tag), 4096)
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	c, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal("closing UDP inlet affected the shared TCP listener", err)
	}
	c.Close()
	packets, err := net.ListenPacket("udp", r.Address(in.Tag))
	if err != nil {
		t.Fatal("UDP port not released", err)
	}
	packets.Close()
}

func TestDirectInboundRouting(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "routed") }))
	defer origin.Close()
	in := directTestInbound(strings.TrimPrefix(origin.URL, "http://"), "tcp")
	proxyIn := Inbound{Type: "socks", Tag: "server", Listen: "127.0.0.1"}
	proxy := newTestRuntime(t, Config{Inbounds: []Inbound{proxyIn}})
	out := testOutbound(t, proxyIn, proxy.Address("server"))
	out.Username = ""
	out.Password = ""
	r := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "block", Tag: "deny"}, out}, Route: Route{Final: "deny", Rules: []Rule{{Inbound: []string{"tunnel"}, Outbound: out.Tag}}}})
	resp, err := http.Get("http://" + r.Address(in.Tag))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "routed" {
		t.Fatal(string(body))
	}
	if proxy.Stats().Uplink == 0 || proxy.Stats().Downlink == 0 {
		t.Fatal("direct inlet bypassed proxy policy")
	}
	query, _ := makeDNSQuery("isolated.test", 1)
	dns := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "direct", Tag: "dns", Listen: "127.0.0.1"}}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "records", Predefined: map[string][]string{"isolated.test": {"192.0.2.7"}}}}}, Route: Route{Rules: []Rule{{Action: "hijack-dns"}}}})
	for _, network := range []string{"tcp", "udp"} {
		c, e := net.Dial(network, dns.Address("dns"))
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		wire := query
		if network == "tcp" {
			wire = binary.BigEndian.AppendUint16(nil, uint16(len(query)))
			wire = append(wire, query...)
		}
		if _, e = c.Write(wire); e != nil {
			t.Fatal(e)
		}
		reply := make([]byte, 4096)
		var n int
		if network == "tcp" {
			var size [2]byte
			_, e = io.ReadFull(c, size[:])
			if e != nil {
				t.Fatal(e)
			}
			n = int(binary.BigEndian.Uint16(size[:]))
			_, e = io.ReadFull(c, reply[:n])
		} else {
			n, e = c.Read(reply)
		}
		if e != nil {
			t.Fatal(e)
		}
		ips, _, e := parseDNSReply(query, reply[:n])
		if e != nil || fmt.Sprint(ips) != "[192.0.2.7]" {
			t.Fatal(ips, e)
		}
	}
}

func TestDirectInboundConcurrencyAndShutdown(t *testing.T) {
	in := directTestInbound(echoUDP(t), "udp")
	in.UDPTimeout = "50ms"
	r := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	var jobs sync.WaitGroup
	for range 32 {
		jobs.Add(1)
		go func() { defer jobs.Done(); directTransfer(t, "udp", r.Address(in.Tag), 1400) }()
	}
	jobs.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { r.Close(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("shutdown stalled")
	}
	// Failure after the first inlet must roll back both of its sockets.
	occupied, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer occupied.Close()
	_, port, _ := net.SplitHostPort(occupied.Addr().String())
	n, _ := shadowPort(port)
	cfg := Config{Inbounds: []Inbound{{Type: "direct", Tag: "first", Listen: "127.0.0.1"}, {Type: "direct", Tag: "busy", Listen: "127.0.0.1", ListenPort: n}}}
	b, _ := json.Marshal(cfg)
	failed, e := New(context.Background(), b, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = failed.Start(); e == nil {
		failed.Close()
		t.Fatal("occupied port accepted")
	}
	addr := failed.Address("first")
	tcp, e := net.Listen("tcp", addr)
	if e != nil {
		t.Fatal(e)
	}
	tcp.Close()
	udp, e := net.ListenPacket("udp", addr)
	if e != nil {
		t.Fatal(e)
	}
	udp.Close()
}

func TestDirectInboundOfficial(t *testing.T) {
	reference := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if reference == "" {
		t.Skip("LANBOAT_TEST_SINGBOX15 required")
	}
	for _, network := range []string{"tcp", "udp", ""} {
		t.Run(network, func(t *testing.T) {
			n := unusedPort(t)
			ready := portAddress("127.0.0.1", n)
			doc := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "direct", "tag": "in", "listen": "127.0.0.1", "listen_port": n, "network": network}}, "dns": map[string]any{"servers": []any{map[string]any{"type": "hosts", "tag": "records", "predefined": map[string]any{"reference.test": "192.0.2.9"}}}}, "route": map[string]any{"rules": []any{map[string]any{"action": "hijack-dns"}}}}
			if network == "" {
				delete(doc["inbounds"].([]any)[0].(map[string]any), "network")
			}
			b, _ := json.Marshal(doc)
			path := filepath.Join(t.TempDir(), "reference.json")
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			log := new(bytes.Buffer)
			cmd := exec.Command(reference, "run", "-c", path)
			cmd.Stdout, cmd.Stderr = log, log
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cmd.Process.Kill()
				cmd.Wait()
				if t.Failed() {
					t.Log(log.String())
				}
			})
			// Use a DNS query as readiness probe even when TCP is disabled.
			query, _ := makeDNSQuery("reference.test", 1)
			for _, kind := range []string{"tcp", "udp"} {
				if network != "" && network != kind {
					continue
				}
				var last error
				for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
					c, e := net.DialTimeout(kind, ready, 50*time.Millisecond)
					if e != nil {
						last = e
						time.Sleep(5 * time.Millisecond)
						continue
					}
					c.SetDeadline(time.Now().Add(100 * time.Millisecond))
					wire := query
					if kind == "tcp" {
						wire = append(binaryAppendLength(query), query...)
					}
					_, e = c.Write(wire)
					reply := make([]byte, 4096)
					var size int
					if e == nil {
						if kind == "tcp" {
							var h [2]byte
							_, e = io.ReadFull(c, h[:])
							if e == nil {
								size = int(binary.BigEndian.Uint16(h[:]))
								_, e = io.ReadFull(c, reply[:size])
							}
						} else {
							size, e = c.Read(reply)
						}
					}
					c.Close()
					if e == nil {
						ips, _, p := parseDNSReply(query, reply[:size])
						if p != nil || fmt.Sprint(ips) != "[192.0.2.9]" {
							t.Fatal(ips, p)
						}
						last = nil
						break
					}
					last = e
					time.Sleep(5 * time.Millisecond)
				}
				if last != nil {
					t.Fatal(last)
				}
			}
		})
	}
}

func binaryAppendLength(query []byte) []byte {
	return binary.BigEndian.AppendUint16(nil, uint16(len(query)))
}

func TestDirectInboundMixedListeners(t *testing.T) {
	for _, first := range []bool{true, false} {
		t.Run(fmt.Sprint(first), func(t *testing.T) {
			in := directTestInbound(echoUDP(t), "udp")
			dns := Inbound{Type: "dns", Tag: "dns", Listen: "127.0.0.1"}
			ss := testInbound(t, "shadowsocks")
			inbounds := []Inbound{dns, in, ss}
			if first {
				inbounds = []Inbound{in, ss, dns}
			}
			r := newTestRuntime(t, Config{Inbounds: inbounds, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"mixed.test": {"192.0.2.10"}}}}}})
			directTransfer(t, "udp", r.Address(in.Tag), 1400)
			client := newTestRuntime(t, Config{Outbounds: []Outbound{testOutbound(t, ss, r.Address(ss.Tag))}})
			assertUDP(t, client)
			query, _ := makeDNSQuery("mixed.test", 1)
			c, err := net.Dial("udp", r.Address(dns.Tag))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			c.Write(query)
			b := make([]byte, 4096)
			n, err := c.Read(b)
			if err != nil {
				t.Fatal(err)
			}
			ips, _, err := parseDNSReply(query, b[:n])
			if err != nil || fmt.Sprint(ips) != "[192.0.2.10]" {
				t.Fatal(ips, err)
			}
		})
	}
}
