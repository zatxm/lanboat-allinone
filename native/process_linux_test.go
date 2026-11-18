package native

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"testing"
	"time"
)

func processTestPath(t *testing.T) string {
	t.Helper()
	path, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func processTestTCP(t *testing.T, network, host string) socketOrigin {
	t.Helper()
	l, err := net.Listen(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	c, err := net.Dial(network, l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	peer, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	return socketOrigin{network: "tcp", source: c.LocalAddr().String(), destination: c.RemoteAddr().String()}
}

func TestProcessSocketDiscovery(t *testing.T) {
	path := processTestPath(t)
	finder := &processFinder{}
	for _, family := range []string{"4", "6"} {
		host := "127.0.0.1"
		if family == "6" {
			host = "::1"
		}
		t.Run("tcp"+family, func(t *testing.T) {
			origin := processTestTCP(t, "tcp"+family, host)
			for i := 0; i < 2; i++ {
				name, got := finder.lookup(context.Background(), origin)
				if got != path || name != filepath.Base(path) {
					t.Fatal(origin, name, got, path)
				}
			}
			origin.destination = net.JoinHostPort(host, "1")
			if name, _ := finder.lookup(context.Background(), origin); name != "" {
				t.Fatal("wrong destination attributed", name)
			}
		})
		for _, wildcard := range []bool{false, true} {
			for _, connected := range []bool{false, true} {
				t.Run(fmt.Sprintf("udp%s/wildcard=%v/connected=%v", family, wildcard, connected), func(t *testing.T) {
					server, err := net.ListenPacket("udp"+family, net.JoinHostPort(host, "0"))
					if err != nil {
						t.Fatal(err)
					}
					defer server.Close()
					var local net.Addr
					if connected {
						c, err := net.Dial("udp"+family, server.LocalAddr().String())
						if err != nil {
							t.Fatal(err)
						}
						defer c.Close()
						local = c.LocalAddr()
					} else {
						bind := host
						if wildcard {
							bind = ""
						}
						c, err := net.ListenPacket("udp"+family, net.JoinHostPort(bind, "0"))
						if err != nil {
							t.Fatal(err)
						}
						defer c.Close()
						local = c.LocalAddr()
					}
					_, port, _ := net.SplitHostPort(local.String())
					origin := socketOrigin{network: "udp", source: net.JoinHostPort(host, port), destination: server.LocalAddr().String()}
					if name, got := finder.lookup(context.Background(), origin); got != path || name != filepath.Base(path) {
						t.Fatal(origin, name, got, path)
					}
				})
			}
		}
	}
	t.Run("dualstack-udp4", func(t *testing.T) {
		c, err := net.ListenPacket("udp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, port, _ := net.SplitHostPort(c.LocalAddr().String())
		origin := socketOrigin{network: "udp", source: "127.0.0.1:" + port, destination: "127.0.0.1:53"}
		if _, got := finder.lookup(context.Background(), origin); got != path {
			t.Fatal(origin, got)
		}
	})
	for _, origin := range []socketOrigin{
		{network: "tcp", source: "192.0.2.20:12345", destination: "127.0.0.1:80"},
		{network: "tcp", source: "invalid", destination: "127.0.0.1:80"},
		{network: "icmp", source: "127.0.0.1:0", destination: "127.0.0.1:0"},
	} {
		if name, path := finder.lookup(context.Background(), origin); name != "" || path != "" {
			t.Fatal("unattributable request", origin, name, path)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if name, path := finder.lookup(ctx, socketOrigin{network: "tcp", source: "127.0.0.1:12345", destination: "127.0.0.1:80"}); name != "" || path != "" {
		t.Fatal("cancelled discovery", name, path)
	}
}

func TestProcessSocketParser(t *testing.T) {
	src, dst := netip.MustParseAddrPort("127.0.0.1:12345"), netip.MustParseAddrPort("127.0.0.1:443")
	b := make([]byte, 72)
	b[0] = syscall.AF_INET
	binary.BigEndian.PutUint16(b[4:], src.Port())
	binary.BigEndian.PutUint16(b[6:], dst.Port())
	copy(b[8:], src.Addr().AsSlice())
	copy(b[24:], dst.Addr().AsSlice())
	binary.NativeEndian.PutUint32(b[68:], 123)
	if inode, score := matchProcessSocket(b, "tcp", src, dst); inode != 123 || score != 7 {
		t.Fatal(inode, score)
	}
	for n := 0; n < 72; n++ {
		if inode, _ := matchProcessSocket(b[:n], "tcp", src, dst); inode != 0 {
			t.Fatal("truncated inet_diag accepted", n)
		}
	}
	clear(b[6:8])
	clear(b[8:40])
	if inode, score := matchProcessSocket(b, "udp", src, dst); inode != 123 || score != 1 {
		t.Fatal("wildcard UDP", inode, score)
	}
	if inode, _ := matchProcessSocket(b, "tcp", src, dst); inode != 0 {
		t.Fatal("wildcard TCP accepted")
	}
	b[0] = syscall.AF_INET6
	if inode, _ := matchProcessSocket(b, "udp", src, dst); inode != 0 {
		t.Fatal("unknown IPv6-only state accepted for v4")
	}
	attr := make([]byte, 8)
	binary.NativeEndian.PutUint16(attr, 5)
	binary.NativeEndian.PutUint16(attr[2:], 11)
	b = append(b, attr...)
	if inode, _ := matchProcessSocket(b, "udp", src, dst); inode != 123 {
		t.Fatal("dual stack not matched")
	}
	b[76] = 1
	if inode, _ := matchProcessSocket(b, "udp", src, dst); inode != 0 {
		t.Fatal("IPv6-only matched v4")
	}
}

func TestProcessProxyRouting(t *testing.T) {
	path := processTestPath(t)
	for _, field := range []string{"name", "path", "regex", "logical", "set", "log-only", "sniff"} {
		t.Run(field, func(t *testing.T) {
			condition := Rule{ProcessName: []string{filepath.Base(path)}, Outbound: "direct"}
			route := Route{Final: "deny"}
			switch field {
			case "path":
				condition = Rule{ProcessPath: []string{path}, Outbound: "direct"}
			case "regex":
				condition = Rule{ProcessPathRegex: []string{"^" + regexp.QuoteMeta(path) + "$"}, Outbound: "direct"}
			case "logical":
				condition = Rule{Type: "logical", Mode: "and", Rules: []Rule{{ProcessName: []string{filepath.Base(path)}}, {Network: []string{"tcp"}}}, Outbound: "direct"}
			case "set":
				route.RuleSet = []RuleSet{{Type: "inline", Tag: "apps", Rules: []Rule{{ProcessPath: []string{path}}}}}
				condition = Rule{RuleSet: []string{"apps"}, Outbound: "direct"}
			case "log-only":
				route.FindProcess = true
				condition = Rule{Outbound: "direct"}
			case "sniff":
				route.Rules = []Rule{{Action: "sniff", Sniffer: []string{"http"}}}
			}
			route.Rules = append(route.Rules, condition)
			r, logs := loggingRuntime(t, Config{Inbounds: []Inbound{{Type: "mixed", Tag: "local", Listen: "127.0.0.1"}}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "deny"}}, Route: route})
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { io.WriteString(w, "routed") }))
			defer origin.Close()
			proxy, _ := url.Parse("http://" + r.Address("local"))
			transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			resp, err := client.Get(origin.URL)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || string(body) != "routed" {
				t.Fatal(string(body), err)
			}
			if logs.FilterMessageSnippet("router: found process path: "+path).Len() == 0 || logs.FilterMessageSnippet("outbound/direct[direct]: outbound connection to").Len() == 0 {
				t.Fatal("missing discovered process in connection log", logs.All())
			}
		})
	}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "socks", Tag: "server", Listen: "127.0.0.1"}}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "deny"}}, Route: Route{Final: "deny", Rules: []Rule{{ProcessPath: []string{path}, Outbound: "direct"}}}})
	out := testOutbound(t, Inbound{Type: "socks"}, server.Address("server"))
	out.Username, out.Password = "", ""
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	assertTCP(t, client)
	assertUDP(t, client)
}

func TestProcessPreserveMetadataAndDynamicSets(t *testing.T) {
	r := newTestRuntime(t, Config{Route: Route{RuleSet: []RuleSet{{Type: "inline", Tag: "dynamic", Rules: []Rule{{IPCIDR: []string{"192.0.2.0/24"}}}}}, Rules: []Rule{{RuleSet: []string{"dynamic"}, Outbound: "direct"}}}})
	if r.needsProcess() {
		t.Fatal("IP-only set enabled process discovery")
	}
	snapshot, err := compileRuleSet([]Rule{{ProcessName: []string{"app"}}})
	if err != nil {
		t.Fatal(err)
	}
	r.ruleSets["dynamic"].store(snapshot)
	if !r.needsProcess() {
		t.Fatal("updated process rule not discovered")
	}
	q := request{metadata: Metadata{ProcessName: "supplied", ProcessPath: "/supplied"}}
	r.enrichProcess(context.Background(), &q)
	if q.metadata.ProcessName != "supplied" || q.metadata.ProcessPath != "/supplied" {
		t.Fatal("caller metadata overwritten", q.metadata)
	}
	snapshot, _ = compileRuleSet([]Rule{{IPCIDR: []string{"192.0.2.0/24"}}})
	r.ruleSets["dynamic"].store(snapshot)
	if r.needsProcess() {
		t.Fatal("removed process rule retained")
	}
	for _, condition := range []Rule{{ProcessPathRegex: []string{".*"}}, {ProcessName: []string{""}}} {
		condition.Outbound = "direct"
		rules, err := compileRoute(Route{Final: "direct", Rules: []Rule{condition}}, map[string]Outbound{"direct": {Type: "direct"}})
		if err != nil || rules[0].matches(request{}) {
			t.Fatal("absent metadata matched a process condition", condition, err)
		}
	}
}

func TestProcessConcurrentDiscovery(t *testing.T) {
	origin := processTestTCP(t, "tcp4", "127.0.0.1")
	finder := &processFinder{}
	path := processTestPath(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Go(func() {
			if _, got := finder.lookup(context.Background(), origin); got != path {
				t.Error("concurrent lookup", got)
			}
		})
	}
	wg.Wait()
}

func TestProcessChildAndClosedSocket(t *testing.T) {
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.DialTCP("tcp4", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	peer, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	origin := socketOrigin{network: "tcp", source: c.LocalAddr().String(), destination: c.RemoteAddr().String()}
	file, err := c.File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	child := exec.Command("/bin/sleep", "30")
	child.ExtraFiles = []*os.File{file}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	c.Close()
	file.Close()
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", child.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	finder := &processFinder{}
	for i := 0; i < 2; i++ {
		if name, got := finder.lookup(context.Background(), origin); name != "sleep" || got != path {
			t.Fatal("request attributed to wrong process", name, got, path)
		}
	}
	child.Process.Kill()
	child.Wait()
	if name, got := finder.lookup(context.Background(), origin); name != "" || got != "" {
		t.Fatal("closed socket retained cached identity", name, got)
	}
}

func TestProcessDNSRouting(t *testing.T) {
	path := processTestPath(t)
	for _, family := range []string{"4", "6"} {
		for _, network := range []string{"tcp", "udp"} {
			t.Run(network+family, func(t *testing.T) {
				host := "127.0.0.1"
				if family == "6" {
					host = "::1"
				}
				r := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "dns", Tag: "dns", Listen: host}}, DNS: DNSConfig{Rules: []DNSRule{{Rule: Rule{ProcessPath: []string{path}, Action: "predefined"}, Answer: []string{"process.test. 60 IN A 192.0.2.9"}}, {Rule: Rule{Action: "reject"}}}}})
				checkProcessDNS(t, network+family, r.Address("dns"))
			})
		}
	}
}

func TestProcessHTTPTransports(t *testing.T) {
	path := processTestPath(t)
	for _, tc := range []struct {
		kind, transport string
		version         int
	}{
		{"naive", "", 2}, {"naive", "", 3}, {"trusttunnel", "", 2}, {"trusttunnel", "", 3},
		{"masque", "", 1}, {"masque", "", 2}, {"masque", "", 3},
		{"vless", "http", 2}, {"vless", "grpc", 2},
		{"vless", "xhttp", 1}, {"vless", "xhttp", 2}, {"vless", "xhttp", 3},
	} {
		t.Run(fmt.Sprintf("%s/%s/%d", tc.kind, tc.transport, tc.version), func(t *testing.T) {
			in := testInbound(t, tc.kind)
			in.TLS = certificate(t)
			switch tc.kind {
			case "naive", "trusttunnel", "masque":
				in.Users = []User{{Username: "client", Password: "private"}}
				if tc.kind != "naive" {
					in.HTTPVersion = tc.version
				}
			}
			if tc.transport != "" {
				in.Transport = Transport{Type: tc.transport}
				if tc.transport == "xhttp" {
					in.Transport.XHTTPOptions.Mode = "stream-one"
					if tc.version == 1 {
						in.TLS = TLSOptions{}
					} else if tc.version == 3 {
						in.TLS.ALPN = []string{"h3"}
					}
				}
			}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "deny"}}, Route: Route{Final: "deny", Rules: []Rule{{ProcessPath: []string{path}, Outbound: "direct"}}}})
			out := testOutbound(t, in, server.Address("server"))
			out.Transport = in.Transport
			if tc.version == 3 && tc.transport == "xhttp" {
				out.TLS.ALPN = []string{"h3"}
			}
			switch tc.kind {
			case "naive":
				out.QUIC, out.UDPOverTCP = tc.version == 3, true
			case "masque":
				out.HTTPVersion, out.MasqueOptions.Mode = tc.version, "udp"
			case "trusttunnel":
				out.HTTPVersion = tc.version
			}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{511})
		})
	}
}

func TestProcessHTTPAddresses(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		var address net.Addr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}
		if network == "udp" {
			address = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}
		}
		req := httptest.NewRequest("CONNECT", "https://untrusted.example:443", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, address))
		local, remote := httpStreamAddresses(req)
		if local.String() != address.String() || remote.String() != req.RemoteAddr || remote.Network() != network {
			t.Fatal("HTTP authority used as socket address", local, remote)
		}
	}
}

func checkProcessDNS(t *testing.T, network, address string) {
	t.Helper()
	c, err := net.DialTimeout(network, address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	query, _ := makeDNSQuery("process.test", 1)
	if network[:3] == "tcp" {
		writeAll(c, binary.BigEndian.AppendUint16(nil, uint16(len(query))))
	}
	if err := writeAll(c, query); err != nil {
		t.Fatal(err)
	}
	var reply []byte
	if network[:3] == "tcp" {
		var size [2]byte
		if _, err := io.ReadFull(c, size[:]); err != nil {
			t.Fatal(err)
		}
		reply = make([]byte, int(binary.BigEndian.Uint16(size[:])))
		_, err = io.ReadFull(c, reply)
	} else {
		reply = make([]byte, 4096)
		var n int
		n, err = c.Read(reply)
		reply = reply[:n]
	}
	if err != nil {
		t.Fatal(err)
	}
	ips, _, err := parseDNSReply(query, reply)
	if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.9" {
		t.Fatal("process DNS rule did not match", ips, err)
	}
}

func TestProcessTUNNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_PROCESS_TUN") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^TestProcessTUNNamespace$", "-test.v", "-test.timeout=45s")
		cmd.Env = append(os.Environ(), "LANBOAT_PROCESS_TUN=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated process TUN: %v\n%s", err, output)
		}
		t.Log(string(output))
		return
	}
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = configureLink(loopback.Index, 65536); err != nil {
		t.Fatal(err)
	}
	path := processTestPath(t)
	for _, redirect := range []bool{false, true} {
		t.Run(fmt.Sprint("redirect=", redirect), func(t *testing.T) {
			proxy := socksEchoProxy(t)
			out := testOutbound(t, Inbound{Type: "socks"}, proxy)
			out.Username, out.Password = "", ""
			r := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "tun", Tag: "tun", AutoRoute: true, AutoRedirect: redirect, StrictRoute: true, DNSMode: "hijack"}}, Outbounds: []Outbound{out, {Type: "block", Tag: "deny"}}, Route: Route{Final: "deny", Rules: []Rule{{ProcessPath: []string{path}, Outbound: "proxy"}}}, DNS: DNSConfig{Rules: []DNSRule{{Rule: Rule{ProcessPath: []string{path}, Action: "predefined"}, Answer: []string{"process.test. 60 IN A 192.0.2.9"}}, {Rule: Rule{Action: "reject"}}}}})
			defer r.Close()
			for _, tc := range []struct{ network, target string }{
				{"tcp4", "203.0.113.21:443"}, {"tcp6", "[2001:db8::21]:443"},
				{"udp4", "203.0.113.22:9000"}, {"udp6", "[2001:db8::22]:9000"},
			} {
				c, err := net.DialTimeout(tc.network, tc.target, 3*time.Second)
				if err != nil {
					t.Fatal(tc, err)
				}
				c.SetDeadline(time.Now().Add(3 * time.Second))
				if err := writeAll(c, []byte("process TUN")); err != nil {
					c.Close()
					t.Fatal(tc, err)
				}
				var reply [11]byte
				_, err = io.ReadFull(c, reply[:])
				c.Close()
				if err != nil || string(reply[:]) != "process TUN" {
					t.Fatal(tc, string(reply[:]), err)
				}
			}
			for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
				address := "9.9.9.9:53"
				if network[3:] == "6" {
					address = "[2001:4860:4860::8888]:53"
				}
				checkProcessDNS(t, network, address)
			}
		})
	}
}

func BenchmarkProcessDisabled(b *testing.B) {
	r := &Runtime{}
	local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}
	b.ReportAllocs()
	for b.Loop() {
		if r.socketOrigin(local, local) != nil {
			b.Fatal("disabled process discovery allocated an origin")
		}
	}
}

func FuzzProcessSocket(f *testing.F) {
	b := make([]byte, 80)
	b[0] = syscall.AF_INET6
	binary.BigEndian.PutUint16(b[4:], 12345)
	binary.NativeEndian.PutUint32(b[68:], 123)
	binary.NativeEndian.PutUint16(b[72:], 5)
	binary.NativeEndian.PutUint16(b[74:], 11)
	f.Add(b)
	f.Add([]byte{10, 0, 0, 0})
	src, dst := netip.MustParseAddrPort("127.0.0.1:12345"), netip.MustParseAddrPort("127.0.0.1:443")
	f.Fuzz(func(t *testing.T, b []byte) {
		matchProcessSocket(b, "tcp", src, dst)
		matchProcessSocket(b, "udp", src, dst)
	})
}
