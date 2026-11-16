package native

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNetworkStrategyLinuxNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_MULTINET_CHILD") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run=^TestNetworkStrategyLinuxNamespace$", "-test.v", "-test.timeout=120s")
		cmd.Env = append(os.Environ(), "LANBOAT_MULTINET_CHILD=1")
		b, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("multi-network namespace: %v %s", e, b)
		}
		t.Log(string(b))
		return
	}
	tunIP(t, "link", "set", "lo", "up")
	peer, e := startNamespace(context.Background(), NetworkNamespaceOptions{Type: "unshare"}, Route{})
	if e != nil {
		t.Fatal(e)
	}
	defer peer.close()
	peerIP := func(args ...string) {
		t.Helper()
		all := append([]string{"-t", strconv.Itoa(peer.command.Process.Pid), "-n", "ip"}, args...)
		if b, e := exec.Command("nsenter", all...).CombinedOutput(); e != nil {
			t.Fatal(string(b), e)
		}
	}
	for i, name := range []string{"lbfirst", "lbsecond"} {
		j := strconv.Itoa(i + 1)
		remote := "peer" + j
		tunIP(t, "link", "add", name, "type", "veth", "peer", "name", remote)
		tunIP(t, "link", "set", remote, "netns", strconv.Itoa(peer.command.Process.Pid))
		tunIP(t, "addr", "add", "10.61."+j+".1/24", "dev", name)
		tunIP(t, "-6", "addr", "add", "fd61:"+j+"::1/64", "dev", name, "nodad")
		tunIP(t, "link", "set", name, "up")
		peerIP("addr", "add", "10.61."+j+".2/24", "dev", remote)
		peerIP("-6", "addr", "add", "fd61:"+j+"::2/64", "dev", remote, "nodad")
		peerIP("link", "set", remote, "up")
		metric := strconv.Itoa((i + 1) * 10)
		tunIP(t, "route", "add", "default", "via", "10.61."+j+".2", "dev", name, "metric", metric)
		tunIP(t, "-6", "route", "add", "default", "via", "fd61:"+j+"::2", "dev", name, "metric", metric)
	}
	tunIP(t, "-6", "route", "replace", "default", "via", "fd61:2::2", "dev", "lbsecond", "metric", "5")
	peerIP("addr", "add", "198.51.100.80/32", "dev", "lo")
	peerIP("-6", "addr", "add", "2001:db8:61::80/128", "dev", "lo", "nodad")
	var choices []networkChoice
	base := newTestRuntime(t, Config{Route: Route{AutoDetectInterface: true}})
	state := systemNetworkMetadata(context.Background(), base)
	for _, c := range state.networkChoices {
		if c.Name == "lbfirst" {
			c.Kind = "wifi"
			choices = append(choices, c)
		}
		if c.Name == "lbsecond" {
			c.Kind = "cellular"
			choices = append(choices, c)
		}
	}
	if len(choices) != 2 {
		t.Fatal("real interfaces not discovered", state.networkChoices)
	}
	newClient := func(o NetworkOptions, route bool) *Runtime {
		t.Helper()
		cfg := Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct", DialOptions: DialOptions{NetworkOptions: o}}}, Route: Route{AutoDetectInterface: true}}
		if route {
			cfg.Outbounds[0].NetworkOptions = NetworkOptions{}
			cfg.Route.Rules = []Rule{{Action: "route-options", NetworkOptions: NetworkOptions{NetworkStrategy: o.NetworkStrategy, FallbackNetworkType: o.FallbackNetworkType, FallbackDelay: o.FallbackDelay}, NetworkType: o.NetworkType}}
		}
		r := newTestRuntime(t, cfg)
		r.network.read = func(context.Context, *Runtime) Metadata { return Metadata{networkChoices: choices} }
		return r
	}
	startEcho := func(ip string) (string, string) {
		t.Helper()
		network := "tcp4"
		udp := "udp4"
		if strings.Contains(ip, ":") {
			network, udp = "tcp6", "udp6"
		}
		l, e := peer.listen(context.Background(), ListenOptions{}, network, net.JoinHostPort(ip, "0"))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, e := l.Accept()
				if e != nil {
					return
				}
				go func() {
					defer c.Close()
					c.SetDeadline(time.Now().Add(5 * time.Second))
					b := make([]byte, 128)
					n, e := c.Read(b)
					if e == nil {
						fmt.Fprintf(c, "%s|%s", c.RemoteAddr(), b[:n])
					}
				}()
			}
		}()
		p, e := peer.packet(context.Background(), DialOptions{}, ListenOptions{}, udp, net.JoinHostPort(ip, "0"), "", true)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { p.Close() })
		go func() {
			b := make([]byte, 4096)
			for {
				n, a, e := p.ReadFrom(b)
				if e != nil {
					return
				}
				p.WriteTo(append([]byte(a.String()+"|"), b[:n]...), a)
			}
		}()
		return l.Addr().String(), p.LocalAddr().String()
	}
	tcp4, udp4 := startEcho("198.51.100.80")
	tcp6, udp6 := startEcho("2001:db8:61::80")
	exchange := func(t *testing.T, r *Runtime, network, target, prefix string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, e := r.Dial(ctx, network, target)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		c.Write([]byte("selection"))
		b := make([]byte, 4096)
		n, e := c.Read(b)
		if e != nil || !bytes.Contains(b[:n], []byte("selection")) || prefix != "" && !strings.HasPrefix(string(b[:n]), prefix) {
			t.Fatal(string(b[:n]), e)
		}
	}
	for _, strategy := range []string{"default", "hybrid"} {
		for _, route := range []bool{false, true} {
			t.Run(strategy+fmt.Sprint(route), func(t *testing.T) {
				r := newClient(NetworkOptions{NetworkStrategy: strategy, NetworkType: []string{"cellular"}}, route)
				exchange(t, r, "tcp", tcp4, "10.61.2.1:")
				exchange(t, r, "udp", udp4, "10.61.2.1:")
				exchange(t, r, "tcp", tcp6, "[fd61:2::1]:")
				exchange(t, r, "udp", udp6, "[fd61:2::1]:")
			})
		}
	}
	t.Run("default-route", func(t *testing.T) {
		r := newClient(NetworkOptions{NetworkStrategy: "default"}, false)
		exchange(t, r, "tcp", tcp4, "10.61.1.1:")
		exchange(t, r, "tcp", tcp6, "[fd61:2::1]:")
	})
	nft := func(script string) {
		t.Helper()
		if _, e := tunCommand("/usr/sbin/nft", script, "-f", "-"); e != nil {
			t.Fatal(e)
		}
	}
	t.Run("fallback-blackhole-and-recovery", func(t *testing.T) {
		_, port, _ := net.SplitHostPort(tcp4)
		nft("add table inet lbselection\nadd chain inet lbselection out { type filter hook output priority 0; policy accept; }\nadd rule inet lbselection out oifname lbfirst tcp dport " + port + " drop\n")
		defer tunCommand("/usr/sbin/nft", "", "delete", "table", "inet", "lbselection")
		r := newClient(NetworkOptions{NetworkStrategy: "fallback", NetworkType: []string{"wifi"}, FallbackNetworkType: []string{"cellular"}, FallbackDelay: "500ms"}, false)
		before := time.Now()
		exchange(t, r, "tcp", tcp4, "10.61.2.1:")
		if d := time.Since(before); d < 400*time.Millisecond || d > 2*time.Second {
			t.Fatal("fallback delay", d)
		}
		key := (NetworkOptions{NetworkType: []string{"wifi"}, FallbackNetworkType: []string{"cellular"}}).key(netip.MustParseAddr("198.51.100.80"))
		if !r.network.fastFallback(key) {
			t.Fatal("fast fallback missing")
		}
		before = time.Now()
		exchange(t, r, "tcp", tcp4, "10.61.2.1:")
		if time.Since(before) > 200*time.Millisecond {
			t.Fatal("fast fallback delayed")
		}
		nft("flush chain inet lbselection out\nadd rule inet lbselection out oifname lbsecond tcp dport " + port + " drop\n")
		exchange(t, r, "tcp", tcp4, "10.61.1.1:")
		if r.network.fastFallback(key) {
			t.Fatal("preferred recovery did not exit fast mode")
		}
	})
	t.Run("down-link-udp", func(t *testing.T) {
		r := newClient(NetworkOptions{NetworkStrategy: "fallback", NetworkType: []string{"wifi"}, FallbackNetworkType: []string{"cellular"}, FallbackDelay: "2s"}, true)
		tunIP(t, "link", "set", "lbfirst", "down")
		defer func() {
			tunIP(t, "link", "set", "lbfirst", "up")
			tunIP(t, "-6", "addr", "replace", "fd61:1::1/64", "dev", "lbfirst", "nodad")
			tunIP(t, "route", "replace", "default", "via", "10.61.1.2", "dev", "lbfirst", "metric", "10")
			tunIP(t, "-6", "route", "replace", "default", "via", "fd61:1::2", "dev", "lbfirst", "metric", "10")
		}()
		exchange(t, r, "udp", udp4, "10.61.2.1:")
	})
	t.Run("http-downloader", func(t *testing.T) {
		l, e := peer.listen(context.Background(), ListenOptions{}, "tcp4", "198.51.100.80:0")
		if e != nil {
			t.Fatal(e)
		}
		s := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { io.WriteString(w, q.RemoteAddr) })}
		defer s.Close()
		go s.Serve(l)
		r := newTestRuntime(t, Config{HTTPClients: []HTTPClientOptions{{Tag: "download", DialOptions: DialOptions{NetworkOptions: NetworkOptions{NetworkStrategy: "default", NetworkType: []string{"cellular"}}}}}})
		r.network.read = func(context.Context, *Runtime) Metadata { return Metadata{networkChoices: choices} }
		c, tr, e := r.ruleHTTPClient(RuleSet{HTTPClient: "download"})
		if e != nil {
			t.Fatal(e)
		}
		defer tr.CloseIdleConnections()
		res, e := c.Get("http://" + l.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		if !strings.HasPrefix(string(b), "10.61.2.1:") {
			t.Fatal(string(b))
		}
	})
	t.Run("namespaced-dialer", func(t *testing.T) {
		r := newTestRuntime(t, Config{NetworkNamespaces: []NetworkNamespaceOptions{{Tag: "current", Path: "/proc/self/ns/net"}}, Outbounds: []Outbound{{Type: "direct", Tag: "direct", DialOptions: DialOptions{NetNS: "current", NetworkOptions: NetworkOptions{NetworkStrategy: "default"}}}}, Route: Route{AutoDetectInterface: true}})
		exchange(t, r, "tcp", tcp4, "10.61.1.1:")
		exchange(t, r, "tcp", tcp6, "[fd61:2::1]:")
	})
	t.Run("bound-outbound-ignores-rule", func(t *testing.T) {
		r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct", DialOptions: DialOptions{BindInterface: "lbfirst"}}}, Route: Route{Rules: []Rule{{NetworkOptions: NetworkOptions{NetworkStrategy: "hybrid"}, NetworkType: []string{"cellular"}, Outbound: "direct"}}}})
		r.network.read = func(context.Context, *Runtime) Metadata {
			t.Error("explicit binding must not discover networks")
			return Metadata{}
		}
		exchange(t, r, "tcp", tcp4, "10.61.1.1:")
		exchange(t, r, "tcp", tcp6, "[fd61:1::1]:")
	})
	t.Run("dns-upstream", func(t *testing.T) {
		p, e := peer.packet(context.Background(), DialOptions{}, ListenOptions{}, "udp4", "198.51.100.80:0", "", true)
		if e != nil {
			t.Fatal(e)
		}
		defer p.Close()
		source := make(chan string, 1)
		go func() {
			b := make([]byte, 4096)
			n, from, e := p.ReadFrom(b)
			if e == nil {
				source <- from.String()
				p.WriteTo(dnsAnswer(b[:n]), from)
			}
		}()
		host, port := splitAddress(t, p.LocalAddr().String())
		r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "udp", Tag: "upstream", Server: host, ServerPort: port, DialOptions: DialOptions{NetworkOptions: NetworkOptions{NetworkStrategy: "default", NetworkType: []string{"cellular"}}}}}}})
		r.network.read = func(context.Context, *Runtime) Metadata { return Metadata{networkChoices: choices} }
		query, _ := makeDNSQuery("selection.test", 1)
		answer, e := r.ExchangeDNS(context.Background(), query, "")
		if e != nil {
			t.Fatal(e)
		}
		ips, _, e := parseDNSReply(query, answer)
		if e != nil || len(ips) != 1 || ips[0].String() != "192.0.2.42" {
			t.Fatal(ips, e)
		}
		if from := <-source; !strings.HasPrefix(from, "10.61.2.1:") {
			t.Fatal(from)
		}
	})
	t.Run("proxy-route-option-isolation", func(t *testing.T) {
		server := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "socks", Tag: "proxy", Listen: "127.0.0.1"}}})
		out := testOutbound(t, Inbound{Type: "socks"}, server.Address("proxy"))
		out.Username, out.Password = "", ""
		out.Detour = "gateway"
		r := newTestRuntime(t, Config{Outbounds: []Outbound{out, {Type: "direct", Tag: "gateway"}}, Route: Route{Final: "proxy", Rules: []Rule{{Outbound: "proxy", NetworkType: []string{"cellular"}, NetworkOptions: NetworkOptions{NetworkStrategy: "hybrid"}}}}})
		r.network.read = func(context.Context, *Runtime) Metadata {
			t.Error("proxy gateway inherited direct routing policy")
			return Metadata{}
		}
		exchange(t, r, "tcp", tcp4, "10.61.1.1:")
	})
	t.Run("namespaced-faketcp", func(t *testing.T) {
		p, e := listenFakeTCP(context.Background(), "198.51.100.80:0", ListenOptions{NetNS: "peer", namespace: peer})
		if e != nil {
			t.Fatal(e)
		}
		defer p.Close()
		go func() {
			b := make([]byte, 4096)
			n, a, e := p.ReadFrom(b)
			if e == nil {
				p.WriteTo(b[:n], a)
			}
		}()
		host, port := splitAddress(t, p.LocalAddr().String())
		r := newTestRuntime(t, Config{NetworkNamespaces: []NetworkNamespaceOptions{{Tag: "current", Path: "/proc/self/ns/net"}}, HTTPClients: []HTTPClientOptions{{Tag: "namespace", DialOptions: DialOptions{NetNS: "current"}}}})
		r.network.read = func(context.Context, *Runtime) Metadata {
			t.Error("namespace must discover its own interfaces")
			return Metadata{}
		}
		c, e := r.dialFakeTCP(context.Background(), Outbound{Server: host, ServerPort: port, DialOptions: DialOptions{NetNS: "current", namespace: r.namespaces["current"], NetworkOptions: NetworkOptions{NetworkStrategy: "hybrid", NetworkType: []string{"other"}}}})
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write([]byte("raw selection"))
		b := make([]byte, 4096)
		n, e := c.Read(b)
		if e != nil || string(b[:n]) != "raw selection" {
			t.Fatal(string(b[:n]), e)
		}
	})

	t.Run("icmp-selected-interface", func(t *testing.T) {
		r := newClient(NetworkOptions{NetworkStrategy: "default", NetworkType: []string{"cellular"}}, false)
		for _, ip := range []string{"198.51.100.80", "2001:db8:61::80"} {
			packet := []byte{8, 0, 0, 0, 0, 1, 0, 1}
			target := netip.MustParseAddr(ip)
			if target.Is6() {
				packet[0] = 128
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_, e := r.directICMPExchange(ctx, target, packet, 64, r.config.Outbounds[0].DialOptions)
			cancel()
			if e != nil {
				t.Fatal(e)
			}
		}
	})

}
