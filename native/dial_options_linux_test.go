package native

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"
)

func dialOptionInt(t *testing.T, raw syscall.RawConn, level, option int) int {
	t.Helper()
	var value int
	var err error
	if e := raw.Control(func(fd uintptr) { value, err = syscall.GetsockoptInt(int(fd), level, option) }); e != nil {
		t.Fatal(e)
	}
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestDialOptionsLinuxTCP(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprint(disabled), func(t *testing.T) {
			o := DialOptions{Inet4BindAddress: "127.0.0.2", ReuseAddr: true, BindAddressNoPort: true, TCPFastOpen: true, DisableTCPKeepAlive: disabled}
			if !disabled {
				o.TCPKeepAlive, o.TCPKeepAliveInterval = "5s", "2s"
			}
			r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", DialOptions: o}}})
			conn, err := r.Dial(context.Background(), "tcp", tcpEcho(t))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if conn.LocalAddr().(*net.TCPAddr).IP.String() != "127.0.0.2" {
				t.Fatal("source binding ignored", conn.LocalAddr())
			}
			raw, err := conn.(*ownedConn).Conn.(*net.TCPConn).SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			for _, option := range [][3]int{{syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1}, {syscall.IPPROTO_IP, 24, 1}, {syscall.IPPROTO_TCP, 30, 1}} {
				if got := dialOptionInt(t, raw, option[0], option[1]); got != option[2] {
					t.Fatal("socket option ignored", option, got)
				}
			}
			keep := dialOptionInt(t, raw, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
			if disabled && keep != 0 || !disabled && keep != 1 {
				t.Fatal("keepalive", disabled, keep)
			}
			if !disabled && (dialOptionInt(t, raw, syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE) != 5 || dialOptionInt(t, raw, syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL) != 2) {
				t.Fatal("keepalive periods ignored")
			}
			conn.SetDeadline(time.Now().Add(time.Second))
			if err := writeAll(conn, []byte("echo")); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 4)
			if _, err := io.ReadFull(conn, got); err != nil || string(got) != "echo" {
				t.Fatal(err, string(got))
			}
		})
	}
}

func TestDialOptionsLinuxUDP(t *testing.T) {
	for _, family := range []string{"4", "6"} {
		for _, fragment := range []bool{false, true} {
			t.Run(family+fmt.Sprint(fragment), func(t *testing.T) {
				local, target := "127.0.0.2", "127.0.0.1:9"
				o := DialOptions{UDPFragment: &fragment, Inet4BindAddress: local}
				level, option := syscall.IPPROTO_IP, 10
				if family == "6" {
					local, target = "::1", "[::1]:9"
					o.Inet4BindAddress, o.Inet6BindAddress = "", local
					level, option = syscall.IPPROTO_IPV6, 23
				}
				r := newTestRuntime(t, Config{})
				conn, err := r.dialSocket(context.Background(), o, "udp"+family, target)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				raw, err := conn.(*net.UDPConn).SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				mode := 2
				if fragment {
					mode = 0
				}
				if got := dialOptionInt(t, raw, level, option); got != mode || conn.LocalAddr().(*net.UDPAddr).IP.String() != local {
					t.Fatal("UDP options ignored", got, conn.LocalAddr())
				}
				packet, err := r.listenPacketWithOptions(context.Background(), o, "udp"+family, ":0", target)
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Close()
				if packet.LocalAddr().(*net.UDPAddr).IP.String() != local {
					t.Fatal("shared UDP source ignored", packet.LocalAddr())
				}
			})
		}
	}
}

func TestDialOptionsLinuxInterfaceOverride(t *testing.T) {
	r := newTestRuntime(t, Config{Route: Route{DefaultInterface: "lanboat-missing"}, Outbounds: []Outbound{{Type: "direct", DialOptions: DialOptions{BindInterface: "lo"}}}})
	conn, err := r.Dial(context.Background(), "tcp", tcpEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestDialOptionsLinuxDNSAndDownload(t *testing.T) {
	t.Run("dns", func(t *testing.T) {
		server, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		peer := make(chan string, 1)
		go func() {
			b := make([]byte, 4096)
			n, from, err := server.ReadFrom(b)
			if err == nil {
				peer <- from.(*net.UDPAddr).IP.String()
				server.WriteTo(dnsAnswer(b[:n]), from)
			}
		}()
		host, port := splitTestAddress(t, server.LocalAddr().String())
		r := newTestRuntime(t, Config{DNS: DNSConfig{Strategy: "ipv4_only", Servers: []DNSServer{{Type: "udp", Server: host, ServerPort: port, DialOptions: DialOptions{Inet4BindAddress: "127.0.0.2"}}}}})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := r.resolver.lookupReal(ctx, "binding.test"); err != nil {
			t.Fatal(err)
		}
		if got := <-peer; got != "127.0.0.2" {
			t.Fatal("DNS source ignored", got)
		}
	})
	t.Run("download", func(t *testing.T) {
		peer := make(chan string, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			host, _, _ := net.SplitHostPort(req.RemoteAddr)
			peer <- host
			io.WriteString(w, "ok")
		}))
		defer server.Close()
		r := newTestRuntime(t, Config{HTTPClients: []HTTPClientOptions{{Tag: "fetch", DialOptions: DialOptions{Inet4BindAddress: "127.0.0.2"}}}})
		client, transport, err := r.ruleHTTPClient(RuleSet{HTTPClient: "fetch"})
		if err != nil {
			t.Fatal(err)
		}
		defer transport.CloseIdleConnections()
		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := <-peer; got != "127.0.0.2" {
			t.Fatal("download source ignored", got)
		}
	})
}

func TestDialOptionsLinuxDetourOwnsSocket(t *testing.T) {
	in := testInbound(t, "socks")
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := testOutbound(t, in, server.Address("server"))
	o.Detour = "upstream"
	o.BindInterface = "lanboat-missing"
	r := newTestRuntime(t, Config{Outbounds: []Outbound{o, {Type: "direct", Tag: "upstream", DialOptions: DialOptions{Inet4BindAddress: "127.0.0.2"}}}})
	conn, err := r.Dial(context.Background(), "tcp", tcpEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	for conn := range r.connections {
		if a, ok := conn.LocalAddr().(*net.TCPAddr); ok && a.IP.String() == "127.0.0.2" {
			return
		}
	}
	t.Fatal("detour's source binding was not used")
}

func TestDialOptionsTUNMarkCannotBeOverridden(t *testing.T) {
	r := newTestRuntime(t, Config{})
	r.protectMark.Store(0x2024)
	_, err := r.directWithOptions(context.Background(), DialOptions{RoutingMark: 1}, "tcp", "127.0.0.1:1")
	if err == nil || !strings.Contains(err.Error(), "protection mark") {
		t.Fatal("TUN loop protection was overridden", err)
	}
}

func TestDialOptionsLinuxHexMark(t *testing.T) {
	cfg, err := Parse([]byte(`{"route":{"default_mark":"0x2024"},"outbounds":[{"type":"direct","routing_mark":"0xff"}]}`))
	if err != nil || cfg.Route.DefaultMark != 0x2024 || cfg.Outbounds[0].RoutingMark != 255 {
		t.Fatal(cfg.Route.DefaultMark, err)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil || strings.Contains(string(encoded), "0x") {
		t.Fatal(err, string(encoded))
	}
}

func TestDialOptionsSS2022OutboundIsolation(t *testing.T) {
	origins := make([]net.PacketConn, 2)
	for i := range origins {
		var err error
		origins[i], err = net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer origins[i].Close()
	}
	in := ss2022Inbound(ss2022Methods[0], false)
	_, port := splitTestAddress(t, origins[0].LocalAddr().String())
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{
		{Type: "direct", Tag: "one", DialOptions: DialOptions{Inet4BindAddress: "127.0.0.2"}},
		{Type: "direct", Tag: "two", DialOptions: DialOptions{Inet4BindAddress: "127.0.0.3"}},
	}, Route: Route{Rules: []Rule{{Port: []uint16{port}, Outbound: "one"}}, Final: "two"}})
	key, err := newSS2022Key(in.Method, in.Password)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := newSS2022Sender(key, [8]byte{})
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.Dial("udp4", server.Address(in.Tag))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	for i, origin := range origins {
		packet, err := sender.seal(origin.LocalAddr().String(), []byte("isolated"), false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(packet); err != nil {
			t.Fatal(err)
		}
		origin.SetDeadline(time.Now().Add(time.Second))
		b := make([]byte, 2048)
		n, from, err := origin.ReadFrom(b)
		if err != nil {
			t.Fatal(err)
		}
		if got := from.(*net.UDPAddr).IP.String(); got != fmt.Sprintf("127.0.0.%d", i+2) {
			t.Fatal("different direct outbounds shared a source socket", i, got)
		}
		origin.WriteTo(b[:n], from)
		n, err = client.Read(b)
		if err != nil {
			t.Fatal(err)
		}
		message, err := openSS2022Packet(key, b[:n], false, nil)
		if err != nil || string(message.payload) != "isolated" {
			t.Fatal("reply", err)
		}
	}
}

func TestDialOptionsTailscalePacketBinding(t *testing.T) {
	fragment := true
	r := newTestRuntime(t, Config{})
	c := &tailscaleClient{r: r, ctx: r.ctx, o: Outbound{DialOptions: DialOptions{Inet4BindAddress: "127.0.0.2", UDPFragment: &fragment, ReuseAddr: true}}}
	packet, err := c.listenPacket(0)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	if got := packet.LocalAddr().(*net.UDPAddr).IP.String(); got != "127.0.0.2" {
		t.Fatal("Tailscale shared UDP ignored source binding", got)
	}
	raw, err := packet.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if dialOptionInt(t, raw, syscall.IPPROTO_IP, 10) != 0 || dialOptionInt(t, raw, syscall.SOL_SOCKET, syscall.SO_REUSEADDR) != 1 {
		t.Fatal("Tailscale shared UDP ignored options")
	}
}
