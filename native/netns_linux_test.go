package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"

	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func namespaceEcho(t *testing.T, n *networkNamespace) (string, string) {
	t.Helper()
	l, err := n.listen(context.Background(), ListenOptions{}, "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	p, err := n.packet(context.Background(), DialOptions{}, ListenOptions{}, "udp4", "127.0.0.1:0", "", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			count, a, err := p.ReadFrom(b)
			if err != nil {
				return
			}
			p.WriteTo(b[:count], a)
		}
	}()
	return l.Addr().String(), p.LocalAddr().String()
}

func TestNetworkNamespaceConfiguration(t *testing.T) {
	for _, raw := range []string{
		`{"network_namespaces":{"tag":"x","path":"/proc/self/ns/net"}}`,
		`{"network_namespaces":[{"type":"unshare","tag":"x"}],"outbounds":{"type":"direct","netns":"x"}}`,
		`{"network_namespaces":[{"type":"unshare","tag":"x"}],"inbounds":{"type":"tun","tag":"tun","netns":"x"}}`,
	} {
		if _, err := Parse([]byte(raw)); err != nil {
			t.Fatal(raw, err)
		}
	}
	for _, raw := range []string{
		`{"network_namespaces":{"path":"/proc/self/ns/net"}}`,
		`{"network_namespaces":[{"tag":"x","path":"/proc/self/ns/net"},{"tag":"x","type":"unshare"}]}`,
		`{"network_namespaces":{"type":"bad","tag":"x"}}`,
		`{"network_namespaces":{"tag":"x"}}`,
		`{"network_namespaces":{"tag":"x","path":"relative/file"}}`,
		`{"network_namespaces":{"tag":"x","path":"/proc/self/ns/net","pid_file":"pid"}}`,
		`{"network_namespaces":{"tag":"x","type":"unshare","path":"/proc/self/ns/net"}}`,
		`{"outbounds":{"type":"direct","netns":".."}}`,
		`{"outbounds":{"type":"direct","netns":"/x\u0000"}}`,
	} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatal("invalid namespace accepted", raw)
		}
	}
}

func TestNetworkNamespaceUnshareSockets(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "namespace.pid")
	r := newTestRuntime(t, Config{NetworkNamespaces: []NetworkNamespaceOptions{{Type: "unshare", Tag: "isolated", PIDFile: pidFile}}, Inbounds: []Inbound{{Type: "socks", Tag: "proxy", Listen: "127.0.0.1", ListenOptions: ListenOptions{NetNS: "isolated"}}}, Outbounds: []Outbound{{Type: "direct", Tag: "direct", DialOptions: DialOptions{NetNS: "isolated"}}}})
	n := r.namespaces["isolated"]
	pid, err := os.ReadFile(pidFile)
	if err != nil || string(pid) != fmt.Sprintln(n.command.Process.Pid) {
		t.Fatal("pid file", string(pid), err)
	}
	if info, err := os.Stat(pidFile); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("pid permissions", err)
	}
	tcp, udp := namespaceEcho(t, n)
	host, err := net.Listen("tcp", tcp)
	if err != nil {
		t.Fatal("listener escaped namespace", err)
	}
	defer host.Close()
	for _, q := range []struct{ network, address string }{{"tcp", tcp}, {"udp", udp}} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		c, err := r.Dial(ctx, q.network, q.address)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		payload := []byte("isolated namespace")
		if _, err = c.Write(payload); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, len(payload))
		if _, err = io.ReadFull(c, b); err != nil || !bytes.Equal(b, payload) {
			t.Fatal(b, err)
		}
		c.Close()
	}
	c, err := n.dial(context.Background(), DialOptions{}, "tcp", r.Address("proxy"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if err = socksAuthenticate(c, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err = socksRequest(c, 1, tcp); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Write([]byte("socks")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 5)
	if _, err = io.ReadFull(c, b); err != nil || string(b) != "socks" {
		t.Fatal(string(b), err)
	}
	r.Close()
	if _, err = os.Stat(pidFile); !os.IsNotExist(err) {
		t.Fatal("pid file not removed", err)
	}
	if n.command.ProcessState.ExitCode() != 0 {
		t.Fatal("namespace helper exited unsuccessfully", n.command.ProcessState)
	}
}

func TestNetworkNamespaceDefault(t *testing.T) {
	n, err := startNamespace(context.Background(), NetworkNamespaceOptions{Path: "/proc/self/ns/net"}, Route{})
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	l, err := n.listen(context.Background(), ListenOptions{}, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	for _, path := range []string{"/etc/passwd", filepath.Join(t.TempDir(), "missing")} {
		if invalid, err := startNamespace(context.Background(), NetworkNamespaceOptions{Path: path}, Route{}); err == nil {
			invalid.close()
			t.Fatal("invalid namespace path accepted", path)
		}
	}
}

func TestNetworkNamespacePIDOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pid")
	if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if n, err := startNamespace(context.Background(), NetworkNamespaceOptions{Type: "unshare", PIDFile: path}, Route{}); err == nil {
		n.close()
		t.Fatal("overwrote an existing pid file")
	}
	if data, _ := os.ReadFile(path); string(data) != "existing" {
		t.Fatal("existing file changed")
	}
	os.Remove(path)
	n, err := startNamespace(context.Background(), NetworkNamespaceOptions{Type: "unshare", PIDFile: path}, Route{})
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(path)
	os.WriteFile(path, []byte("replacement"), 0600)
	n.close()
	if data, _ := os.ReadFile(path); string(data) != "replacement" {
		t.Fatal("removed a replacement file")
	}
}

func TestNetworkNamespaceConcurrent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n, err := startNamespace(ctx, NetworkNamespaceOptions{Type: "unshare"}, Route{})
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	target, _ := namespaceEcho(t, n)
	var tasks sync.WaitGroup
	for range 8 {
		tasks.Go(func() {
			for range 16 {
				c, err := n.dial(ctx, DialOptions{}, "tcp", target)
				if err != nil {
					t.Error(err)
					return
				}
				c.Close()
			}
		})
	}
	tasks.Wait()
	cancel()
	n.close()
	if _, err := n.dial(ctx, DialOptions{}, "tcp", target); err == nil {
		t.Fatal("closed namespace accepted dial")
	}
}

func TestNetworkNamespaceTUN(t *testing.T) {
	if os.Getenv("LANBOAT_NS_TUN_PROBE") != "" {
		testNamespaceTUNProbe(t)
		return
	}
	for _, redirect := range []bool{false, true} {
		t.Run(fmt.Sprint("redirect", redirect), func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "through isolated TUN") }))
			defer origin.Close()
			_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
			r := newTestRuntime(t, Config{NetworkNamespaces: []NetworkNamespaceOptions{{Type: "unshare", Tag: "vpn"}}, Inbounds: []Inbound{{Type: "tun", Tag: "tun", InterfaceName: "lbns0", Address: []string{"172.25.0.1/30", "fd25::1/126"}, AutoRoute: true, AutoRedirect: redirect, RouteAddress: []string{"192.0.2.0/24", "2001:db8:25::/64"}, ListenOptions: ListenOptions{NetNS: "vpn"}}}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}, Route: Route{Rules: []Rule{{Network: []string{"icmp"}, Action: "reject", Method: "reply"}, {IPCIDR: []string{"192.0.2.0/24", "2001:db8:25::/64"}, OverrideAddress: "127.0.0.1", Outbound: "direct"}}}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"namespace.test": {"192.0.2.77"}}}}}})
			n := r.namespaces["vpn"]
			if _, err := net.InterfaceByName("lbns0"); err == nil {
				t.Fatal("TUN escaped to the parent namespace")
			}
			probe := exec.Command("nsenter", "-t", strconv.Itoa(n.command.Process.Pid), "-U", "--preserve-credentials", "-n", os.Args[0], "-test.run=^TestNetworkNamespaceTUN$", "-test.timeout=20s", "-test.v")
			probe.Env = append(os.Environ(), "LANBOAT_NS_TUN_PROBE="+port)
			if data, err := probe.CombinedOutput(); err != nil {
				t.Fatalf("namespace TUN: %v %s", err, data)
			}

			r.Close()
			if n.command.ProcessState.ExitCode() != 0 {
				t.Fatal(n.command.ProcessState)
			}
		})
	}
}

func FuzzNetworkNamespaceConfiguration(f *testing.F) {
	f.Add([]byte(`{"network_namespaces":[{"type":"unshare","tag":"test"}]}`))
	f.Add([]byte(`{"network_namespaces":{"tag":"n","path":"/proc/self/ns/net"},"outbounds":{"type":"direct","netns":"n"}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) <= 32768 {
			_, _ = Parse(b)
		}
	})
}

func testNamespaceTUNProbe(t *testing.T) {
	for _, ip := range []string{"192.0.2.22", "2001:db8:25::22"} {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, os.Getenv("LANBOAT_NS_TUN_PROBE")), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: namespace.test\r\nConnection: close\r\n\r\n")
		b, err := io.ReadAll(c)
		c.Close()
		if err != nil || !bytes.Contains(b, []byte("through isolated TUN")) {
			t.Fatal(string(b), err)
		}
	}
	c, err := net.Dial("udp", "172.25.0.2:53")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	query, _ := makeDNSQuery("namespace.test", 1)
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write(query)
	b := make([]byte, 4096)
	count, err := c.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	ips, _, err := parseDNSReply(query, b[:count])
	if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.77" {
		t.Fatal(ips, err)
	}
	r := newTestRuntime(t, Config{})
	for _, ip := range []string{"192.0.2.22", "2001:db8:25::22"} {
		q := []byte{8, 0, 0, 0, 0, 1, 0, 1}
		if netip.MustParseAddr(ip).Is6() {
			q[0] = 128
		}
		if _, err := r.directICMPExchange(context.Background(), netip.MustParseAddr(ip), q, 64); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNetworkNamespaceDNSHTTP(t *testing.T) {
	for _, kind := range []string{"udp", "tcp", "https"} {
		t.Run(kind, func(t *testing.T) {
			r := newTestRuntime(t, Config{NetworkNamespaces: []NetworkNamespaceOptions{{Type: "unshare", Tag: "dns"}}, HTTPClients: []HTTPClientOptions{{Tag: "download", DialOptions: DialOptions{NetNS: "dns"}}}, DNS: DNSConfig{Servers: []DNSServer{{Type: "udp", Tag: "ns", Server: "127.0.0.1", DialOptions: DialOptions{NetNS: "dns"}}}}})
			n := r.namespaces["dns"]
			var host string
			var port uint16
			if kind == "udp" {
				p, err := n.packet(context.Background(), DialOptions{}, ListenOptions{}, "udp", "127.0.0.1:0", "", true)
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				host, port = splitAddress(t, p.LocalAddr().String())
				go func() {
					b := make([]byte, 4096)
					for {
						count, from, err := p.ReadFrom(b)
						if err != nil {
							return
						}
						p.WriteTo(dnsAnswer(b[:count]), from)
					}
				}()
			} else {
				l, err := n.listen(context.Background(), ListenOptions{}, "tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				host, port = splitAddress(t, l.Addr().String())
				if kind == "https" {
					tlsConfig, err := certificate(t).config(true, "")
					if err != nil {
						t.Fatal(err)
					}
					l = tls.NewListener(l, tlsConfig)
					s := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { b, _ := io.ReadAll(q.Body); w.Write(dnsAnswer(b)) })}
					defer s.Close()
					go s.Serve(l)
				} else {
					go func() {
						for {
							c, err := l.Accept()
							if err != nil {
								return
							}
							go func() {
								defer c.Close()
								var h [2]byte
								if _, e := io.ReadFull(c, h[:]); e != nil {
									return
								}
								b := make([]byte, int(binary.BigEndian.Uint16(h[:])))
								if _, e := io.ReadFull(c, b); e != nil {
									return
								}
								b = dnsAnswer(b)
								writeAll(c, binary.BigEndian.AppendUint16(nil, uint16(len(b))))
								writeAll(c, b)
							}()
						}
					}()
				}
			}
			// The broker is shared with r; assign its immutable pointer to the resolver fixture.
			server := r.config.DNS.Servers[0]
			if server.namespace != n || r.config.HTTPClients[0].namespace != n {
				t.Fatal("DNS/HTTP namespace not bound")
			}
			server.Type, server.Server, server.ServerPort = kind, host, port
			if kind == "https" {
				server.Type = "https"
				server.Path = "/dns-query"
				server.TLS.Insecure = true
			}
			res, err := newResolver(DNSConfig{Servers: []DNSServer{server}}, r)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Close()
			q, _ := makeDNSQuery("private.test", 1)
			got, err := res.exchangePolicy(context.Background(), q, false)
			if err != nil {
				t.Fatal(err)
			}
			ips, _, err := parseDNSReply(q, got)
			if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.42" {
				t.Fatal(ips, err)
			}
		})
	}
}

func splitAddress(t *testing.T, address string) (string, uint16) {
	t.Helper()
	h, p, e := net.SplitHostPort(address)
	if e != nil {
		t.Fatal(e)
	}
	n, e := strconv.ParseUint(p, 10, 16)
	if e != nil {
		t.Fatal(e)
	}
	return h, uint16(n)
}

func TestNetworkNamespaceHTTPDownloader(t *testing.T) {
	r := newTestRuntime(t, Config{NetworkNamespaces: []NetworkNamespaceOptions{{Type: "unshare", Tag: "download"}}, HTTPClients: []HTTPClientOptions{{Tag: "client", DialOptions: DialOptions{NetNS: "download"}}}})
	n := r.namespaces["download"]
	l, err := n.listen(context.Background(), ListenOptions{}, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { io.WriteString(w, "private download") })}
	defer s.Close()
	go s.Serve(l)
	for _, inline := range []bool{false, true} {
		ref := clientReference("client")
		if inline {
			b, _ := json.Marshal(r.config.HTTPClients[0])
			ref = clientReference(b)
		}
		c, transport, err := r.ruleHTTPClient(RuleSet{HTTPClient: ref})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Get("http://" + l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		transport.CloseIdleConnections()
		if err != nil || string(b) != "private download" {
			t.Fatal(string(b), err)
		}
	}
}

func TestNetworkNamespaceSOCKSUDP(t *testing.T) {
	r := newTestRuntime(t, Config{NetworkNamespaces: []NetworkNamespaceOptions{{Type: "unshare", Tag: "udp"}}, Inbounds: []Inbound{{Type: "socks", Tag: "socks", Listen: "127.0.0.1", ListenOptions: ListenOptions{NetNS: "udp"}}}, Outbounds: []Outbound{{Type: "direct", Tag: "direct", DialOptions: DialOptions{NetNS: "udp"}}}})
	n := r.namespaces["udp"]
	_, target := namespaceEcho(t, n)
	control, err := n.dial(context.Background(), DialOptions{}, "tcp", r.Address("socks"))
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	control.SetDeadline(time.Now().Add(3 * time.Second))
	if err = socksAuthenticate(control, "", ""); err != nil {
		t.Fatal(err)
	}
	relay, err := socksRequest(control, 3, "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	c, err := n.dial(context.Background(), DialOptions{}, "udp", relay)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	address, _ := encodeAddress(target)
	packet := append([]byte{0, 0, 0}, address...)
	packet = append(packet, []byte("udp relay")...)
	c.Write(packet)
	b := make([]byte, 4096)
	count, err := c.Read(b)
	if err != nil || !bytes.HasSuffix(b[:count], []byte("udp relay")) {
		t.Fatal(count, err)
	}
}

func TestNetworkNamespaceFakeTCP(t *testing.T) {
	r := newTestRuntime(t, Config{NetworkNamespaces: []NetworkNamespaceOptions{{Type: "unshare", Tag: "raw"}}})
	n := r.namespaces["raw"]
	p, err := listenFakeTCP(context.Background(), "127.0.0.1:0", ListenOptions{NetNS: "raw", namespace: n})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	host, port := splitAddress(t, p.LocalAddr().String())
	c, err := r.dialFakeTCP(context.Background(), Outbound{Server: host, ServerPort: port, DialOptions: DialOptions{NetNS: "raw", namespace: n}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	p.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte("raw namespace"))
	b := make([]byte, 4096)
	count, peer, err := p.ReadFrom(b)
	if err != nil {
		t.Fatal(err)
	}
	p.WriteTo(b[:count], peer)
	count, err = c.Read(b)
	if err != nil || string(b[:count]) != "raw namespace" {
		t.Fatal(count, err)
	}
	for _, ip := range []string{"127.0.0.1", "::1"} {
		q := []byte{8, 0, 0, 0, 0, 1, 0, 1}
		if netip.MustParseAddr(ip).Is6() {
			q[0] = 128
		}
		if _, err = r.directICMPExchange(context.Background(), netip.MustParseAddr(ip), q, 64, DialOptions{NetNS: "raw", namespace: n}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNetworkNamespaceFraming(t *testing.T) {
	for _, b := range [][]byte{nil, {0, 0, 0, 0}, {255, 255, 255, 255}, {0, 0, 0, 1, '{'}} {
		var q namespaceRequest
		if err := readNamespaceFrame(bytes.NewReader(b), &q); err == nil {
			t.Fatal("bad frame accepted")
		}
	}
	n, err := startNamespace(context.Background(), NetworkNamespaceOptions{Type: "unshare"}, Route{})
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	if _, files, err := n.call(context.Background(), namespaceRequest{Op: "init"}); err == nil {
		closeNamespaceFiles(files)
		t.Fatal("reinitialization accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := n.dial(ctx, DialOptions{}, "tcp", "127.0.0.1:9"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestNetworkNamespaceExistingForeign(t *testing.T) {
	if os.Getenv("LANBOAT_NS_EXISTING") != "1" {
		c := exec.Command("unshare", "-Urn", os.Args[0], "-test.run=^TestNetworkNamespaceExistingForeign$", "-test.v", "-test.timeout=30s")
		c.Env = append(os.Environ(), "LANBOAT_NS_EXISTING=1")
		if b, err := c.CombinedOutput(); err != nil {
			t.Fatalf("existing namespace: %v %s", err, b)
		}
		return
	}
	n, err := startNamespace(context.Background(), NetworkNamespaceOptions{Type: "unshare"}, Route{})
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	path := fmt.Sprintf("/proc/%d/ns/net", n.command.Process.Pid)
	r := newTestRuntime(t, Config{NetworkNamespaces: []NetworkNamespaceOptions{{Type: "default", Tag: "existing", Path: path}}, Outbounds: []Outbound{{Type: "direct", Tag: "direct", DialOptions: DialOptions{NetNS: "existing"}}}, HTTPClients: []HTTPClientOptions{{Tag: "path", DialOptions: DialOptions{NetNS: path}}}})
	target, _ := namespaceEcho(t, n)
	c, err := r.Dial(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte("existing"))
	b := make([]byte, 8)
	if _, err = io.ReadFull(c, b); err != nil || string(b) != "existing" {
		t.Fatal(string(b), err)
	}
	if r.config.HTTPClients[0].namespace == nil {
		t.Fatal("direct namespace path not initialized")
	}
	if outside, err := net.Listen("tcp", target); err != nil {
		t.Fatal("listener escaped", err)
	} else {
		outside.Close()
	}
}

func TestNetworkNamespaceRouteRefresh(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		t.Run(fmt.Sprint(redirect), func(t *testing.T) {
			r := newTestRuntime(t, Config{NetworkNamespaces: []NetworkNamespaceOptions{{Type: "unshare", Tag: "routes"}}, Inbounds: []Inbound{{Type: "tun", Tag: "tun", InterfaceName: "lbroutes0", AutoRoute: true, AutoRedirect: redirect, DNSMode: "disabled", RouteAddressSet: []string{"networks"}, ListenOptions: ListenOptions{NetNS: "routes"}}}, Route: Route{RuleSet: []RuleSet{{Type: "inline", Tag: "networks", Rules: []Rule{{IPCIDR: []string{"192.0.2.21/32"}}}}}}})
			n := r.namespaces["routes"]
			tun := r.tunnels[0]
			read := func() string {
				t.Helper()
				args := []string{"-t", strconv.Itoa(n.command.Process.Pid), "-U", "--preserve-credentials", "-n"}
				if redirect {
					args = append(args, "nft", "list", "ruleset")
				} else {
					args = append(args, "ip", "-4", "route", "show", "table", "all")
				}
				b, err := exec.Command("nsenter", args...).CombinedOutput()
				if err != nil {
					t.Fatal(string(b), err)
				}
				return string(b)
			}
			if b := read(); !strings.Contains(b, "192.0.2.21") {
				t.Fatal("initial kernel routes missing", b)
			}
			snapshot, err := compileRuleSet([]Rule{{IPCIDR: []string{"192.0.2.23/32"}}})
			if err != nil {
				t.Fatal(err)
			}
			r.ruleSets["networks"].store(snapshot)
			tun.platformMu.Lock()
			err = tun.refreshRoutes()
			tun.platformMu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if b := read(); strings.Contains(b, "192.0.2.21") || !strings.Contains(b, "192.0.2.23") {
				t.Fatal("kernel routes not replaced", b)
			}
			response, files, err := n.call(context.Background(), namespaceRequest{Op: "tun-update", ID: tun.namespaceID, Inbound: Inbound{RouteAddress: []string{"invalid"}}})
			closeNamespaceFiles(files)
			if err == nil {
				t.Fatal("bad route update accepted", response)
			}
			if b := read(); !strings.Contains(b, "192.0.2.23") {
				t.Fatal("invalid update damaged active routes", b)
			}
		})
	}
}

func TestNetworkNamespaceSocketLimits(t *testing.T) {
	n, err := startNamespace(context.Background(), NetworkNamespaceOptions{Type: "unshare"}, Route{})
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	for _, op := range []string{"dial", "listen", "packet-listen"} {
		if _, f, err := n.call(context.Background(), namespaceRequest{Op: op, Network: "unix", Address: filepath.Join(t.TempDir(), "escape")}); err == nil {
			closeNamespaceFiles(f)
			t.Fatal("non-network socket accepted")
		}
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 64 {
		if c, err := n.dial(context.Background(), DialOptions{}, "tcp", "127.0.0.1:1"); err == nil {
			c.Close()
			t.Fatal("unexpected listener")
		}
	}
	after, _ := os.ReadDir("/proc/self/fd")
	if len(after) > len(before)+2 {
		t.Fatal("descriptor leak", len(before), len(after))
	}
	if c, err := (&Runtime{}).dialSocket(context.Background(), DialOptions{NetNS: "unbound"}, "tcp", "127.0.0.1:1"); err == nil {
		c.Close()
		t.Fatal("unbound namespace fell back")
	}
}

func TestNetworkNamespaceProtocolTraffic(t *testing.T) {
	for _, kind := range []string{"hysteria2", "tuic"} {
		t.Run(kind, func(t *testing.T) {
			in := Inbound{Type: kind, Tag: "server", Listen: "127.0.0.1", ListenPort: unusedPort(t), Users: []User{{Name: "client", Password: "private", UUID: testUUID}}, ListenOptions: ListenOptions{NetNS: "protocol"}}
			in.TLS = certificate(t)
			out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
			out.NetNS = "protocol"
			if kind == "hysteria2" {
				out.UUID, out.Username = "", ""
			}
			r := newTestRuntime(t, Config{NetworkNamespaces: []NetworkNamespaceOptions{{Type: "unshare", Tag: "protocol"}}, Inbounds: []Inbound{in}, Outbounds: []Outbound{out, {Type: "direct", Tag: "direct"}}, Route: Route{Final: "proxy", Rules: []Rule{{Inbound: []string{"server"}, Outbound: "direct"}}}})
			assertTCP(t, r)
			assertUDPSizes(t, r, []int{1, 511, 4096})
		})
	}
}

func TestNetworkNamespaceMetadata(t *testing.T) {
	r := newTestRuntime(t, Config{NetworkNamespaces: []NetworkNamespaceOptions{{Type: "unshare", Tag: "metadata"}}, Inbounds: []Inbound{{Type: "socks", Tag: "local", Listen: "127.0.0.1", ListenOptions: ListenOptions{NetNS: "metadata"}}}, Route: Route{FindProcess: true, FindNeighbor: true}})
	n := r.namespaces["metadata"]
	target, _ := namespaceEcho(t, n)
	c, err := n.dial(context.Background(), DialOptions{}, "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	q := request{inbound: "local", network: "tcp", source: c.LocalAddr().String(), address: c.RemoteAddr().String(), origin: r.socketOrigin(c.LocalAddr(), c.RemoteAddr())}
	r.enrichProcess(context.Background(), &q)
	if q.metadata.UserID == nil || *q.metadata.UserID != uint32(os.Getuid()) || q.metadata.ProcessPath == "" {
		t.Fatal("namespace socket owner", q.metadata)
	}
	pid := strconv.Itoa(n.command.Process.Pid)
	for _, args := range [][]string{{"link", "add", "lbmeta0", "type", "dummy"}, {"link", "set", "lbmeta0", "up"}, {"addr", "add", "192.0.2.1/24", "dev", "lbmeta0"}, {"neigh", "replace", "192.0.2.9", "lladdr", "02:11:22:33:44:55", "dev", "lbmeta0", "nud", "permanent"}} {
		all := append([]string{"-t", pid, "-U", "--preserve-credentials", "-n", "ip"}, args...)
		if b, err := exec.Command("nsenter", all...).CombinedOutput(); err != nil {
			t.Fatal(string(b), err)
		}
	}
	q = request{inbound: "local", source: "192.0.2.9:1234"}
	r.enrichNeighbor(context.Background(), &q)
	if q.metadata.SourceMACAddress != "02:11:22:33:44:55" {
		t.Fatal("namespace neighbor", q.metadata)
	}
}

func TestNetworkNamespaceAliases(t *testing.T) {
	r := newTestRuntime(t, Config{NetworkNamespaces: []NetworkNamespaceOptions{{Tag: "first", Path: "/proc/self/ns/net"}, {Tag: "second", Path: "/proc/self/ns/net"}}, Outbounds: []Outbound{{Type: "direct", Tag: "direct", DialOptions: DialOptions{NetNS: "/proc/self/ns/net"}}}})
	n := r.namespaces["first"]
	if n != r.namespaces["second"] || n != r.namespaces["/proc/self/ns/net"] {
		t.Fatal("same namespace created duplicate helpers")
	}
	r.Close()
	if n.command.ProcessState.ExitCode() != 0 {
		t.Fatal(n.command.ProcessState)
	}
}

func TestNetworkNamespaceMissingWorker(t *testing.T) {
	t.Setenv("LANBOAT_NS_NO_DISPATCH", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	if n, err := startNamespace(ctx, NetworkNamespaceOptions{Type: "unshare"}, Route{}); err == nil {
		n.close()
		t.Fatal("missing worker dispatcher accepted")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("startup failure left a running helper")
	}
}
