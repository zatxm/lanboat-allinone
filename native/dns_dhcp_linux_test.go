package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func dhcpNamespace(t *testing.T) bool {
	t.Helper()
	if os.Getenv("LANBOAT_DHCP_CHILD") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v", "-test.timeout=60s")
		cmd.Env = append(os.Environ(), "LANBOAT_DHCP_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("DHCP isolated:%v\n%s", err, out)
		}
		t.Log(string(out))
		return false
	}
	mdnsCommand(t, "ip", "link", "set", "lo", "up")
	for i, ip := range []string{"192.0.2.10/24", "198.51.100.10/24"} {
		name := fmt.Sprintf("dhcp%d", i)
		mdnsCommand(t, "ip", "link", "add", name, "type", "dummy")
		mdnsCommand(t, "ip", "link", "set", name, "address", fmt.Sprintf("02:00:00:00:dd:0%d", i+1))
		mdnsCommand(t, "ip", "addr", "add", ip, "dev", name)
		mdnsCommand(t, "ip", "link", "set", name, "up")
	}
	mdnsCommand(t, "ip", "route", "add", "default", "dev", "dhcp0")
	return true
}

func dhcpResponder(t *testing.T, reply func([]byte) []byte) *atomic.Int64 {
	t.Helper()
	s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 67})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var count atomic.Int64
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, peer, err := s.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 240 || buf[0] != 1 || peer.Port != 68 {
				t.Error("invalid discovery", peer, n)
				continue
			}
			count.Add(1)
			if b := reply(bytes.Clone(buf[:n])); b != nil {
				_, _ = s.WriteToUDP(b, peer)
			}
		}
	}()
	t.Cleanup(func() { s.Close(); <-done })
	return &count
}

func TestDHCPNamespace(t *testing.T) {
	if !dhcpNamespace(t) {
		return
	}
	var silent atomic.Bool
	count := dhcpResponder(t, func(q []byte) []byte {
		if silent.Load() {
			return nil
		}
		return dhcpTestOffer(q, 53, 1, 2, 54, 4, 192, 0, 2, 1, 6, 4, 192, 0, 2, 53, 15, 12, 'c', 'o', 'r', 'p', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', 255)
	})
	r, _ := newResolver(DNSConfig{Servers: []DNSServer{{Type: "dhcp", Tag: "lan", Interfaces: []string{"dhcp0"}}}})
	defer r.Close()
	client := r.dhcp["lan"]
	var jobs sync.WaitGroup
	for range 32 {
		jobs.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			state, err := client.snapshot(ctx, []string{"dhcp0"})
			if err != nil || fmt.Sprint(state.servers) != "[192.0.2.53]" {
				t.Error(state, err)
			}
		})
	}
	jobs.Wait()
	if count.Load() != 1 {
		t.Fatal("discovery not coalesced", count.Load())
	}
	state := r.dnsNetwork("lan")
	if fmt.Sprint(state.addresses) != "[192.0.2.53]" || !slices.Equal(state.domains, []string{"corp.example"}) {
		t.Fatal(state)
	}
	oldKey := client.state.key
	mdnsCommand(t, "ip", "addr", "add", "192.0.2.11/24", "dev", "dhcp0")
	if state, err := client.snapshot(context.Background(), []string{"dhcp0"}); err != nil || state.key == oldKey {
		t.Fatal("interface cache reused", state, err)
	}
	if count.Load() != 2 {
		t.Fatal(count.Load())
	}
	path, err := r.dhcpPath(context.Background(), nil)
	if err != nil || path.iface.Name != "dhcp0" {
		t.Fatal("default interface", path, err)
	}
	if _, err := client.snapshot(context.Background(), []string{"missing"}); err == nil {
		t.Fatal("missing interface accepted")
	}
	silent.Store(true)
	client.mu.Lock()
	client.state.until = time.Time{}
	client.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := client.snapshot(ctx, []string{"dhcp0"}); err == nil {
		t.Fatal("canceled discovery accepted")
	}
	done := make(chan struct{})
	go func() { r.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("DHCP shutdown blocked")
	}
	if _, err := client.snapshot(context.Background(), []string{"dhcp0"}); err == nil {
		t.Fatal("closed client returned stale DNS")
	}
}

func TestDHCPDNSMasq(t *testing.T) {
	if !dhcpNamespace(t) {
		return
	}
	mdnsCommand(t, "ip", "link", "del", "dhcp0")
	dir := t.TempDir()
	logs := new(bytes.Buffer)
	cmd := exec.Command("unshare", "--net", "--", "sh", "-c", `kill -STOP $$; exec dnsmasq "$@"`, "sh", "--conf-file=/dev/null", "--no-daemon", "--no-ping", "--user=root", "--group=root", "--no-resolv", "--no-hosts", "--bind-interfaces", "--interface=server0", "--listen-address=192.0.2.1", "--dhcp-range=192.0.2.100,192.0.2.120,255.255.255.0,1h", "--dhcp-option=6,192.0.2.1", "--dhcp-option=119,corp.example,lab.example", "--address=/dhcp.test/203.0.113.7", "--txt-record=text.dhcp.test,independent-dhcp", "--dhcp-leasefile="+filepath.Join(dir, "leases"), "--pid-file="+filepath.Join(dir, "pid"))
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Log(logs.String())
		}
	})
	for until := time.Now().Add(time.Second); ; {
		status, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", cmd.Process.Pid))
		if bytes.Contains(status, []byte("State:\tT")) {
			break
		}
		if time.Now().After(until) {
			t.Fatal("DHCP server namespace did not stop")
		}
		time.Sleep(time.Millisecond)
	}
	peerPID := fmt.Sprint(cmd.Process.Pid)
	mdnsCommand(t, "ip", "link", "add", "dhcp0", "type", "veth", "peer", "name", "server0")
	mdnsCommand(t, "ip", "link", "set", "server0", "netns", peerPID)
	mdnsCommand(t, "ip", "addr", "add", "192.0.2.10/24", "dev", "dhcp0")
	mdnsCommand(t, "ip", "link", "set", "dhcp0", "up")
	mdnsCommand(t, "ip", "route", "add", "default", "dev", "dhcp0")
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"addr", "add", "192.0.2.1/24", "dev", "server0"}, {"link", "set", "server0", "up"}} {
		mdnsCommand(t, "nsenter", append([]string{"-t", peerPID, "-n", "ip"}, args...)...)
	}
	if err := cmd.Process.Signal(syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	for until := time.Now().Add(2 * time.Second); ; {
		c, e := net.DialTimeout("tcp", "192.0.2.1:53", 20*time.Millisecond)
		if e == nil {
			c.Close()
			break
		}
		if time.Now().After(until) {
			t.Fatal(e)
		}
		time.Sleep(5 * time.Millisecond)
	}
	config := Config{Inbounds: []Inbound{{Type: "direct", Tag: "dns", Listen: "127.0.0.1"}}, DNS: DNSConfig{Servers: []DNSServer{{Type: "dhcp", Tag: "lan", Interfaces: []string{"dhcp0"}}}, Timeout: "3s"}, Route: Route{Rules: []Rule{{Action: "hijack-dns"}}}}
	native := newTestRuntime(t, config)
	for _, typ := range []uint16{1, 16} {
		host := "dhcp.test"
		if typ == 16 {
			host = "text.dhcp.test"
		}
		query, _ := makeDNSQuery(host, typ)
		reply, err := native.ExchangeDNS(context.Background(), query, "")
		if err != nil {
			t.Fatal(err)
		}
		rr, e := dnsRecords(reply)
		if e != nil || len(rr[0]) != 1 {
			t.Fatal(rr, e)
		}
		if typ == 1 {
			ips, _, e := parseDNSReply(query, reply)
			if e != nil || fmt.Sprint(ips) != "[203.0.113.7]" {
				t.Fatal(ips, e)
			}
		}
	}
	if state := native.resolver.dnsNetwork("lan"); !slices.Equal(state.domains, []string{"corp.example", "lab.example"}) {
		t.Fatal("search domains", state)
	}
	reference := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if reference == "" {
		t.Fatal("LANBOAT_TEST_SINGBOX15 required")
	}
	port := unusedPort(t)
	doc := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "direct", "tag": "dns", "listen": "127.0.0.1", "listen_port": port}}, "dns": map[string]any{"servers": []any{map[string]any{"type": "dhcp", "tag": "lan", "interface": "dhcp0"}}, "timeout": "3s"}, "route": map[string]any{"rules": []any{map[string]any{"action": "hijack-dns"}}}}
	b, _ := json.Marshal(doc)
	file := filepath.Join(dir, "reference.json")
	if err := os.WriteFile(file, b, 0600); err != nil {
		t.Fatal(err)
	}
	ref := exec.Command(reference, "run", "-c", file)
	refLog := new(bytes.Buffer)
	ref.Stdout, ref.Stderr = refLog, refLog
	if err := ref.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ref.Process.Kill()
		ref.Wait()
		if t.Failed() {
			t.Log(refLog.String())
		}
	})
	query, _ := makeDNSQuery("dhcp.test", 1)
	for _, address := range []string{native.Address("dns"), portAddress("127.0.0.1", port)} {
		for _, network := range []string{"tcp", "udp"} {
			var last error
			for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
				c, e := net.DialTimeout(network, address, 100*time.Millisecond)
				if e != nil {
					last = e
					time.Sleep(5 * time.Millisecond)
					continue
				}
				c.SetDeadline(time.Now().Add(500 * time.Millisecond))
				wire := query
				if network == "tcp" {
					wire = append(binary.BigEndian.AppendUint16(nil, uint16(len(query))), query...)
				}
				_, e = c.Write(wire)
				reply := make([]byte, 4096)
				var n int
				if e == nil {
					if network == "tcp" {
						var h [2]byte
						_, e = io.ReadFull(c, h[:])
						if e == nil {
							n = int(binary.BigEndian.Uint16(h[:]))
							_, e = io.ReadFull(c, reply[:n])
						}
					} else {
						n, e = c.Read(reply)
					}
				}
				c.Close()
				if e == nil {
					ips, _, e := parseDNSReply(query, reply[:n])
					if e != nil || fmt.Sprint(ips) != "[203.0.113.7]" {
						t.Fatal(ips, e)
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
	}
	if leases, err := os.ReadFile(filepath.Join(dir, "leases")); err == nil && len(bytes.TrimSpace(leases)) != 0 {
		t.Fatal("DNS discovery acquired a host address lease", string(leases))
	}
}

func TestDHCPUpstreamsAndCache(t *testing.T) {
	if !dhcpNamespace(t) {
		return
	}
	for _, address := range []string{"192.0.2.53/24", "192.0.2.54/24"} {
		mdnsCommand(t, "ip", "addr", "add", address, "dev", "dhcp0")
	}
	var generation atomic.Int32
	discoveries := dhcpResponder(t, func(q []byte) []byte {
		last := byte(53 + generation.Load())
		return dhcpTestOffer(q, 53, 1, 2, 54, 4, 192, 0, 2, 1, 6, 8, 192, 0, 2, 52, 192, 0, 2, last, 255)
	})
	var udpCount, tcpCount atomic.Int32
	for index, host := range []string{"192.0.2.53", "192.0.2.54"} {
		p, err := net.ListenPacket("udp", host+":53")
		if err != nil {
			t.Fatal(err)
		}
		l, err := net.Listen("tcp", host+":53")
		if err != nil {
			p.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { p.Close(); l.Close() })
		answer := fmt.Sprintf("cached.test. 120 IN A 203.0.113.%d", 7+index)
		go func() {
			b := make([]byte, 4096)
			for {
				n, peer, err := p.ReadFrom(b)
				if err != nil {
					return
				}
				udpCount.Add(1)
				reply := bytes.Clone(b[:n])
				reply[2] |= 130
				p.WriteTo(reply, peer)
			}
		}()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					c.SetDeadline(time.Now().Add(time.Second))
					var h [2]byte
					if _, err := io.ReadFull(c, h[:]); err != nil {
						return
					}
					q := make([]byte, int(binary.BigEndian.Uint16(h[:])))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					tcpCount.Add(1)
					reply, err := predefinedDNS(q, DNSRule{Answer: []string{answer}})
					if err != nil {
						t.Error(err)
						return
					}
					writeAll(c, binary.BigEndian.AppendUint16(nil, uint16(len(reply))))
					writeAll(c, reply)
				}()
			}
		}()
	}
	proxyIn := testInbound(t, "socks")
	proxy := newTestRuntime(t, Config{Inbounds: []Inbound{proxyIn}})
	out := testOutbound(t, proxyIn, proxy.Address(proxyIn.Tag))
	r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "dhcp", Tag: "lan", Interfaces: []string{"dhcp0"}, Detour: out.Tag}}, Timeout: "3s"}, Outbounds: []Outbound{{Type: "block", Tag: "deny"}, out}})
	query, _ := makeDNSQuery("cached.test", 1)
	check := func(want string) {
		t.Helper()
		reply, err := r.ExchangeDNS(context.Background(), query, "")
		ips, _, parseErr := parseDNSReply(query, reply)
		if err != nil || parseErr != nil || fmt.Sprint(ips) != "["+want+"]" {
			t.Error("upstream fallback", ips, err, parseErr)
		}
	}
	var jobs sync.WaitGroup
	for range 16 {
		jobs.Go(func() { check("203.0.113.7") })
	}
	jobs.Wait()
	if discoveries.Load() != 1 || udpCount.Load() != 1 || tcpCount.Load() != 1 {
		t.Fatal("cache/coalescing or TCP fallback", discoveries.Load(), udpCount.Load(), tcpCount.Load())
	}
	generation.Store(1)
	client := r.resolver.dhcp["lan"]
	client.mu.Lock()
	client.state.until = time.Time{}
	client.mu.Unlock()
	check("203.0.113.8")
	if discoveries.Load() != 2 || udpCount.Load() != 2 || tcpCount.Load() != 2 {
		t.Fatal("DNS cache crossed discovered server generations", discoveries.Load(), udpCount.Load(), tcpCount.Load())
	}
	if proxy.Stats().Uplink == 0 {
		t.Fatal("DNS ignored proxy detour")
	}
}
