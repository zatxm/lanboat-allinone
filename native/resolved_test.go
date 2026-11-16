package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func resolvedPrivateBus(t *testing.T) (string, func()) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("resolved is Linux-only")
	}
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--print-address=1")
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	var once sync.Once
	stop := func() { once.Do(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }) }
	t.Cleanup(stop)
	line, e := bufio.NewReader(stdout).ReadString('\n')
	if e != nil || !strings.HasPrefix(line, "unix:") {
		t.Fatal(e, line, stderr.String())
	}
	address := strings.TrimSpace(line)
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", address)
	return address, stop
}
func resolvedBusCall(t *testing.T, address, member, sig string, args ...string) string {
	t.Helper()
	out, e := resolvedBusCommand(address, member, sig, args...)
	if e != nil {
		t.Fatalf("%s: %v %s", member, e, out)
	}
	return out
}
func resolvedBusCommand(address, member, sig string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	argv := []string{"--address=" + address, "--timeout=3", "call", resolvedName, resolvedPath, resolvedInterface, member}
	if sig != "" {
		argv = append(argv, sig)
	}
	argv = append(argv, args...)
	out, e := exec.CommandContext(ctx, "busctl", argv...).CombinedOutput()
	return string(out), e
}
func resolvedFreePort(t *testing.T) uint16 {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}
func resolvedTestConfig(t *testing.T) Config {
	return Config{Services: []ServiceOptions{{Type: "resolved", Tag: "resolve", Listen: "127.0.0.1", ListenPort: resolvedFreePort(t)}}, DNS: DNSConfig{Servers: []DNSServer{{Type: "resolved", Tag: "link", Service: "resolve"}}, Final: "link", Timeout: "2s"}}
}
func resolvedTestUpstream(t *testing.T, ip string) (string, uint16) {
	t.Helper()
	r := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "dns", Tag: "dns", Listen: "127.0.0.1"}}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"node.corp.test": {ip}, "node.deep.corp.test": {ip}, "other.test": {ip}, "expanded.corp.test": {ip}}}}}})
	return splitTestAddress(t, r.Address("dns"))
}
func resolvedSetServer(t *testing.T, address string, index int, host string, port uint16) {
	t.Helper()
	ip := netip.MustParseAddr(host)
	raw := ip.AsSlice()
	family := "2"
	if ip.Is6() {
		family = "10"
	}
	args := []string{fmt.Sprint(index), "1", family, fmt.Sprint(len(raw))}
	for _, b := range raw {
		args = append(args, fmt.Sprint(b))
	}
	args = append(args, fmt.Sprint(port), "")
	resolvedBusCall(t, address, "SetLinkDNSEx", "ia(iayqs)", args...)
}
func resolvedAssertIP(t *testing.T, r *Runtime, host, want string) {
	t.Helper()
	q, _ := makeDNSQuery(host, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	reply, e := r.ExchangeDNS(ctx, q, "")
	if e != nil {
		t.Fatal(e)
	}
	ips, _, e := parseDNSReply(q, reply)
	if e != nil || len(ips) != 1 || ips[0].String() != want {
		t.Fatalf("%s: %v %v", host, ips, e)
	}
}
func TestResolvedBusWire(t *testing.T) {
	for _, tc := range []struct {
		sig string
		v   []any
	}{
		{"x", []any{int64(-1)}},
		{"ia(iayqs)", []any{int32(1), []any{[]any{int32(2), []byte{127, 0, 0, 1}, uint16(5353), "dns.example"}, []any{int32(10), netip.MustParseAddr("::1").AsSlice(), uint16(853), ""}}}},
		{"ia(sb)", []any{int32(4), []any{[]any{"corp.test", true}, []any{"test", false}}}},
		{"a{sv}", []any{[]any{[]any{"unix-user", busVariant{"u", uint32(1000)}}}}},
		{"a(iiay)st", []any{[]any{[]any{int32(0), int32(2), []byte{192, 0, 2, 1}}}, "example.test.", uint64(0)}},
	} {
		t.Run(tc.sig, func(t *testing.T) {
			m := busMessage{kind: 1, serial: 1, path: resolvedPath, iface: resolvedInterface, member: "Test", signature: tc.sig, values: tc.v}
			wire := m.encode()
			got, e := busRead(bytes.NewReader(wire))
			if e != nil || !reflect.DeepEqual(m, got) {
				t.Fatalf("%v\n%#v\n%#v", e, m, got)
			}
			for i := range len(wire) {
				if _, e = busRead(bytes.NewReader(wire[:i])); e == nil {
					t.Fatal("accepted truncated message", i)
				}
			}
		})
	}
	// A big-endian method body exercises alignment independently of our little-endian encoder.
	b := []byte{'B', 1, 0, 1, 0, 0, 0, 4, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 7}
	m, e := busRead(bytes.NewReader(b))
	if e == nil {
		t.Fatal("body without signature accepted", m)
	}
	b = busMessage{kind: 1, serial: 1, signature: "u", values: []any{uint32(7)}}.encode()
	b[0] = 'B'
	for _, pos := range []int{4, 8, 12} {
		n := binary.LittleEndian.Uint32(b[pos:])
		binary.BigEndian.PutUint32(b[pos:], n)
	}
	binary.BigEndian.PutUint32(b[len(b)-4:], 7)
	m, e = busRead(bytes.NewReader(b))
	if e != nil || m.values[0].(uint32) != 7 {
		t.Fatal(e, m)
	}
}
func FuzzResolvedBus(f *testing.F) {
	f.Add(busMessage{kind: 1, serial: 1, signature: "a{sv}", values: []any{[]any{[]any{"LastScan", busVariant{"x", int64(-1)}}}}}.encode())
	f.Add(busMessage{kind: 1, serial: 1, signature: "ia(iayqs)", values: []any{int32(1), []any{[]any{int32(2), []byte{127, 0, 0, 1}, uint16(53), ""}}}}.encode())
	f.Add([]byte("l\x01\x00\x01"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > dbusLimit+65552 {
			return
		}
		_, _ = busRead(bytes.NewReader(data))
	})
}

func TestResolvedBusRejectsForgedCredentials(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b := &resolvedBus{conn: client, ctx: ctx, cancel: cancel, pending: map[uint32]chan busMessage{}, done: make(chan struct{}), requests: make(chan busMessage, 1)}
	go b.read(client)
	defer b.close()
	peerDone := make(chan error, 1)
	go func() {
		request, e := busRead(server)
		if e != nil {
			peerDone <- e
			return
		}
		for _, sender := range []string{":1.999", "org.freedesktop.DBus"} {
			uid := uint32(0)
			if sender == "org.freedesktop.DBus" {
				uid = 12345
			}
			reply := busMessage{kind: 2, serial: 1, reply: request.serial, sender: sender, signature: "u", values: []any{uid}}
			if e = writeAll(server, reply.encode()); e != nil {
				peerDone <- e
				return
			}
		}
		peerDone <- nil
	}()
	m, e := b.call(ctx, "GetConnectionUnixUser", "s", []any{":1.77"})
	if e != nil || m.values[0].(uint32) != 12345 {
		t.Fatal("forged authorization response accepted", e, m)
	}
	if e := <-peerDone; e != nil {
		t.Fatal(e)
	}
}
func TestResolvedServiceDNS(t *testing.T) {
	address, _ := resolvedPrivateBus(t)
	host, port := resolvedTestUpstream(t, "192.0.2.1")
	r := newTestRuntime(t, resolvedTestConfig(t))
	resolvedSetServer(t, address, 1, host, port)
	resolvedBusCall(t, address, "SetLinkDomains", "ia(sb)", "1", "1", "corp.test", "true")
	resolvedAssertIP(t, r, "node.corp.test", "192.0.2.1")
	out := resolvedBusCall(t, address, "ResolveHostname", "isit", "0", "node.corp.test", "0", "0")
	if !strings.Contains(out, "192 0 2 1") {
		t.Fatal(out)
	}
	query, _ := makeDNSQuery("node.corp.test", 1)
	for _, network := range []string{"udp", "tcp"} {
		up := DNSServer{Type: network, Server: "127.0.0.1", ServerPort: r.config.Services[0].ListenPort}
		reply, e := r.resolver.exchangeOn(context.Background(), up, query)
		if e != nil {
			t.Fatal(e)
		}
		ips, _, e := parseDNSReply(query, reply)
		if e != nil || len(ips) != 1 {
			t.Fatal(network, e, ips)
		}
	}
	q, _ := makeDNSQuery("other.test", 1)
	reply, e := r.ExchangeDNS(context.Background(), q, "")
	if e != nil || reply[3]&15 != 3 {
		t.Fatal("nonmatching domain escaped", e, reply)
	}
	host, port = resolvedTestUpstream(t, "192.0.2.2")
	resolvedSetServer(t, address, 1, host, port)
	resolvedAssertIP(t, r, "node.corp.test", "192.0.2.2")
	state := r.resolver.dnsNetwork("link")
	if len(state.addresses) != 1 || !slices.Contains(state.domains, "corp.test") {
		t.Fatal(state)
	}
	resolvedBusCall(t, address, "FlushCaches", "")
	resolvedBusCall(t, address, "RevertLink", "i", "1")
	reply, e = r.ExchangeDNS(context.Background(), q, "")
	if e != nil || reply[3]&15 != 3 || len(r.resolver.dnsNetwork("link").addresses) != 0 {
		t.Fatal("reverted link retained DNS", e)
	}
}
func TestResolvedDefaultAndPreferred(t *testing.T) {
	address, _ := resolvedPrivateBus(t)
	host, port := resolvedTestUpstream(t, "192.0.2.3")
	cfg := resolvedTestConfig(t)
	cfg.DNS.Servers = append(cfg.DNS.Servers, DNSServer{Type: "hosts", Tag: "fallback", Predefined: map[string][]string{"other.test": {"192.0.2.9"}}})
	cfg.DNS.Final = "fallback"
	cfg.DNS.Rules = []DNSRule{{Rule: Rule{PreferredBy: []string{"link"}}, Server: "link"}}
	r := newTestRuntime(t, cfg)
	resolvedSetServer(t, address, 1, host, port)
	resolvedBusCall(t, address, "SetLinkDomains", "ia(sb)", "1", "1", "corp.test", "false")
	resolvedAssertIP(t, r, "node.corp.test", "192.0.2.3")
	resolvedAssertIP(t, r, "other.test", "192.0.2.9")
	resolvedBusCall(t, address, "SetLinkDefaultRoute", "ib", "1", "true")
	q, _ := makeDNSQuery("other.test", 1)
	reply, e := r.resolver.exchangeDNSOn(context.Background(), "link", q, DNSRule{}, false)
	if e != nil || reply[3]&15 != 3 {
		t.Fatal("accept_default_resolvers=false ignored", e)
	}
	s := r.resolved["resolve"]
	links, preferred := s.state.Load().candidates("other.test", 0, true)
	if len(links) != 1 || preferred {
		t.Fatal(links, preferred)
	}
	// Longest domain wins; explicit interface scope never selects another link.
	resolvedSetServer(t, address, 2, host, port)
	resolvedBusCall(t, address, "SetLinkDomains", "ia(sb)", "2", "1", "deep.corp.test", "true")
	links, _ = s.state.Load().candidates("node.deep.corp.test", 0, false)
	if len(links) != 1 || links[0].index != 2 {
		t.Fatal(links)
	}
	links, _ = s.state.Load().candidates("node.deep.corp.test", 1, false)
	if len(links) != 1 || links[0].index != 1 {
		t.Fatal(links)
	}
	resolvedBusCall(t, address, "SetLinkDNSEx", "ia(iayqs)", "2", "0")
	q, _ = makeDNSQuery("node.deep.corp.test", 1)
	if _, e = r.ExchangeDNS(context.Background(), q, ""); e == nil {
		t.Fatal("private domain with unavailable DNS fell through to another link")
	}
}
func TestResolvedLifecycleAndErrors(t *testing.T) {
	address, stop := resolvedPrivateBus(t)
	cfg := resolvedTestConfig(t)
	r := newTestRuntime(t, cfg)
	data, _ := json.Marshal(cfg)
	duplicate := cfg
	duplicate.Services = slices.Clone(cfg.Services)
	duplicate.Services[0].ListenPort = resolvedFreePort(t)
	duplicateData, _ := json.Marshal(duplicate)
	duplicateCore, e := New(context.Background(), duplicateData, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = duplicateCore.Start(); e == nil {
		t.Fatal("duplicate D-Bus owner accepted")
	}
	duplicateCore.Close()
	other, e := New(context.Background(), data, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if e = other.Start(); e == nil {
		t.Fatal("duplicate stub/name accepted")
	}
	for _, tc := range []struct {
		member, sig string
		args        []string
	}{{"SetLinkDNSEx", "ia(iayqs)", []string{"1", "1", "2", "3", "127", "0", "1", "53", ""}}, {"SetLinkDomains", "ia(sb)", []string{"1", "1", "bad..domain", "true"}}, {"SetLinkDefaultRoute", "ib", []string{"0", "true"}}, {"SetLinkDNSSEC", "is", []string{"1", "yes"}}, {"SetLinkDNS", "s", []string{"wrong"}}, {"Unknown", "", nil}} {
		if out, e := resolvedBusCommand(address, tc.member, tc.sig, tc.args...); e == nil {
			t.Fatal("invalid method succeeded", tc, out)
		}
	}
	if !resolvedCallerAllowed(0) || !resolvedCallerAllowed(uint32(os.Getuid())) || resolvedCallerAllowed(4294967294) {
		t.Fatal("mutation authorization")
	}
	stop()
	select {
	case <-r.resolved["resolve"].bus.done:
	case <-time.After(time.Second):
		t.Fatal("bus reader did not exit")
	}
	done := make(chan struct{})
	go func() { r.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("service shutdown blocked")
	}
	if len(r.resolved["resolve"].state.Load().links) != 0 {
		t.Fatal("closed service retained state")
	}
}

func TestResolvedRecordAddressAndService(t *testing.T) {
	address, _ := resolvedPrivateBus(t)
	cfg := resolvedTestConfig(t)
	cfg.DNS = DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"node.corp.test": {"192.0.2.42"}, "expanded.corp.test": {"192.0.2.43"}}}}, Rules: []DNSRule{
		{Rule: Rule{Domain: []string{"42.2.0.192.in-addr.arpa"}, Action: "predefined"}, Answer: []string{"42.2.0.192.in-addr.arpa. 60 IN PTR node.corp.test."}},
		{Rule: Rule{Domain: []string{"_https._tcp.corp.test"}, Action: "predefined"}, Answer: []string{"_https._tcp.corp.test. 60 IN SRV 10 20 443 node.corp.test.", `_https._tcp.corp.test. 60 IN TXT "a=b"`}},
		{Rule: Rule{Domain: []string{"alias.corp.test"}, Action: "predefined"}, Answer: []string{"alias.corp.test. 60 IN CNAME node.corp.test."}},
	}}
	r := newTestRuntime(t, cfg)
	checks := []struct {
		member, sig string
		args        []string
		want        string
	}{
		{"ResolveRecord", "isqqt", []string{"0", "node.corp.test", "1", "1", "0"}, "a(iqqay)t 1 0 1 1"},
		{"ResolveAddress", "iiayt", []string{"0", "2", "4", "192", "0", "2", "42", "0"}, `a(is)t 1 0 "node.corp.test"`},
		{"ResolveService", "isssit", []string{"0", "", "_https._tcp", "corp.test", "0", "0"}, "10 20 443"},
		{"ResolveService", "isssit", []string{"0", "", "_https._tcp", "corp.test", "0", "192"}, "10 20 443"},
		{"ResolveHostname", "isit", []string{"0", "alias.corp.test", "2", "0"}, "192 0 2 42"},
	}
	for _, tc := range checks {
		t.Run(tc.member+tc.args[len(tc.args)-1], func(t *testing.T) {
			out := resolvedBusCall(t, address, tc.member, tc.sig, tc.args...)
			if !strings.Contains(out, tc.want) {
				t.Fatal(out)
			}
		})
	}
	resolvedBusCall(t, address, "SetLinkDomains", "ia(sb)", "1", "1", "corp.test", "false")
	out := resolvedBusCall(t, address, "ResolveHostname", "isit", "0", "expanded", "2", "0")
	if !strings.Contains(out, "192 0 2 43") {
		t.Fatal(out)
	}
	if out, e := resolvedBusCommand(address, "ResolveHostname", "isit", "0", "alias.corp.test", "2", "32"); e == nil {
		t.Fatal("NO_CNAME ignored", out)
	}
	if out, e := resolvedBusCommand(address, "ResolveHostname", "isit", "0", "expanded", "2", "256"); e == nil {
		t.Fatal("NO_SEARCH ignored", out)
	}
	if out, e := resolvedBusCommand(address, "ResolveHostname", "isit", "0", "node.corp.test", "2", "512"); e == nil {
		t.Fatal("output authentication flag accepted as input", out)
	}
	if r.resolved["resolve"].state.Load().links[0].domains[0].routeOnly {
		t.Fatal("search domain changed")
	}
}

func TestResolvedFlushInflight(t *testing.T) {
	address, _ := resolvedPrivateBus(t)
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	upstream := dnsTestUpstream(t, "up", func(ctx context.Context, q []byte) []byte {
		if calls.Add(1) == 1 {
			close(started)
			select {
			case <-release:
				return dnsTestReply(q, "192.0.2.1")
			case <-ctx.Done():
				return nil
			}
		}
		return dnsTestReply(q, "192.0.2.2")
	})
	cfg := resolvedTestConfig(t)
	cfg.DNS = DNSConfig{Servers: []DNSServer{upstream}, Timeout: "3s"}
	r := newTestRuntime(t, cfg)
	q, _ := makeDNSQuery("parallel.test", 1)
	done := make(chan error, 1)
	go func() { _, e := r.ExchangeDNS(context.Background(), q, ""); done <- e }()
	<-started
	resolvedBusCall(t, address, "FlushCaches", "")
	resolvedAssertIP(t, r, "parallel.test", "192.0.2.2")
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	resolvedAssertIP(t, r, "parallel.test", "192.0.2.2")
	if calls.Load() != 2 {
		t.Fatal("post-flush cache was not retained", calls.Load())
	}
}

func TestResolvedChangedLinkInflight(t *testing.T) {
	address, _ := resolvedPrivateBus(t)
	started, release := make(chan struct{}), make(chan struct{})
	upstream := dnsTestUpstream(t, "wait", func(ctx context.Context, q []byte) []byte {
		close(started)
		select {
		case <-release:
			return dnsTestReply(q, "192.0.2.1")
		case <-ctx.Done():
			return nil
		}
	})
	old := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "dns", Tag: "old", Listen: "127.0.0.1"}}, DNS: DNSConfig{Servers: []DNSServer{upstream}}})
	cfg := resolvedTestConfig(t)
	cfg.DNS.Servers[0].AcceptDefaultResolvers = true
	r := newTestRuntime(t, cfg)
	host, port := splitTestAddress(t, old.Address("old"))
	resolvedSetServer(t, address, 1, host, port)
	resolvedBusCall(t, address, "SetLinkDefaultRoute", "ib", "1", "true")
	q, _ := makeDNSQuery("node.corp.test", 1)
	done := make(chan error, 1)
	go func() {
		reply, e := r.ExchangeDNS(context.Background(), q, "")
		if e == nil {
			ips, _, parseErr := parseDNSReply(q, reply)
			if parseErr != nil || len(ips) != 1 || ips[0].String() != "192.0.2.1" {
				e = fmt.Errorf("old snapshot %v %v", ips, parseErr)
			}
		}
		done <- e
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first query did not reach old resolver")
	}
	host, port = resolvedTestUpstream(t, "192.0.2.2")
	resolvedSetServer(t, address, 1, host, port)
	resolvedAssertIP(t, r, "node.corp.test", "192.0.2.2")
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	resolvedAssertIP(t, r, "node.corp.test", "192.0.2.2")
}

func TestResolvedTLSAndTCPFallback(t *testing.T) {
	address, _ := resolvedPrivateBus(t)
	cert := certificate(t)
	up := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "dns", Tag: "dns", Listen: "127.0.0.1", TLS: cert}}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"node.corp.test": {"192.0.2.7"}}}}}})
	host, port := splitTestAddress(t, up.Address("dns"))
	cfg := resolvedTestConfig(t)
	cfg.DNS.Servers[0].AcceptDefaultResolvers = true
	r := newTestRuntime(t, cfg)
	resolvedSetServer(t, address, 1, host, port)
	resolvedBusCall(t, address, "SetLinkDefaultRoute", "ib", "1", "true")
	resolvedBusCall(t, address, "SetLinkDNSOverTLS", "is", "1", "yes")
	q, _ := makeDNSQuery("node.corp.test", 1)
	if _, e := r.ExchangeDNS(context.Background(), q, ""); e == nil {
		t.Fatal("untrusted DoT certificate accepted")
	}
	resolvedBusCall(t, address, "SetLinkDNSOverTLS", "is", "1", "opportunistic")
	resolvedAssertIP(t, r, "node.corp.test", "192.0.2.7")
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(strings.Join(cert.Certificate, "\n"))) {
		t.Fatal("test root")
	}
	r.resolver.clients[""] = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12}}}
	resolvedBusCall(t, address, "SetLinkDNSOverTLS", "is", "1", "yes")
	resolvedAssertIP(t, r, "node.corp.test", "192.0.2.7")
	// A truncated UDP answer must retry the same server through TCP, not another DNS link.
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	p, e := net.ListenPacket("udp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	work := make(chan error, 2)
	go func() {
		buf := make([]byte, 2048)
		n, peer, e := p.ReadFrom(buf)
		if e != nil {
			work <- e
			return
		}
		reply := append([]byte(nil), buf[:n]...)
		reply[2] |= 0x82
		_, e = p.WriteTo(reply, peer)
		work <- e
	}()
	go func() {
		c, e := l.Accept()
		if e != nil {
			work <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		size := make([]byte, 2)
		_, e = io.ReadFull(c, size)
		if e == nil {
			q := make([]byte, binary.BigEndian.Uint16(size))
			_, e = io.ReadFull(c, q)
			if e == nil {
				reply := dnsTestReply(q, "192.0.2.8")
				e = writeAll(c, binary.BigEndian.AppendUint16(nil, uint16(len(reply))))
				if e == nil {
					e = writeAll(c, reply)
				}
			}
		}
		work <- e
	}()
	host, port = splitTestAddress(t, l.Addr().String())
	resolvedSetServer(t, address, 1, host, port)
	resolvedBusCall(t, address, "SetLinkDNSOverTLS", "is", "1", "no")
	resolvedAssertIP(t, r, "node.corp.test", "192.0.2.8")
	for range 2 {
		if e := <-work; e != nil {
			t.Fatal(e)
		}
	}
}

func TestResolvedOfficialReference(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only")
	}
	reference := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if reference == "" {
		t.Skip("set LANBOAT_TEST_SINGBOX15 for external resolved comparison")
	}
	address, _ := resolvedPrivateBus(t)
	host, port := resolvedTestUpstream(t, "192.0.2.54")
	cfg := resolvedTestConfig(t)
	raw, _ := json.Marshal(cfg)
	path := filepath.Join(t.TempDir(), "config.json")
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	for _, engine := range []string{"native", "reference"} {
		t.Run(engine, func(t *testing.T) {
			if engine == "native" {
				r := newTestRuntime(t, cfg)
				defer r.Close()
			} else {
				cmd := exec.Command(reference, "run", "-c", path)
				var logs bytes.Buffer
				cmd.Stdout = &logs
				cmd.Stderr = &logs
				if e := cmd.Start(); e != nil {
					t.Fatal(e)
				}
				defer func() {
					cmd.Process.Kill()
					cmd.Wait()
					if t.Failed() {
						t.Log(logs.String())
					}
				}()
				ready := false
				for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
					out, e := exec.Command("busctl", "--address="+address, "call", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "NameHasOwner", "s", resolvedName).Output()
					if e == nil && strings.TrimSpace(string(out)) == "b true" {
						ready = true
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if !ready {
					t.Fatal("reference did not acquire D-Bus name")
				}
			}
			resolvedSetServer(t, address, 1, host, port)
			resolvedBusCall(t, address, "SetLinkDomains", "ia(sb)", "1", "1", "corp.test", "true")
			out := resolvedBusCall(t, address, "ResolveHostname", "isit", "0", "node.corp.test", "0", "0")
			if !strings.Contains(out, "192 0 2 54") {
				t.Fatal(out)
			}
			out = resolvedBusCall(t, address, "ResolveRecord", "isqqt", "0", "node.corp.test", "1", "1", "0")
			if !strings.Contains(out, "192 0 2 54") {
				t.Fatal(out)
			}
			if _, e := resolvedBusCommand(address, "ResolveHostname", "isit", "0", "other.test", "2", "0"); e == nil {
				t.Fatal("split DNS mismatch did not return error")
			}
			resolvedBusCall(t, address, "SetLinkDefaultRoute", "ib", "1", "true")
			resolvedBusCall(t, address, "FlushCaches", "")
			resolvedBusCall(t, address, "RevertLink", "i", "1")
		})
	}
}
func TestResolvedValidation(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	}
	for _, raw := range []string{`{"services":[{"type":"unknown"}]}`, `{"dns":{"servers":[{"type":"resolved","service":"missing"}]}}`, `{"services":[{"type":"resolved"},{"type":"resolved","tag":"other"}]}`, `{"services":[{"type":"resolved"}],"dns":{"servers":[{"type":"resolved","service":"resolved","server":"1.1.1.1"}]}}`, `{"services":[{"type":"resolved"}],"inbounds":[{"type":"dns","tag":"resolved"}]}`} {
		if _, e := Parse([]byte(raw)); e == nil {
			t.Fatal("invalid configuration accepted", raw)
		}
	}
	cfg, e := Parse([]byte(`{"services":[{"type":"resolved"}],"dns":{"servers":[{"type":"resolved","service":"resolved"}]}}`))
	if e != nil || cfg.Services[0].Listen != "127.0.0.53" || cfg.Services[0].ListenPort != 53 {
		t.Fatal(e, cfg.Services)
	}
}
