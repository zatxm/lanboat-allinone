package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func masqueTestDNS(address string, alpn string) MasqueDNSConfiguration {
	host, port, _ := net.SplitHostPort(address)
	n, _ := strconv.Atoi(port)
	ns := MasqueNameserver{Priority: 1, Parameters: map[uint16][]byte{3: binary.BigEndian.AppendUint16(nil, uint16(n))}}
	if ip := netip.MustParseAddr(host); ip.Is4() {
		ns.IPv4Addresses = []netip.Addr{ip}
	} else {
		ns.IPv6Addresses = []netip.Addr{ip}
	}
	if alpn != "" {
		ns.ServerName = "example.com"
		ns.Parameters[1], ns.Parameters[2] = append([]byte{byte(len(alpn))}, alpn...), []byte{}
		if alpn == "h2" || alpn == "h3" {
			ns.Parameters[7] = []byte("/dns-query{?dns}")
		}
	}
	return MasqueDNSConfiguration{Nameservers: []MasqueNameserver{ns}, InternalDomains: []string{""}, SearchDomains: []string{"corp.example"}}
}

func masqueDNSPair(t *testing.T, version int, dns []MasqueDNSConfiguration, pref64 []netip.Prefix, dnsTLS TLSOptions) (*Runtime, *Runtime) {
	t.Helper()
	in := Inbound{Type: "masque", Tag: "server", Listen: "127.0.0.1", HTTPVersion: version, Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t), MasqueOptions: MasqueOptions{DNS: dns, PREF64: pref64}}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, s.Address("server"))
	out.Tag, out.HTTPVersion = "proxy", version
	out.MasqueOptions = MasqueOptions{AcceptDNS: true, AcceptPREF64: true}
	return s, newTestRuntime(t, Config{Outbounds: []Outbound{out}, DNS: DNSConfig{Servers: []DNSServer{{Type: "masque", Tag: "assigned", Endpoint: "proxy", TLS: dnsTLS}}, Final: "assigned"}})
}

func masqueDNSQuery(t *testing.T, r *Runtime, name string, typ uint16) []netip.Addr {
	t.Helper()
	query, _ := makeDNSQuery(name, typ)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	reply, err := r.ExchangeDNS(ctx, query, "")
	if err != nil {
		t.Fatal(err)
	}
	ips, _, err := parseDNSReply(query, reply)
	if err != nil {
		t.Fatal(err)
	}
	return ips
}

func masqueWaitNetwork(t *testing.T, c *Runtime, wantDNS, wantPREF64 bool) MasqueNetworkConfiguration {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var version uint64
	for {
		state, err := c.WaitMasqueConfiguration(ctx, "proxy", version)
		if err != nil {
			t.Fatal(err)
		}
		if (!wantDNS || state.DNSReceived) && (!wantPREF64 || state.PREF64Received) {
			return state
		}
		version = state.Version
	}
}

func TestMasqueNetworkConfiguration(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			backend := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "dns", Tag: "dns", Listen: "127.0.0.1"}}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"v4.test": {"192.0.2.7"}, "v6.test": {"2001:db8::7"}}}}}})
			dns := masqueTestDNS(backend.Address("dns"), "")
			s, c := masqueDNSPair(t, version, []MasqueDNSConfiguration{dns}, []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")}, TLSOptions{})
			state := masqueWaitNetwork(t, c, true, true)
			if len(state.DNS) != 1 || state.DNS[0].SearchDomains[0] != "corp.example" || len(state.PREF64) != 1 {
				t.Fatal(state)
			}
			for _, tc := range []struct {
				name string
				typ  uint16
				want string
			}{{"v4.test", 1, "192.0.2.7"}, {"v4.test", 28, "64:ff9b::c000:207"}, {"v6.test", 28, "2001:db8::7"}} {
				ips := masqueDNSQuery(t, c, tc.name, tc.typ)
				if len(ips) != 1 || ips[0].String() != tc.want {
					t.Fatal(tc, ips)
				}
			}
			state.DNS[0].Nameservers[0].Parameters[3][0] ^= 255
			fresh, err := c.MasqueConfiguration(context.Background(), "proxy")
			if err != nil || bytes.Equal(fresh.DNS[0].Nameservers[0].Parameters[3], state.DNS[0].Nameservers[0].Parameters[3]) {
				t.Fatal("snapshot aliases active configuration", err)
			}
			oldVersion := fresh.Version
			c.resetNetworkTransports()
			fresh = masqueWaitNetwork(t, c, true, true)
			if fresh.Version <= oldVersion {
				t.Fatal("new session reused DNS cache version")
			}
			if ips := masqueDNSQuery(t, c, "v4.test", 1); len(ips) != 1 {
				t.Fatal(ips)
			}
			if err := s.PublishMasqueConfiguration(context.Background(), "server", nil, nil); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			for {
				fresh, err = c.WaitMasqueConfiguration(ctx, "proxy", fresh.Version)
				if err != nil {
					t.Fatal(err)
				}
				if len(fresh.DNS) == 0 && len(fresh.PREF64) == 0 {
					break
				}
			}
			q, _ := makeDNSQuery("v4.test", 1)
			if _, err := c.ExchangeDNS(context.Background(), q, ""); err == nil {
				t.Fatal("withdrawal returned cached DNS answer")
			}
		})
	}
}

func TestMasqueEncryptedDNS(t *testing.T) {
	for _, kind := range []string{"tls", "https", "quic", "h3"} {
		t.Run(kind, func(t *testing.T) {
			var address string
			var trust TLSOptions
			if kind == "https" {
				s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					if req.ProtoMajor != 2 || req.URL.Path != "/dns-query" || req.URL.RawQuery != "token=test" {
						t.Error("wrong DoH request", req.Proto, req.URL)
					}
					q, _ := io.ReadAll(req.Body)
					w.Header().Set("Content-Type", "application/dns-message")
					w.Write(dnsAnswer(q))
				}))
				s.EnableHTTP2 = true
				s.StartTLS()
				t.Cleanup(s.Close)
				address, trust = s.Listener.Addr().String(), TLSOptions{Insecure: true}
			} else {
				typ := "dns"
				if kind == "quic" || kind == "h3" {
					typ += "-" + kind
				}
				in := Inbound{Type: typ, Tag: "dns", Listen: "127.0.0.1", TLS: certificate(t)}
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"example.test": {"192.0.2.42", "2001:db8::42"}}}}}})
				address, trust = s.Address("dns"), TLSOptions{Certificate: in.TLS.Certificate}
			}
			alpn := map[string]string{"tls": "dot", "https": "h2", "quic": "doq", "h3": "h3"}[kind]
			dns := masqueTestDNS(address, alpn)
			if kind == "https" {
				dns.Nameservers[0].Parameters[7] = []byte("/dns-query?token=test{&dns}")
			}
			_, c := masqueDNSPair(t, 3, []MasqueDNSConfiguration{dns}, nil, trust)
			masqueWaitNetwork(t, c, true, false)
			var workers sync.WaitGroup
			for range 8 {
				workers.Go(func() { masqueDNSQuery(t, c, "example.test", 1) })
			}
			workers.Wait()
		})
	}
}

func TestMasqueConfigurationCodec(t *testing.T) {
	plain := masqueTestDNS("192.0.2.33:53", "")
	plain.Nameservers[0].IPv6Addresses = []netip.Addr{netip.MustParseAddr("2001:db8::1")}
	plain.InternalDomains = []string{"internal.corp.example", "xn--fiqs8s.example"}
	encrypted := masqueTestDNS("[2001:db8::2]:853", "doq")
	for _, configs := range [][]MasqueDNSConfiguration{nil, {plain}, {plain, encrypted}} {
		b, err := masqueDNSBytes(configs)
		if err != nil {
			t.Fatal(err)
		}
		got, err := masqueDNSConfigurations(b)
		if err != nil {
			t.Fatal(err)
		}
		again, err := masqueDNSBytes(got)
		if err != nil || !bytes.Equal(b, again) {
			t.Fatal("noncanonical round trip", err)
		}
		for n := 1; n < len(b); n++ {
			// A complete earlier configuration is a valid shorter capsule.
			if decoded, err := masqueDNSConfigurations(b[:n]); err == nil {
				v, _ := masqueDNSBytes(decoded)
				if !bytes.Equal(v, b[:n]) {
					t.Fatal("truncation accepted", n)
				}
			}
		}
	}
	b, _ := masquePREF64Bytes([]netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")})
	if hex.EncodeToString(b) != "600064ff9b0000000000000000" {
		t.Fatal("PREF64 draft vector", hex.EncodeToString(b))
	}
	for _, bits := range []int{32, 40, 48, 56, 64, 96} {
		prefix := netip.PrefixFrom(netip.MustParseAddr("2001:db8::"), bits)
		b, err := masquePREF64Bytes([]netip.Prefix{prefix})
		got, e := masquePREF64Prefixes(b)
		if err != nil || e != nil || !slices.Equal(got, []netip.Prefix{prefix}) {
			t.Fatal(bits, got, err, e)
		}
		ip := masqueNAT64(prefix, netip.MustParseAddr("192.0.2.33"))
		if !prefix.Contains(ip) || bits < 96 && ip.As16()[8] != 0 {
			t.Fatal("invalid synthesized IPv6", bits, ip)
		}
	}
}

func FuzzMasqueNetworkConfiguration(f *testing.F) {
	b, _ := masqueDNSBytes([]MasqueDNSConfiguration{masqueTestDNS("192.0.2.33:53", "")})
	f.Add(b)
	f.Add([]byte{96, 0, 100, 255, 155, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if cfg, err := masqueDNSConfigurations(b); err == nil {
			if _, err := masqueDNSBytes(cfg); err != nil {
				t.Fatal(err)
			}
		}
		_, _ = masquePREF64Prefixes(b)
	})
}

func masquePlainDNS(t *testing.T, ip string, truncated bool) (string, *atomic.Int64) {
	t.Helper()
	var listener net.Listener
	var packet net.PacketConn
	var err error
	if truncated {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			listener, packet, err = bindPairedUDP(listener, true)
		}
	} else {
		packet, err = net.ListenPacket("udp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { packet.Close() })
	if listener != nil {
		t.Cleanup(func() { listener.Close() })
	}
	var count atomic.Int64
	answer := func(q []byte) []byte {
		count.Add(1)
		_, end, typ, err := dnsQuestion(q)
		if err != nil {
			return nil
		}
		var ips []netip.Addr
		if typ == 1 {
			ips = []netip.Addr{netip.MustParseAddr(ip)}
		}
		return dnsResponse(q, end, ips, 300, 0)
	}
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, err := packet.ReadFrom(b)
			if err != nil {
				return
			}
			reply := answer(b[:n])
			if truncated {
				reply = reply[:n]
				reply[2] |= 2
				clear(reply[6:8])
			}
			packet.WriteTo(reply, a)
		}
	}()
	if truncated {
		go func() {
			for {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					var size [2]byte
					if _, err := io.ReadFull(c, size[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(size[:]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					reply := answer(q)
					writeAll(c, binary.BigEndian.AppendUint16(nil, uint16(len(reply))))
					writeAll(c, reply)
				}()
			}
		}()
	}
	return packet.LocalAddr().String(), &count
}

func TestMasqueDNSCacheAndPolicy(t *testing.T) {
	a, ca := masquePlainDNS(t, "192.0.2.7", true)
	b, cb := masquePlainDNS(t, "192.0.2.8", false)
	root, corp := masqueTestDNS(a, ""), masqueTestDNS(b, "")
	corp.InternalDomains = []string{"corp.example"}
	s, c := masqueDNSPair(t, 3, []MasqueDNSConfiguration{root, corp}, nil, TLSOptions{})
	state := masqueWaitNetwork(t, c, true, false)
	for range 2 {
		if ips := masqueDNSQuery(t, c, "host.example", 1); len(ips) != 1 || ips[0].String() != "192.0.2.7" {
			t.Fatal(ips)
		}
		if ips := masqueDNSQuery(t, c, "host.corp.example", 1); len(ips) != 1 || ips[0].String() != "192.0.2.8" {
			t.Fatal(ips)
		}
	}
	if ca.Load() != 2 || cb.Load() != 1 {
		t.Fatal("cache or TCP fallback failed", ca.Load(), cb.Load())
	}
	corp.InternalDomains = []string{""}
	if err := s.PublishMasqueConfiguration(context.Background(), "server", []MasqueDNSConfiguration{corp}, nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := c.WaitMasqueConfiguration(ctx, "proxy", state.Version); err != nil {
		t.Fatal(err)
	}
	if ips := masqueDNSQuery(t, c, "host.example", 1); len(ips) != 1 || ips[0].String() != "192.0.2.8" {
		t.Fatal("update returned old cached address", ips)
	}
	// EDNS DO=1 leaves a signed resolver's negative AAAA response unchanged.
	if err := s.PublishMasqueConfiguration(ctx, "server", []MasqueDNSConfiguration{corp}, []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")}); err != nil {
		t.Fatal(err)
	}
	masqueWaitNetwork(t, c, true, true)
	q, _ := makeDNSQuery("signed.example", 28)
	q[11] = 1
	q = append(q, 0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0)
	reply, err := c.ExchangeDNS(context.Background(), q, "")
	if err != nil {
		t.Fatal(err)
	}
	if ips, _, err := parseDNSReply(q, reply); err != nil || len(ips) != 0 {
		t.Fatal("DNS64 synthesized a DNSSEC request", ips, err)
	}
}

func TestMasqueDNSBootstrap(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q, _ := io.ReadAll(req.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(dnsAnswer(q))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	dns := masqueTestDNS(srv.Listener.Addr().String(), "h2")
	dns.Nameservers[0].IPv4Addresses = nil
	_, initial := masqueDNSPair(t, 3, []MasqueDNSConfiguration{dns}, nil, TLSOptions{Insecure: true})
	config := initial.config
	initial.Close()
	config.DNS.Servers[0].DomainResolver = "bootstrap"
	config.DNS.Servers = append(config.DNS.Servers, DNSServer{Type: "hosts", Tag: "bootstrap", Predefined: map[string][]string{"example.com": {"127.0.0.1"}}})
	c := newTestRuntime(t, config)
	if ips := masqueDNSQuery(t, c, "example.test", 1); len(ips) != 1 {
		t.Fatal(ips)
	}
	// Also bootstrap the MASQUE endpoint's hostname without recursing into itself.
	config.Outbounds[0].Server = "localhost"
	config.Outbounds[0].DomainResolver = "bootstrap"
	config.DNS.Servers[1].Predefined["localhost"] = []string{"127.0.0.1"}
	other := newTestRuntime(t, config)
	if ips := masqueDNSQuery(t, other, "example.test", 1); len(ips) != 1 {
		t.Fatal(ips)
	}
	config.Outbounds[0].DomainResolver = ""
	local := newTestRuntime(t, config)
	if ips := masqueDNSQuery(t, local, "example.test", 1); len(ips) != 1 {
		t.Fatal(ips)
	}
	config.Outbounds[0].DomainResolver = "assigned"
	raw, _ := json.Marshal(config)
	if _, err := Parse(raw); err == nil {
		t.Fatal("self bootstrap DNS cycle accepted")
	}
}

func TestMasqueConfigurationValidation(t *testing.T) {
	for name, mutate := range map[string]func(*MasqueDNSConfiguration){
		"priority":     func(c *MasqueDNSConfiguration) { c.Nameservers[0].Priority = 0 },
		"zero-server":  func(c *MasqueDNSConfiguration) { c.Nameservers = nil },
		"unicode":      func(c *MasqueDNSConfiguration) { c.SearchDomains = []string{"中文.example"} },
		"trailing-dot": func(c *MasqueDNSConfiguration) { c.InternalDomains = []string{"example."} },
		"empty-search": func(c *MasqueDNSConfiguration) { c.SearchDomains = []string{""} },
		"ipv4hint":     func(c *MasqueDNSConfiguration) { c.Nameservers[0].Parameters[4] = []byte{1, 2, 3, 4} },
		"ipv6hint":     func(c *MasqueDNSConfiguration) { c.Nameservers[0].Parameters[6] = make([]byte, 16) },
		"mixed-address": func(c *MasqueDNSConfiguration) {
			c.Nameservers[0].IPv6Addresses = []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.1")}
		},
		"invalid-alpn": func(c *MasqueDNSConfiguration) {
			c.Nameservers[0].ServerName = "example.com"
			c.Nameservers[0].Parameters[1] = []byte{0}
		},
		"encrypted-no-name": func(c *MasqueDNSConfiguration) { c.Nameservers[0].Parameters[1] = []byte{3, 'd', 'o', 't'} },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := masqueTestDNS("192.0.2.1:53", "")
			mutate(&cfg)
			if _, err := masqueDNSBytes([]MasqueDNSConfiguration{cfg}); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	for _, b := range [][]byte{{0}, {0x40}, {255, 255, 255, 255, 255, 255, 255, 255}, make([]byte, 65537)} {
		if _, err := masqueDNSConfigurations(b); err == nil {
			t.Fatal("invalid DNS capsule accepted")
		}
	}
	for _, b := range [][]byte{{1}, make([]byte, 13), make([]byte, 129*13)} {
		if _, err := masquePREF64Prefixes(b); err == nil {
			t.Fatal("invalid PREF64 capsule accepted")
		}
	}
	r := newTestRuntime(t, Config{})
	p := &masqueIP{runtime: r, configurationChanged: make(chan struct{})}
	if err := p.configureNetwork(masqueDNSAssign, []byte{0xff}); err != nil || p.configuration.Version != 0 {
		t.Fatal("untrusted configuration was interpreted", err)
	}
	p.acceptDNS = true
	b, _ := masqueDNSBytes([]MasqueDNSConfiguration{masqueTestDNS("192.0.2.1:53", "")})
	if err := p.configureNetwork(masqueDNSAssign, b); err == nil {
		t.Fatal("DNS before routes accepted")
	}
	p.haveRoutes = true
	if err := p.configureNetwork(masqueDNSAssign, b); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.PublishMasqueConfiguration(ctx, "missing", nil, nil); err == nil {
		t.Fatal("missing endpoint accepted")
	}
	if _, err := r.WaitMasqueConfiguration(ctx, "missing", 0); err == nil {
		t.Fatal("missing client accepted")
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal(ctx.Err())
	}
}

func TestMasqueDNSAddressesAndNoLeak(t *testing.T) {
	backend := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "dns", Tag: "dns", Listen: "::1"}}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"example.test": {"192.0.2.42"}}}}}})
	cfg := masqueTestDNS(backend.Address("dns"), "")
	cfg.Nameservers[0].IPv4Addresses = []netip.Addr{netip.MustParseAddr("127.0.0.2")}
	_, c := masqueDNSPair(t, 3, []MasqueDNSConfiguration{cfg}, nil, TLSOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	q, _ := makeDNSQuery("example.test", 1)
	reply, err := c.ExchangeDNS(ctx, q, "")
	if err != nil {
		t.Fatal("IPv6 fallback", err)
	}
	if ips, _, err := parseDNSReply(q, reply); err != nil || len(ips) != 1 {
		t.Fatal(ips, err)
	}
	address, requests := masquePlainDNS(t, "192.0.2.7", false)
	s, base := masqueDNSPair(t, 3, []MasqueDNSConfiguration{masqueTestDNS(address, "")}, nil, TLSOptions{})
	serverConfig := s.config
	serverConfig.Route = Route{Rules: []Rule{{Network: []string{"udp"}, Action: "reject"}}}
	blocked := newTestRuntime(t, serverConfig)
	clientConfig := base.config
	out := testOutbound(t, serverConfig.Inbounds[0], blocked.Address("server"))
	out.AcceptDNS = true
	out.AcceptPREF64 = true
	clientConfig.Outbounds = []Outbound{out}
	client := newTestRuntime(t, clientConfig)
	call, stop := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer stop()
	if _, err := client.ExchangeDNS(call, q, ""); err == nil {
		t.Fatal("rejected tunnel DNS succeeded")
	}
	if requests.Load() != 0 {
		t.Fatal("DNS escaped the rejected tunnel", requests.Load())
	}
}

func TestMasqueConfigurationConcurrency(t *testing.T) {
	address, _ := masquePlainDNS(t, "192.0.2.7", false)
	dns := []MasqueDNSConfiguration{masqueTestDNS(address, "")}
	s, c := masqueDNSPair(t, 3, dns, nil, TLSOptions{})
	state := masqueWaitNetwork(t, c, true, false)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 16 {
				if ips := masqueDNSQuery(t, c, "example.test", 1); len(ips) != 1 {
					t.Error(ips)
				}
			}
		})
	}
	workers.Go(func() {
		for range 20 {
			if err := s.PublishMasqueConfiguration(context.Background(), "server", dns, nil); err != nil {
				t.Error(err)
			}
		}
	})
	workers.Wait()
	manager := s.masqueNetworkServers["server"]
	manager.gate <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	err := s.PublishMasqueConfiguration(ctx, "server", nil, nil)
	cancel()
	<-manager.gate
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("publication ignored cancellation while waiting", err)
	}
	fresh, err := c.MasqueConfiguration(context.Background(), "proxy")
	if err != nil || fresh.Version <= state.Version {
		t.Fatal(fresh, err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Millisecond)
	_, err = c.WaitMasqueConfiguration(ctx, "proxy", fresh.Version)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("configuration wait ignored deadline", err)
	}
}

func TestMasqueUntrustedConfiguration(t *testing.T) {
	s, c := masquePair(t, "ip")
	assertTCP(t, c)
	manager := s.masqueNetworkServers["server"]
	manager.gate <- struct{}{}
	var peer *masqueIP
	for p := range manager.peers {
		peer = p
		break
	}
	<-manager.gate
	if peer == nil {
		t.Fatal("server tunnel missing")
	}
	if err := peer.flow.capsule(masqueDNSAssign, make([]byte, 100000)); err != nil {
		t.Fatal(err)
	}
	if err := peer.flow.capsule(masquePREF64, []byte{0xff}); err != nil {
		t.Fatal(err)
	}
	assertTCP(t, c)
	state, err := c.MasqueConfiguration(context.Background(), "proxy")
	if err != nil || state.Version != 0 || state.DNSReceived || state.PREF64Received {
		t.Fatal("unsolicited configuration was accepted", state, err)
	}
}

func TestMasqueDNSProtocolFallback(t *testing.T) {
	var requests atomic.Int64
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		if req.ProtoMajor != 2 {
			t.Error("ALPN fallback did not use HTTP2", req.Proto)
		}
		q, _ := io.ReadAll(req.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(dnsAnswer(q))
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	dns := masqueTestDNS(origin.Listener.Addr().String(), "h3")
	dns.Nameservers[0].Parameters[1] = []byte{2, 'h', '3', 2, 'h', '2'}
	_, c := masqueDNSPair(t, 3, []MasqueDNSConfiguration{dns}, nil, TLSOptions{Insecure: true})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	q, _ := makeDNSQuery("example.test", 1)
	reply, err := c.ExchangeDNS(ctx, q, "")
	if err != nil {
		t.Fatal(err)
	}
	if ips, _, err := parseDNSReply(q, reply); err != nil || len(ips) != 1 || requests.Load() != 1 {
		t.Fatal(ips, err, requests.Load())
	}
}
