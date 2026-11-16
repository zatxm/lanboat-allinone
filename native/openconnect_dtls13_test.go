package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"
)

func TestOpenConnectDTLS13(t *testing.T) {
	for _, suite := range []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "mixed-hash"} {
		t.Run(suite, func(t *testing.T) {
			name := suite
			if suite == "mixed-hash" {
				name = "TLS_AES_256_GCM_SHA384"
			}
			in := Inbound{Type: "openconnect", Tag: "server", Listen: "127.0.0.1", Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t), OpenConnectOptions: OpenConnectOptions{DTLSVersion: "1.3", DTLSCipherSuites: []string{name}}}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			host, port, _ := net.SplitHostPort(server.Address("server"))
			var number uint16
			fmt.Sscan(port, &number)
			out := Outbound{Type: "openconnect", Tag: "proxy", Server: host, ServerPort: number, Username: "client", Password: "private", TLS: TLSOptions{Enabled: true, Insecure: true}, OpenConnectOptions: in.OpenConnectOptions}
			if suite == "mixed-hash" {
				out.DTLSCipherSuites = nil
			}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			tunnel, err := client.ocClients["proxy"].session(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			d := ocWaitDTLS(t, tunnel)
			if d.v13 == nil || !d.v13.retried {
				t.Fatal("DTLS1.3 stateless cookie was bypassed")
			}
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{0, 1, 511, 4096, 60000})
			assertUDPAddress(t, client, []int{1, 4096, 60000}, masqueEcho(t, "udp", "[::1]:0"))
			if d.sent.Load() == 0 || d.received.Load() == 0 {
				t.Fatal("CSTP concealed broken DTLS1.3")
			}
			d.conn.Close()
			deadline := time.Now().Add(time.Second)
			for d.ready.Load() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			assertTCP(t, client)
			next := ocWaitDTLS(t, tunnel)
			if next == d {
				t.Fatal("DTLS1.3 channel was not renewed")
			}
			assertUDPSizes(t, client, []int{4096})
			if next.sent.Load() == 0 || next.received.Load() == 0 {
				t.Fatal("renewed DTLS1.3 carried no traffic")
			}
		})
	}
}

func TestOpenConnectDTLS13Config(t *testing.T) {
	_, base := ocPair(t)
	o := base.config.Outbounds[0]
	o.DTLSVersion = "1.3"
	o.DTLSCipherSuites = nil
	for _, name := range []string{"", "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"} {
		o.DTLSCipherSuites = nil
		if name != "" {
			o.DTLSCipherSuites = []string{name}
		}
		raw, _ := json.Marshal(Config{Outbounds: []Outbound{o}})
		if _, err := Parse(raw); err != nil {
			t.Fatal(name, err)
		}
	}
	for _, bad := range []struct {
		version  string
		disabled bool
		names    []string
	}{
		{"1.4", false, nil}, {"1.3", true, nil}, {"1.3", false, []string{"PSK-AES128-GCM-SHA256"}},
		{"1.3", false, []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"}},
		{"1.2", false, []string{"TLS_AES_128_GCM_SHA256"}},
	} {
		o.DTLSVersion = bad.version
		o.DisableDTLS = bad.disabled
		o.DTLSCipherSuites = bad.names
		raw, _ := json.Marshal(Config{Outbounds: []Outbound{o}})
		if _, err := Parse(raw); err == nil {
			t.Fatal("accepted conflicting config", bad)
		}
	}
	o.DTLSVersion = "1.3"
	o.DisableDTLS = false
	o.DTLSCipherSuites = nil
	o.Type = "socks"
	o.Group = ""
	raw, _ := json.Marshal(Config{Outbounds: []Outbound{o}})
	if _, err := Parse(raw); err == nil {
		t.Fatal("DTLS version accepted on another protocol")
	}
}

func TestOpenConnectDTLS13Cookie(t *testing.T) {
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	peer, err := net.Dial("udp4", packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	listener := newOCDTLSListener(nil, packet)
	listener.version13 = true
	listener.suites = []uint16{0x1301}
	id := bytes.Repeat([]byte{8}, 32)
	listener.bindings[string(id)] = &ocDTLSBinding{}
	owner := &ocDTLS{client: true, psk: bytes.Repeat([]byte{9}, 32), suites: listener.suites}
	d := &dtls13{identity: []byte(hex.EncodeToString(id))}
	d.init(owner)
	body, err := d.clientHello(nil)
	if err != nil {
		t.Fatal(err)
	}
	wire := append(ocDTLSRecordHeader(22, 0, 0, len(body)+12), ocDTLSHandshakeMessage(1, 0, body)...)
	if _, accepted := listener.accept13(wire, peer.LocalAddr()); accepted != nil {
		t.Fatal("cookie omitted")
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 2048)
	n, err := peer.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	p := stCursor{data: b[25:n]}
	p.take(34)
	p.vector(1)
	p.take(3)
	extensions := p.vector(2)
	ext, err := stExtensions(extensions)
	if err != nil {
		t.Fatal(err)
	}
	cookie := stCursor{data: ext[44]}
	good := bytes.Clone(cookie.vector(2))
	retry := func(c []byte) []byte {
		body, e := d.clientHello(c)
		if e != nil {
			t.Fatal(e)
		}
		return append(ocDTLSRecordHeader(22, 0, 1, len(body)+12), ocDTLSHandshakeMessage(1, 1, body)...)
	}
	if got, v := listener.accept13(retry(good), peer.LocalAddr()); v == nil || !bytes.Equal(got, id) {
		t.Fatal("valid source cookie rejected")
	}
	changed := retry(good)
	hello, e := parseDTLS13Hello(changed[25:])
	if e != nil {
		t.Fatal(e)
	}
	hello.share[0] ^= 1
	if _, v := listener.accept13(changed, peer.LocalAddr()); v != nil {
		t.Fatal("ClientHello changed outside cookie and binder")
	}
	for i := range good {
		bad := bytes.Clone(good)
		bad[i] ^= 1
		if _, v := listener.accept13(retry(bad), peer.LocalAddr()); v != nil {
			t.Fatal("tampered cookie", i)
		}
	}
	other := *peer.LocalAddr().(*net.UDPAddr)
	other.Port++
	if _, v := listener.accept13(retry(good), &other); v != nil {
		t.Fatal("cookie accepted on a different source")
	}
	expired := bytes.Clone(good)
	binary.BigEndian.PutUint64(expired, uint64(time.Now().Add(-3*time.Minute).Unix()))
	claims := expired[:len(expired)-16]
	copy(expired[len(expired)-16:], listener.dtls13CookieMAC(peer.LocalAddr(), id, d.random[:], claims))
	if _, v := listener.accept13(retry(expired), peer.LocalAddr()); v != nil {
		t.Fatal("expired cookie accepted")
	}
	if len(listener.peers) != 0 {
		t.Fatal("stateless cookie allocated a peer")
	}
}

func TestDTLS13CipherOffer(t *testing.T) {
	c, s := dtls13Pair(t, 0x1301)
	c.suites = []uint16{0x1301, 0x1303, 0x1302}
	s.suites = []uint16{0x1302, 0x1303}
	dtls13HandshakePair(t, c, s)
	if c.suite != 0x1302 || s.suite != 0x1302 {
		t.Fatal("server cipher priority/PSK hash selection", c.suite, s.suite)
	}
}

func FuzzDTLS13Hello(f *testing.F) {
	o := &ocDTLS{psk: bytes.Repeat([]byte{7}, 32), suites: []uint16{0x1301, 0x1302, 0x1303}}
	d := &dtls13{identity: []byte("lanboat")}
	d.init(o)
	b, err := d.clientHello(nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseDTLS13Hello(b) })
}

func TestDTLS13Records(t *testing.T) {
	for _, id := range []uint16{0x1301, 0x1302, 0x1303} {
		t.Run(fmt.Sprintf("%04x", id), func(t *testing.T) {
			s, _ := stSuite(id)
			secret := bytes.Repeat([]byte{7}, s.hash.Size())
			sender, _ := newDTLS13Epoch(s, secret, 3)
			receiver, _ := newDTLS13Epoch(s, secret, 3)
			for n := range 70000 {
				payload := []byte{byte(n), byte(n >> 8)}
				wire, err := sender.seal(23, payload)
				if err != nil {
					t.Fatal(err)
				}
				if n%1000 == 0 {
					for _, index := range []int{0, 1, 2, len(wire) - 1} {
						bad := bytes.Clone(wire)
						bad[index] ^= 1
						if _, _, _, _, ok := receiver.open(bad); ok {
							t.Fatal("tampering accepted")
						}
					}
				}
				kind, data, seq, duplicate, ok := receiver.open(wire)
				if !ok || duplicate || kind != 23 || seq != uint64(n) || !bytes.Equal(data, payload) {
					t.Fatal(n, seq, kind, duplicate, ok)
				}
				if _, _, _, duplicate, ok = receiver.open(wire); !ok || !duplicate {
					t.Fatal("replay not identified")
				}
			}
			sender.sequence = 1 << 24
			if _, err := sender.seal(23, nil); err == nil {
				t.Fatal("AEAD usage limit bypassed")
			}
		})
	}
	for _, v := range []struct {
		short      uint64
		bits       uint
		next, want uint64
	}{{0, 8, 256, 256}, {255, 8, 256, 255}, {0, 16, 65536, 65536}, {65535, 16, 65536, 65535}} {
		if got := dtls13Sequence(v.short, v.bits, v.next); got != v.want {
			t.Fatal(v, got)
		}
	}
	// A short header can omit the length and carry an eight-bit encrypted sequence.
	s, _ := stSuite(0x1301)
	key, _ := newDTLS13Epoch(s, bytes.Repeat([]byte{4}, 32), 3)
	header := []byte{0x23, 0}
	plain := []byte{9, 23}
	wire := key.key.aead.Seal(bytes.Clone(header), key.key.nonce(0), plain, header)
	mask := key.key.mask(wire[2:])
	wire[1] ^= mask[0]
	kind, p, _, dup, ok := key.open(wire)
	if !ok || dup || kind != 23 || !slices.Equal(p, []byte{9}) || dtls13RecordSize(wire) != len(wire) {
		t.Fatal("minimal header", kind, p, dup, ok)
	}
}

func TestOpenConnectDTLS13VersionMismatch(t *testing.T) {
	for _, versions := range [][2]string{{"1.3", "1.2"}, {"1.2", "1.3"}} {
		t.Run(versions[0]+"-"+versions[1], func(t *testing.T) {
			in := Inbound{Type: "openconnect", Tag: "server", Listen: "127.0.0.1", Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t), OpenConnectOptions: OpenConnectOptions{DTLSVersion: versions[0]}}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			host, port, _ := net.SplitHostPort(server.Address("server"))
			var number uint16
			fmt.Sscan(port, &number)
			out := Outbound{Type: "openconnect", Tag: "proxy", Server: host, ServerPort: number, Username: "client", Password: "private", TLS: TLSOptions{Enabled: true, Insecure: true}, OpenConnectOptions: OpenConnectOptions{DTLSVersion: versions[1]}}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 4096})
			tunnel := client.ocClients["proxy"].tunnel.Load()
			tunnel.dtlsMu.Lock()
			installed := tunnel.dtls
			tunnel.dtlsMu.Unlock()
			server.ocServers["server"].dtls.mu.Lock()
			n := len(server.ocServers["server"].dtls.bindings)
			server.ocServers["server"].dtls.mu.Unlock()
			if installed != nil || n != 0 {
				t.Fatal("unnegotiated DTLS allocated a channel")
			}
		})
	}
}
