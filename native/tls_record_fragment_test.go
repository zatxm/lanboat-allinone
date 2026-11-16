package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func tlsFragmentPayload(t *testing.T, wire []byte) ([][]byte, []byte) {
	t.Helper()
	var records [][]byte
	var body []byte
	for len(wire) > 0 {
		if len(wire) < 5 {
			t.Fatal("short TLS header")
		}
		n := int(binary.BigEndian.Uint16(wire[3:5]))
		if len(wire) < 5+n {
			t.Fatal("short TLS body")
		}
		records = append(records, wire[:5+n])
		body = append(body, wire[5:5+n]...)
		wire = wire[5+n:]
	}
	return records, body
}

func TestTLSRecordFragmentWire(t *testing.T) {
	var capture bytes.Buffer
	c := tls.Client(memoryNetConn{bytes.NewReader(nil), &capture}, &tls.Config{ServerName: "record-fragment.example", InsecureSkipVerify: true})
	_ = c.Handshake()
	original := capture.Bytes()
	_, hello := tlsFragmentPayload(t, original)
	name, start, ok := clientHelloSNI(hello)
	if !ok || name != "record-fragment.example" || string(hello[start:start+len(name)]) != name {
		t.Fatal("SNI position", name, start, ok)
	}
	wire, left, err := fragmentTLSRecords(original, 0)
	if err != nil || left != 0 {
		t.Fatal(left, err)
	}
	records, body := tlsFragmentPayload(t, wire)
	if len(records) != 2 || !bytes.Equal(body, hello) {
		t.Fatal("changed TLS transcript")
	}
	for _, record := range records {
		if bytes.Contains(record, []byte(name)) {
			t.Fatal("SNI remained inside a single record")
		}
	}
	data := []byte{23, 3, 3, 0, 4, 1, 2, 3, 4}
	w := &tlsRecordFragmentConn{Conn: memoryNetConn{bytes.NewReader(nil), &capture}}
	capture.Reset()
	if n, e := w.Write(data); e != nil || n != len(data) || !bytes.Equal(capture.Bytes(), data) {
		t.Fatal("encrypted records modified", n, e)
	}
	for _, p := range [][]byte{{22, 3}, {22, 3, 3, 0, 4, 1}, {22, 3, 3, 0, 0, 0}, make([]byte, (1<<20)+1)} {
		if _, _, err := fragmentTLSRecords(p, 0); err == nil {
			t.Fatal("accepted malformed record")
		}
	}
	// One large ClientHello can span multiple original TLS records.
	first := []byte{22, 3, 3, 0, 8, 1, 0, 0, 16, 0, 0, 0, 0}
	second := []byte{22, 3, 3, 0, 12, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	_, left, err = fragmentTLSRecords(first, 0)
	if err != nil || left != 12 {
		t.Fatal(left, err)
	}
	_, left, err = fragmentTLSRecords(second, left)
	if err != nil || left != 0 {
		t.Fatal(left, err)
	}
}

func TestTLSRecordFragmentProtocolsAndReference(t *testing.T) {
	testTLSFragmentProtocolsAndReference(t, false)
}

func testTLSFragmentProtocolsAndReference(t *testing.T, tcp bool) {
	for _, kind := range []string{"socks", "http", "shadowsocks", "vmess", "vless", "trojan", "anytls", "relay", "brook", "snell"} {
		for _, tr := range []string{"", "ws", "http", "grpc"} {
			if (kind == "socks" || kind == "http" || kind == "anytls" || kind == "snell") && tr != "" {
				continue
			}
			if kind == "brook" && tr != "ws" {
				continue
			}
			t.Run(kind+"/"+tr, func(t *testing.T) {
				in := testInbound(t, kind)
				in.TLS = certificate(t)
				if kind == "snell" {
					in.Version, in.Password = "4", "private"
				}
				in.Transport = Transport{Type: tr}
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				o := testOutbound(t, in, s.Address("server"))
				o.Transport = in.Transport
				o.Version = in.Version
				o.TLS = testFragmentTLSOptions(o.TLS, tcp)
				c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
				assertTCP(t, c)
			})
		}
	}
	for _, kind := range []string{"trojan", "vmess", "vless"} {
		t.Run("external/"+kind, func(t *testing.T) {
			in := testInbound(t, kind)
			in.TLS = certificate(t)
			in.ListenPort = unusedPort(t)
			referenceRuntime(t, Config{Inbounds: []Inbound{in}})
			o := testOutbound(t, in, portAddress("127.0.0.1", in.ListenPort))
			o.TLS = testFragmentTLSOptions(o.TLS, tcp)
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{1, 511})
		})
	}
}

func TestTLSRecordFragmentRejectsInvalidConfig(t *testing.T) {
	if _, err := (TLSOptions{RecordFragment: true}).config(false, "example.com"); err == nil {
		t.Fatal("fragment without TLS")
	}
	if _, err := (TLSOptions{Enabled: true, RecordFragment: true}).config(true, ""); err == nil {
		t.Fatal("inbound fragment accepted")
	}
	if err := (TLSOptions{Enabled: true, RecordFragment: true}).validateQUICVersion(); err == nil {
		t.Fatal("QUIC fragment accepted")
	}
}

func TestTLSRecordFragmentPeerAuthentication(t *testing.T) {
	testTLSFragmentPeerAuthentication(t, false)
}

func testTLSFragmentPeerAuthentication(t *testing.T, tcp bool) {
	in := testInbound(t, "trojan")
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := testOutbound(t, in, s.Address("server"))
	o.TLS = testFragmentTLSOptions(o.TLS, tcp)
	o.TLS.Insecure = false
	o.TLS.Certificate = in.TLS.Certificate
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	assertTCP(t, c)
	o.TLS.ServerName = "wrong.example"
	bad := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	if conn, err := bad.Dial(context.Background(), "tcp", relayEchoTCP(t)); err == nil {
		conn.Close()
		t.Fatal("fragment bypassed hostname verification")
	}
}

func TestTLSRecordFragmentCancellation(t *testing.T) { testTLSFragmentCancellation(t, false) }

func testTLSFragmentCancellation(t *testing.T, tcp bool) {
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	c := clientTLS(a, &tls.Config{InsecureSkipVerify: true, ServerName: "cancel.example"}, testFragmentTLSOptions(TLSOptions{}, tcp))
	done := make(chan error, 1)
	go func() { done <- c.HandshakeContext(ctx) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("handshake cancel blocked")
	}
	_ = c.Close()
}

func TestTLSRecordFragmentVersionsAndRetry(t *testing.T) { testTLSFragmentVersionsAndRetry(t, false) }

func testTLSFragmentVersionsAndRetry(t *testing.T, tcp bool) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(strconv.Itoa(int(version)), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			a, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			b, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			a.SetDeadline(time.Now().Add(3 * time.Second))
			b.SetDeadline(time.Now().Add(3 * time.Second))
			server, err := certificate(t).config(true, "")
			if err != nil {
				t.Fatal(err)
			}
			server.MinVersion, server.MaxVersion, server.CurvePreferences = version, version, []tls.CurveID{tls.CurveP256}
			done := make(chan error, 1)
			go func() { done <- tls.Server(b, server).Handshake() }()
			capture := &echCaptureConn{Conn: a}
			cfg := &tls.Config{InsecureSkipVerify: true, ServerName: "retry.example", MinVersion: version, MaxVersion: version, CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}}
			c := clientTLS(capture, cfg, testFragmentTLSOptions(TLSOptions{}, tcp))
			if err = c.Handshake(); err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			capture.mu.Lock()
			wire := append([]byte{}, capture.b.Bytes()...)
			capture.mu.Unlock()
			records, _ := tlsFragmentPayload(t, wire)
			hellos := 0
			plaintext := true
			for _, record := range records {
				if version == tls.VersionTLS12 && record[0] == 20 {
					plaintext = false
				}
				if plaintext && record[0] == 22 && len(record) > 5 && record[5] == 1 {
					hellos++
				}
				if !tcp && bytes.Contains(record, []byte("retry.example")) {
					t.Fatal("retry SNI was not fragmented")
				}
			}
			want := 1
			if version == tls.VersionTLS13 {
				want = 2
			}
			if hellos != want {
				t.Fatal("ClientHello count", hellos, want)
			}
			// Encrypted TLS1.2 Finished can begin with byte1 by chance. It must
			// remain opaque after peer verification, even if it looks like Hello.
			ciphertext := []byte{22, 3, 3, 0, 8, 1, 0, 0, 4, 0, 0, 0, 0}
			capture.mu.Lock()
			capture.b.Reset()
			capture.mu.Unlock()
			if _, err = c.NetConn().Write(ciphertext); err != nil {
				t.Fatal(err)
			}
			capture.mu.Lock()
			actual := append([]byte{}, capture.b.Bytes()...)
			capture.mu.Unlock()
			if !bytes.Equal(actual, ciphertext) {
				t.Fatal("encrypted handshake record was fragmented")
			}
		})
	}
}

func FuzzTLSRecordFragment(f *testing.F) {
	f.Add([]byte{22, 3, 3, 0, 4, 1, 0, 0, 0})
	f.Add([]byte{23, 3, 3, 0, 1, 42})
	f.Fuzz(func(t *testing.T, p []byte) {
		wire, _, err := fragmentTLSRecords(p, 0)
		if err != nil {
			return
		}
		_, before := tlsFragmentPayload(t, p)
		_, after := tlsFragmentPayload(t, wire)
		if !bytes.Equal(before, after) {
			t.Fatal("fragment changed transcript")
		}
	})
}

// Reuse the same TLS application record to make the post-handshake cost visible.
func BenchmarkTLSRecordFragmentData(b *testing.B) {
	c := &tlsRecordFragmentConn{Conn: memoryNetConn{bytes.NewReader(nil), io.Discard}}
	data := make([]byte, 32768)
	data[0] = 23
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	_, _ = c.Write(data)
	for b.Loop() {
		_, _ = c.Write(data)
	}
}

func TestTLSRecordFragmentDNSAndDownloads(t *testing.T) { testTLSFragmentDNSAndDownloads(t, false) }

func testTLSFragmentDNSAndDownloads(t *testing.T, tcp bool) {
	for _, kind := range []string{"tls", "https"} {
		t.Run(kind, func(t *testing.T) {
			var address string
			if kind == "tls" {
				in := Inbound{Type: "dns", Tag: "server", Listen: "127.0.0.1", TLS: certificate(t)}
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"fragment.test": {"192.0.2.7"}}}}}})
				address = s.Address("server")
			} else {
				s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.ProtoMajor != 2 {
						t.Error("DoH lost HTTP2")
					}
					q, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						return
					}
					w.Header().Set("Content-Type", "application/dns-message")
					_, _ = w.Write(dnsAnswer(q))
				}))
				s.EnableHTTP2 = true
				s.StartTLS()
				defer s.Close()
				address = s.Listener.Addr().String()
			}
			host, port, _ := net.SplitHostPort(address)
			n, _ := strconv.ParseUint(port, 10, 16)
			c := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: kind, Tag: "resolver", Server: host, ServerPort: uint16(n), TLS: testFragmentTLSOptions(TLSOptions{Insecure: true}, tcp)}}}})
			ips, err := c.LookupIP(context.Background(), "fragment.test")
			if err != nil || len(ips) == 0 {
				t.Fatal(ips, err)
			}
		})
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Error("rule downloader lost HTTP2")
		}
		_, _ = w.Write([]byte("rules"))
	}))
	s.EnableHTTP2 = true
	s.StartTLS()
	defer s.Close()
	c := newTestRuntime(t, Config{})
	settings := `{"tls":{"record_fragment":true,"insecure":true}}`
	if tcp {
		settings = `{"tls":{"fragment":true,"fragment_fallback_delay":"1ms","insecure":true}}`
	}
	client, transport, err := c.ruleHTTPClient(RuleSet{HTTPClient: clientReference(settings)})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	response, err := client.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || string(data) != "rules" {
		t.Fatal(string(data), err)
	}
}

func TestTLSRecordFragmentECHAndMutualTLS(t *testing.T) { testTLSFragmentECHAndMutualTLS(t, false) }

func testTLSFragmentECHAndMutualTLS(t *testing.T, tcp bool) {
	f := newMutualTLSFixture(t)
	for _, ech := range []bool{false, true} {
		t.Run(strconv.FormatBool(ech), func(t *testing.T) {
			in := testInbound(t, "trojan")
			in.TLS = f.server()
			options := f.client()
			if ech {
				config, key := testECHPair(t)
				in.TLS = testECHServer(t, f, key)
				options = testECHClient(f, config)
			}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			if ech {
				s.serverTLS[in.Tag].VerifyConnection = requireECH
			}
			o := testOutbound(t, in, s.Address("server"))
			o.TLS = options
			o.TLS = testFragmentTLSOptions(o.TLS, tcp)
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			assertTCP(t, c)
		})
	}
}

func testFragmentTLSOptions(o TLSOptions, tcp bool) TLSOptions {
	if tcp {
		o.Fragment = true
		o.FragmentFallbackDelay = "1ms"
	} else {
		o.RecordFragment = true
	}
	return o
}
