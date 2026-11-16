package native

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func ocTLS12Pair(t *testing.T, suite uint16, mutual bool, configure ...func(*tls.Config, *tls.Config)) (*ocTLS12, *ocTLS12) {
	t.Helper()
	f := newMutualTLSFixture(t)
	serverCert, serverKey := f.serverCert, f.serverKey
	if suite == tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 || suite == tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 || suite == tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 {
		o := certificate(t)
		serverCert, serverKey = o.Certificate[0], o.Key[0]
	}
	pair, e := tls.X509KeyPair([]byte(serverCert), []byte(serverKey))
	if e != nil {
		t.Fatal(e)
	}
	root := x509.NewCertPool()
	root.AppendCertsFromPEM([]byte(f.ca))
	root.AppendCertsFromPEM([]byte(serverCert))
	sc := &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, CipherSuites: []uint16{suite}, NextProtos: []string{"http/1.1"}}
	cc := &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, ServerName: "example.com", RootCAs: root, CipherSuites: []uint16{suite}, NextProtos: []string{"http/1.1"}}
	if mutual {
		pair, e = tls.X509KeyPair([]byte(f.clientCert), []byte(f.clientKey))
		if e != nil {
			t.Fatal(e)
		}
		cc.Certificates = []tls.Certificate{pair}
		sc.ClientAuth = tls.RequireAndVerifyClientCert
		sc.ClientCAs = root
	}
	for _, change := range configure {
		change(cc, sc)
	}
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type result struct {
		conn tlsConnection
		err  error
	}
	done := make(chan result, 1)
	go func() { c, e := handshakeOCTLS(ctx, b, sc, TLSOptions{}, true); done <- result{c, e} }()
	c, ce := handshakeOCTLS(ctx, a, cc, TLSOptions{}, false)
	s := <-done
	if ce != nil || s.err != nil {
		t.Fatalf("handoff client=%v server=%v", ce, s.err)
	}
	client, server := c.(*ocTLS12), s.conn.(*ocTLS12)
	client.enabled.Store(true)
	server.enabled.Store(true)
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}
func ocTLS12ReadLoop(c *ocTLS12) <-chan []byte {
	out := make(chan []byte, 256)
	go func() {
		defer close(out)
		b := make([]byte, 16384)
		for {
			n, e := c.Read(b)
			if e != nil {
				return
			}
			out <- bytes.Clone(b[:n])
		}
	}()
	return out
}
func ocTLS12Exchange(t *testing.T, c *ocTLS12, read <-chan []byte) {
	t.Helper()
	payload := []byte("CSTP-in-place-rekey")
	if _, e := c.Write(payload); e != nil {
		t.Fatal(e)
	}
	select {
	case b := <-read:
		if !bytes.Equal(b, payload) {
			t.Fatalf("unexpected application data %q", b)
		}
	case <-time.After(time.Second):
		t.Fatal("application data blocked")
	}
}
func TestOCTLS12Renegotiation(t *testing.T) {
	for _, suite := range ocTLS12Suites {
		t.Run(tls.CipherSuiteName(suite), func(t *testing.T) {
			c, s := ocTLS12Pair(t, suite, false)
			cr, sr := ocTLS12ReadLoop(c), ocTLS12ReadLoop(s)
			previous, e := ocExporter(c)
			if e != nil {
				t.Fatal(e)
			}
			state := c.ConnectionState()
			initial, e := state.ExportKeyingMaterial("EXPORTER-openconnect-psk", nil, 32)
			if e != nil || !bytes.Equal(initial, previous) {
				t.Fatal("initial exporter mismatch", e)
			}
			for round := range 4 {
				before := bytes.Clone(c.clientVerify)
				actor := c
				if round%2 != 0 {
					actor = s
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				e = actor.renegotiate(ctx)
				cancel()
				if e != nil {
					t.Fatal("rekey", round, e)
				}
				ocTLS12Exchange(t, c, sr)
				ocTLS12Exchange(t, s, cr)
				x, e := ocExporter(c)
				if e != nil {
					t.Fatal(e)
				}
				y, e := ocExporter(s)
				if e != nil || !bytes.Equal(x, y) || bytes.Equal(x, previous) || bytes.Equal(before, c.clientVerify) {
					t.Fatal("exporter/Finished did not change consistently", e)
				}
				if c.generation.Load() != uint64(round+1) || s.generation.Load() != uint64(round+1) {
					t.Fatal("generation did not advance")
				}
				previous = x
			}
		})
	}
}
func TestOCTLS12MutualRenegotiation(t *testing.T) {
	c, s := ocTLS12Pair(t, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, true)
	cr, sr := ocTLS12ReadLoop(c), ocTLS12ReadLoop(s)
	for _, actor := range []*ocTLS12{c, s, c, s} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		e := actor.renegotiate(ctx)
		cancel()
		if e != nil {
			t.Fatal(e)
		}
		ocTLS12Exchange(t, c, sr)
		ocTLS12Exchange(t, s, cr)
	}
}

func TestOCTLS12CertificateCallbacksAndCurves(t *testing.T) {
	for _, curve := range []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521} {
		t.Run(fmt.Sprint(curve), func(t *testing.T) {
			var serverCalls, clientCalls atomic.Int32
			c, s := ocTLS12Pair(t, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, true, func(cc, sc *tls.Config) {
				cc.CurvePreferences = []tls.CurveID{curve}
				sc.CurvePreferences = cc.CurvePreferences
				sc.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
					if h.Context() == nil {
						t.Error("initial server callback has no context")
					}
					serverCalls.Add(1)
					return &sc.Certificates[0], nil
				}
				cc.GetClientCertificate = func(h *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					if h.Context() == nil {
						t.Error("initial client callback has no context")
					}
					clientCalls.Add(1)
					return &cc.Certificates[0], nil
				}
			})
			cr, sr := ocTLS12ReadLoop(c), ocTLS12ReadLoop(s)
			for _, actor := range []*ocTLS12{c, s} {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				e := actor.renegotiate(ctx)
				cancel()
				if e != nil {
					t.Fatal(e)
				}
				ocTLS12Exchange(t, c, sr)
				ocTLS12Exchange(t, s, cr)
			}
			if serverCalls.Load() != 1 || clientCalls.Load() != 1 {
				t.Fatal("renegotiation reselected the initial identity", serverCalls.Load(), clientCalls.Load())
			}
		})
	}
}

func TestOCTLS12Signatures(t *testing.T) {
	o := certificate(t)
	rsa, e := tls.X509KeyPair([]byte(o.Certificate[0]), []byte(o.Key[0]))
	if e != nil {
		t.Fatal(e)
	}
	keys := []crypto.Signer{rsa.PrivateKey.(crypto.Signer)}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, e := ecdsa.GenerateKey(curve, rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		keys = append(keys, key)
	}
	_, ed, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	keys = append(keys, ed)
	for i, key := range keys {
		for _, scheme := range ocTLS12Signatures {
			if !ocTLS12SignatureKey(key.Public(), scheme) {
				continue
			}
			t.Run(fmt.Sprintf("%d/%x", i, uint16(scheme)), func(t *testing.T) {
				input := []byte("TLS1.2 transcript and randoms")
				wire, e := ocTLS12Sign(&tls.Certificate{PrivateKey: key}, []tls.SignatureScheme{scheme}, input)
				if e != nil {
					t.Fatal(e)
				}
				p := stCursor{data: wire}
				selected := tls.SignatureScheme(p.number(2))
				sig := p.vector(2)
				if e = p.end(); e != nil || selected != scheme {
					t.Fatal(e)
				}
				if e = ocTLS12Verify(key.Public(), scheme, input, sig); e != nil {
					t.Fatal(e)
				}
				sig[0] ^= 1
				if e = ocTLS12Verify(key.Public(), scheme, input, sig); e == nil {
					t.Fatal("tampered signature accepted")
				}
			})
		}
	}
}

func TestOCTLS12ConcurrentTraffic(t *testing.T) {
	c, s := ocTLS12Pair(t, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, false)
	cr, sr := ocTLS12ReadLoop(c), ocTLS12ReadLoop(s)
	var wg sync.WaitGroup
	for _, actor := range []*ocTLS12{c, s} {
		wg.Add(1)
		go func(c *ocTLS12) {
			defer wg.Done()
			for range 64 {
				if _, e := c.Write(bytes.Repeat([]byte{8}, 1024)); e != nil {
					t.Error(e)
					return
				}
			}
		}(actor)
	}
	for i := range 4 {
		actor := c
		if i%2 != 0 {
			actor = s
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		e := actor.renegotiate(ctx)
		cancel()
		if e != nil {
			t.Fatal(e)
		}
	}
	wg.Wait()
	for _, rx := range []<-chan []byte{cr, sr} {
		for range 64 {
			select {
			case b, ok := <-rx:
				if !ok || len(b) != 1024 || !bytes.Equal(b, bytes.Repeat([]byte{8}, 1024)) {
					t.Fatal("concurrent payload corrupted")
				}
			case <-time.After(time.Second):
				t.Fatal("concurrent payload stalled")
			}
		}
	}
}

type ocTLS12DelayedHeader struct {
	net.Conn
	once atomic.Bool
}

func (c *ocTLS12DelayedHeader) Write(p []byte) (int, error) {
	if len(p) > 3 && !c.once.Swap(true) {
		n, e := c.Conn.Write(p[:3])
		if e != nil {
			return n, e
		}
		time.Sleep(200 * time.Millisecond)
		m, e := c.Conn.Write(p[3:])
		return n + m, e
	}
	return c.Conn.Write(p)
}
func TestOCTLS12ScheduledRekeyPartialRecord(t *testing.T) {
	c, s := ocTLS12Pair(t, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, false)
	s.Conn = &ocTLS12DelayedHeader{Conn: s.Conn}
	c.scheduleRekey(80 * time.Millisecond)
	cr := ocTLS12ReadLoop(c)
	ocTLS12ReadLoop(s)
	done := make(chan error, 1)
	go func() { _, e := s.Write([]byte("delayed-old-record")); done <- e }()
	select {
	case b, ok := <-cr:
		if !ok || string(b) != "delayed-old-record" {
			t.Fatalf("partial record lost %q", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("scheduled rekey stalled")
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	clientKey, ce := ocExporter(c)
	serverKey, se := ocExporter(s)
	if c.generation.Load() == 0 || ce != nil || se != nil || !bytes.Equal(clientKey, serverKey) {
		t.Fatal("timer did not rekey before returning queued application data")
	}
}
func TestOCTLS12RenegotiationBinding(t *testing.T) {
	for _, field := range []string{"client", "server", "ems", "identity", "verification"} {
		t.Run(field, func(t *testing.T) {
			c, s := ocTLS12Pair(t, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, false)
			switch field {
			case "client":
				c.clientVerify[0] ^= 1
			case "server":
				s.serverVerify[0] ^= 1
			case "ems":
				c.ems = false
			case "identity":
				c.state.PeerCertificates = nil
			case "verification":
				c.config.VerifyConnection = func(tls.ConnectionState) error { return fmt.Errorf("verification rejected") }
			}
			ocTLS12ReadLoop(c)
			ocTLS12ReadLoop(s)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if e := c.renegotiate(ctx); e == nil {
				t.Fatal("invalid renegotiation accepted")
			}
			if c.generation.Load() != 0 || s.generation.Load() != 0 {
				t.Fatal("invalid handshake committed")
			}
		})
	}
}
func TestOCTLS12ConcurrentRenegotiation(t *testing.T) {
	c, s := ocTLS12Pair(t, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, false)
	cr, sr := ocTLS12ReadLoop(c), ocTLS12ReadLoop(s)
	for range 10 {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		var wg sync.WaitGroup
		wg.Add(2)
		for _, actor := range []*ocTLS12{c, s} {
			go func(c *ocTLS12) {
				defer wg.Done()
				if e := c.renegotiate(ctx); e != nil {
					t.Error(e)
				}
			}(actor)
		}
		wg.Wait()
		cancel()
		if t.Failed() {
			return
		}
		ocTLS12Exchange(t, c, sr)
		ocTLS12Exchange(t, s, cr)
	}
}
func TestOCTLS12RekeyCancellation(t *testing.T) {
	c, s := ocTLS12Pair(t, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, false)
	_ = s
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := c.renegotiate(ctx); e != context.Canceled {
		t.Fatal(e)
	}
	if c.pending != nil {
		t.Fatal("cancelled call started a handshake")
	}
}

func TestOCTLS12RekeyActiveCancellation(t *testing.T) {
	c, _ := ocTLS12Pair(t, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if e := c.renegotiate(ctx); e != context.DeadlineExceeded && ctx.Err() == nil {
		t.Fatal(e)
	}
	if time.Since(start) > time.Second {
		t.Fatal("blocked write ignored cancellation")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed || c.pending != nil || !bytes.Equal(c.master, make([]byte, 48)) {
		t.Fatal("cancelled handshake retained live secret/state")
	}
}

func TestOCTLS12UnauthenticatedRenegotiation(t *testing.T) {
	c, s := ocTLS12Pair(t, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, false)
	s.enabled.Store(false)
	ocTLS12ReadLoop(c)
	ocTLS12ReadLoop(s)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := c.renegotiate(ctx); e == nil {
		t.Fatal("unauthenticated channel accepted renegotiation")
	}
}

func TestOCTLS12AlertLoggingBoundary(t *testing.T) {
	c, s := ocTLS12Pair(t, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, false)
	done := make(chan error, 1)
	go func() { _, e := c.Read(make([]byte, 1)); done <- e }()
	if e := s.send(21, bytes.Repeat([]byte("private-request-content"), 32)); e != nil {
		t.Fatal(e)
	}
	e := <-done
	if e == nil || e.Error() != "invalid CSTP TLS alert" || strings.Contains(e.Error(), "private-request") {
		t.Fatal("raw alert payload entered the error", e)
	}
}

func TestOCTLS12LegacyCBCUnchanged(t *testing.T) {
	o := certificate(t)
	pair, e := tls.X509KeyPair([]byte(o.Certificate[0]), []byte(o.Key[0]))
	if e != nil {
		t.Fatal(e)
	}
	sc := &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}}
	cc := &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, InsecureSkipVerify: true, CipherSuites: sc.CipherSuites}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		s, e := handshakeOCTLS(ctx, b, sc, TLSOptions{}, true)
		if e == nil {
			if _, ok := s.(*tls.Conn); !ok {
				e = fmt.Errorf("legacy TLS bypass missing")
			}
		}
		if e == nil {
			_, e = s.Write([]byte("CBC-preserved"))
		}
		done <- e
	}()
	c, e := handshakeOCTLS(ctx, a, cc, TLSOptions{}, false)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := c.(*tls.Conn); !ok {
		t.Fatal("legacy TLS was replaced")
	}
	data := make([]byte, len("CBC-preserved"))
	if _, e = io.ReadFull(c, data); e != nil || string(data) != "CBC-preserved" {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

type ocTLS12ChunkConn struct{ net.Conn }

func (c ocTLS12ChunkConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, e := c.Conn.Write(p[:min(7, len(p))])
		total += n
		p = p[n:]
		if e != nil {
			return total, e
		}
	}
	return total, nil
}
func TestOCTLS12FragmentedRenegotiation(t *testing.T) {
	c, s := ocTLS12Pair(t, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, true)
	c.Conn = ocTLS12ChunkConn{c.Conn}
	s.Conn = ocTLS12ChunkConn{s.Conn}
	cr, sr := ocTLS12ReadLoop(c), ocTLS12ReadLoop(s)
	for _, actor := range []*ocTLS12{c, s} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		e := actor.renegotiate(ctx)
		cancel()
		if e != nil {
			t.Fatal(e)
		}
		ocTLS12Exchange(t, c, sr)
		ocTLS12Exchange(t, s, cr)
	}
}

func TestOCTLS12RecordBoundaries(t *testing.T) {
	for _, suite := range ocTLS12Suites {
		t.Run(tls.CipherSuiteName(suite), func(t *testing.T) {
			keys, e := ocTLS12Keys(suite, bytes.Repeat([]byte{3}, 48), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32))
			if e != nil {
				t.Fatal(e)
			}
			for _, size := range []int{0, 1, 16384} {
				sender, receiver := *keys[0], *keys[0]
				wire, e := sender.seal(23, bytes.Repeat([]byte{7}, size))
				if e != nil {
					t.Fatal(e)
				}
				plain, e := receiver.open(wire)
				if e != nil || len(plain) != size {
					t.Fatal(size, e)
				}
				if _, e = receiver.open(wire); e == nil {
					t.Fatal("replayed record accepted")
				}
			}
			if _, e = keys[0].seal(23, make([]byte, 16385)); e == nil {
				t.Fatal("oversized record accepted")
			}
			keys[0].sequence = ^uint64(0)
			if _, e = keys[0].seal(23, nil); e == nil {
				t.Fatal("sequence exhaustion accepted")
			}
		})
	}
}

func TestOpenConnectCSTPRekeyConfig(t *testing.T) {
	in := Inbound{Type: "openconnect", Tag: "server", Listen: "127.0.0.1", Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t)}
	for _, o := range []OpenConnectOptions{{RekeyMethod: "ssl"}, {RekeyMethod: "bad", RekeyTime: "1s"}, {RekeyMethod: "ssl", RekeyTime: "1s"}} {
		in.OpenConnectOptions = o
		data, _ := json.Marshal(Config{Inbounds: []Inbound{in}})
		if _, e := Parse(data); e == nil {
			t.Fatal("invalid rekey policy accepted", o)
		}
	}
	in.TLS.MaxVersion = "1.2"
	in.OpenConnectOptions = OpenConnectOptions{RekeyMethod: "ssl", RekeyTime: "1s"}
	data, _ := json.Marshal(Config{Inbounds: []Inbound{in}})
	if _, e := Parse(data); e != nil {
		t.Fatal(e)
	}
	in.Type = "socks"
	data, _ = json.Marshal(Config{Inbounds: []Inbound{in}})
	if _, e := Parse(data); e == nil {
		t.Fatal("CSTP policy accepted on SOCKS")
	}
	o := Outbound{Type: "openconnect", Tag: "proxy", Server: "localhost", ServerPort: 443, TLS: TLSOptions{Enabled: true, MaxVersion: "1.2"}, OpenConnectOptions: in.OpenConnectOptions}
	data, _ = json.Marshal(Config{Outbounds: []Outbound{o}})
	if _, e := Parse(data); e == nil {
		t.Fatal("inbound rekey policy accepted on outbound")
	}
}

func FuzzOCTLS12Hello(f *testing.F) {
	f.Add([]byte{3, 3}, true)
	f.Add(append(make([]byte, 40), 0, 0), false)
	f.Fuzz(func(t *testing.T, body []byte, client bool) {
		if len(body) > 65535 {
			return
		}
		ocTLS12ParseHello(body, client)
		ocTLS12Certificates(body)
		ocTLS12Request(body)
	})
}

func FuzzOCTLS12Record(f *testing.F) {
	for _, suite := range ocTLS12Suites {
		keys, e := ocTLS12Keys(suite, bytes.Repeat([]byte{3}, 48), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32))
		if e != nil {
			f.Fatal(e)
		}
		wire, e := keys[0].seal(23, []byte("seed"))
		if e != nil {
			f.Fatal(e)
		}
		f.Add(suite, wire)
	}
	f.Fuzz(func(t *testing.T, suite uint16, wire []byte) {
		if len(wire) > 18437 {
			return
		}
		keys, e := ocTLS12Keys(suite, bytes.Repeat([]byte{3}, 48), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32))
		if e != nil {
			return
		}
		keys[0].open(wire)
	})
}
func TestOpenConnectCSTPSSLRekey(t *testing.T) {
	for _, dtls := range []bool{false, true} {
		t.Run(fmt.Sprint(dtls), func(t *testing.T) {
			in := Inbound{Type: "openconnect", Tag: "server", Listen: "127.0.0.1", Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t), OpenConnectOptions: OpenConnectOptions{DisableDTLS: !dtls, RekeyTime: "1s", RekeyMethod: "ssl"}}
			in.TLS.MaxVersion = "1.2"
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			o := testOutbound(t, in, s.Address("server"))
			o.Type = "openconnect"
			o.Username, o.Password = "client", "private"
			o.OpenConnectOptions = OpenConnectOptions{DisableDTLS: !dtls}
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			tunnel, e := c.ocClients[o.Tag].session(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			var d *ocDTLS
			if dtls {
				d = ocWaitDTLS(t, tunnel)
			}
			conn, e := c.Dial(context.Background(), "tcp", masqueEcho(t, "tcp", "127.0.0.1:0"))
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			tlsConn := tunnel.conn.(*bufferedConn).Conn.(*ocTLS12)
			for round := uint64(1); round <= 3; round++ {
				deadline := time.Now().Add(3 * time.Second)
				for tlsConn.generation.Load() < round && time.Now().Before(deadline) {
					time.Sleep(10 * time.Millisecond)
				}
				if tlsConn.generation.Load() < round {
					t.Fatal("periodic rekey did not complete")
				}
				payload := bytes.Repeat([]byte("persistent-CSTP"), 100)
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if e = writeAll(conn, payload); e != nil {
					t.Fatal(e)
				}
				got := make([]byte, len(payload))
				if _, e = io.ReadFull(conn, got); e != nil || !bytes.Equal(got, payload) {
					t.Fatal("persistent TCP", e)
				}
				assertUDPSizes(t, c, []int{1, 4096})
				if c.ocClients[o.Tag].tunnel.Load() != tunnel {
					t.Fatal("CSTP tunnel replaced")
				}
				if dtls && ocWaitDTLS(t, tunnel) != d {
					t.Fatal("DTLS replaced")
				}
				if dtls && round == 1 {
					d.conn.Close()
					deadline := time.Now().Add(5 * time.Second)
					for time.Now().Before(deadline) {
						tunnel.dtlsMu.Lock()
						next := tunnel.dtls
						tunnel.dtlsMu.Unlock()
						if next != d && next.ready.Load() {
							d = next
							break
						}
						time.Sleep(10 * time.Millisecond)
					}
					if !d.ready.Load() {
						t.Fatal("DTLS could not renew using the new CSTP exporter")
					}
					assertUDPSizes(t, c, []int{1, 4096})
				}
			}
			if _, e = io.WriteString(conn, "still-connected"); e != nil {
				t.Fatal(e)
			}
		})
	}
}

type ocTLS12CountingReader struct {
	io.Reader
	calls int
}

func (r *ocTLS12CountingReader) Read(p []byte) (int, error) { r.calls++; return r.Reader.Read(p) }
func TestOCTLS12BufferedRecords(t *testing.T) {
	for _, suite := range ocTLS12Suites {
		t.Run(tls.CipherSuiteName(suite), func(t *testing.T) {
			keys, e := ocTLS12Keys(suite, bytes.Repeat([]byte{3}, 48), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32))
			if e != nil {
				t.Fatal(e)
			}
			var wire bytes.Buffer
			for i := range 16 {
				b, e := keys[0].seal(23, bytes.Repeat([]byte{byte(i)}, 700))
				if e != nil {
					t.Fatal(e)
				}
				wire.Write(b)
			}
			keys, e = ocTLS12Keys(suite, bytes.Repeat([]byte{3}, 48), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32))
			if e != nil {
				t.Fatal(e)
			}
			reader := &ocTLS12CountingReader{Reader: bytes.NewReader(wire.Bytes())}
			c := &ocTLS12{Conn: memoryNetConn{reader, &bytes.Buffer{}}, readKey: keys[0]}
			for i := range 16 {
				kind, p, e := c.record()
				if e != nil || kind != 23 || !bytes.Equal(p, bytes.Repeat([]byte{byte(i)}, 700)) {
					t.Fatal(kind, len(p), e)
				}
			}
			if reader.calls != 1 {
				t.Fatal("coalesced records required extra reads", reader.calls)
			}
		})
	}
}
