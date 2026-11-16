package native

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func cloakTestInbound(t *testing.T, mode, method string) (Inbound, string) {
	t.Helper()
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	uid := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))
	in := testInbound(t, "shadowsocks")
	in.Plugin = "cloak"
	in.PluginOpts = "UID=" + uid + ";PrivateKey=" + base64.StdEncoding.EncodeToString(key.Bytes()) + ";ProxyMethod=shadowsocks;Transport=" + mode + ";EncryptionMethod=" + method + ";NumConn=4;StreamTimeout=300"
	if mode != "direct" {
		in.TLS = certificate(t)
	}
	client := "UID=" + uid + ";PublicKey=" + base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()) + ";ProxyMethod=shadowsocks;Transport=" + mode + ";EncryptionMethod=" + method + ";ServerName=example.com;NumConn=4"
	return in, client
}
func cloakTestOutbound(t *testing.T, in Inbound, address, options string) Outbound {
	t.Helper()
	o := testOutbound(t, in, address)
	o.Plugin, o.PluginOpts = "cloak", options
	if in.TLS.Enabled {
		o.TLS = TLSOptions{Enabled: true, ServerName: "example.com", Certificate: in.TLS.Certificate}
	}
	return o
}
func TestCloakIndependent(t *testing.T) {
	for _, mode := range []string{"direct", "cdn", "websocket"} {
		for _, method := range []string{"plain", "aes-gcm", "aes-128-gcm", "chacha20-poly1305"} {
			t.Run(mode+"/"+method, func(t *testing.T) {
				in, options := cloakTestInbound(t, mode, method)
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				o := cloakTestOutbound(t, in, s.Address(in.Tag), options)
				c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
				assertTCP(t, c)
				assertTCP(t, c)
				kcpLargeTransfer(t, c, 600000)
				if conn, e := c.Dial(context.Background(), "udp", echoUDP(t)); e == nil {
					conn.Close()
					t.Fatal("plugin exposed a bypass UDP path")
				}
				c.resetNetworkTransports()
				assertTCP(t, c)
				for _, cfg := range []Config{s.config, c.config} {
					b, _ := json.Marshal(cfg)
					if _, e := Parse(b); e != nil {
						t.Fatal(e)
					}
				}
				c.Close()
				s.Close()
				if c.cloakBudget.Load() != 0 || s.cloakBudget.Load() != 0 {
					t.Fatal("Cloak memory accounting leaked", c.cloakBudget.Load(), s.cloakBudget.Load())
				}
			})
		}
	}
}
func TestCloakWireRoundTrip(t *testing.T) {
	for method := range byte(4) {
		t.Run(strconv.Itoa(int(method)), func(t *testing.T) {
			var key [32]byte
			rand.Read(key[:])
			codec, e := newCloakCodec(key, method)
			if e != nil {
				t.Fatal(e)
			}
			for _, n := range []int{1, 16, 128, 16000} {
				for seq := range uint64(8) {
					want := bytes.Repeat([]byte{byte(seq)}, n)
					frame := codec.seal(cloakFrame{id: 13, seq: seq, body: want})
					f, e := codec.open(append([]byte(nil), frame...))
					if e != nil || f.id != 13 || f.seq != seq || !bytes.Equal(f.body, want) {
						t.Fatal("frame mismatch", n, seq, e)
					}
					if method != 0 {
						frame[len(frame)-1] ^= 1
						if _, e = codec.open(frame); e == nil {
							t.Fatal("modified frame accepted")
						}
					}
				}
			}
		})
	}
}
func TestCloakBrowserLayouts(t *testing.T) {
	in, options := cloakTestInbound(t, "direct", "chacha20-poly1305")
	p := SIP003Options{Plugin: "cloak", PluginOpts: options}
	if e := p.prepare("shadowsocks", Transport{}, TLSOptions{}, false); e != nil {
		t.Fatal(e)
	}
	public, encrypted, _, e := p.plugin.cloak.auth(7)
	if e != nil {
		t.Fatal(e)
	}
	var last []byte
	for _, browser := range []string{"chrome", "firefox", "safari"} {
		b := cloakClientHello(browser, "example.com", public, encrypted)
		if len(b) != 517 {
			t.Fatal("hello padding", len(b))
		}
		if bytes.Equal(last, b) {
			t.Fatal("browser layout unchanged")
		}
		last = b
		random, session, share, e := cloakHelloFields(b[5:], false)
		if e != nil || !bytes.Equal(random, public) || !bytes.Equal(append(append([]byte(nil), session...), share...), encrypted) {
			t.Fatal("hello fields", e)
		}
		if name, _, ok := clientHelloSNI(b[5:]); !ok || name != "example.com" {
			t.Fatal("SNI", name, ok)
		}
	}
	_ = in
}
func TestCloakConcurrentAndClose(t *testing.T) {
	in, options := cloakTestInbound(t, "direct", "aes-gcm")
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := cloakTestOutbound(t, in, s.Address(in.Tag), options)
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	var work sync.WaitGroup
	for range 12 {
		work.Go(func() { kcpLargeTransfer(t, c, 400000) })
	}
	work.Wait()
	c.Close()
	s.Close()
	if c.cloakBudget.Load() != 0 || s.cloakBudget.Load() != 0 {
		t.Fatal("close leaked budget")
	}
}
func TestCloakRejectCredentials(t *testing.T) {
	for _, mode := range []string{"UID", "PublicKey", "ProxyMethod", "tls-name", "tls-ca", "detour"} {
		t.Run(mode, func(t *testing.T) {
			transport := "direct"
			if strings.HasPrefix(mode, "tls-") {
				transport = "websocket"
			}
			in, options := cloakTestInbound(t, transport, "aes-gcm")
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			o := cloakTestOutbound(t, in, s.Address(in.Tag), options)
			switch mode {
			case "UID":
				o.PluginOpts = strings.Replace(o.PluginOpts, "UID="+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16)), "UID="+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 16)), 1)
			case "PublicKey":
				key, _ := ecdh.X25519().GenerateKey(rand.Reader)
				start := strings.Index(o.PluginOpts, "PublicKey=") + len("PublicKey=")
				end := strings.Index(o.PluginOpts[start:], ";") + start
				o.PluginOpts = o.PluginOpts[:start] + base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()) + o.PluginOpts[end:]
			case "ProxyMethod":
				o.PluginOpts = strings.Replace(o.PluginOpts, "ProxyMethod=shadowsocks", "ProxyMethod=wrong", 1)
			case "tls-name":
				o.PluginOpts += ";sni=wrong.test"
			case "tls-ca":
				o.TLS.Certificate = nil
			case "detour":
				o.Detour = "deny"
			}
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o, {Type: "block", Tag: "deny"}}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, e := c.Dial(ctx, "tcp", relayEchoTCP(t))
			if e == nil {
				conn.Close()
				t.Fatal("invalid cloak credentials accepted")
			}
		})
	}
}
func TestCloakOptions(t *testing.T) {
	in, valid := cloakTestInbound(t, "direct", "aes-gcm")
	_ = in
	for _, suffix := range []string{";UID=invalid", ";EncryptionMethod=invalid", ";NumConn=0", ";NumConn=9", ";StreamTimeout=-1", ";StreamTimeout=86401", ";BrowserSig=unknown", ";Transport=unknown", ";ProxyMethod=longer-than-twelve", ";ServerName=bad host", ";AlternativeNames=bad host", ";path=no-prefix", ";server=bad host", ";port=0", ";skip-cert-verify=invalid", ";unknown=yes"} {
		values, _ := sip003Options(valid)
		name, value, _ := strings.Cut(strings.TrimPrefix(suffix, ";"), "=")
		values[name] = value
		parts := make([]string, 0, len(values))
		for k, v := range values {
			parts = append(parts, k+"="+v)
		}
		p := SIP003Options{Plugin: "cloak", PluginOpts: strings.Join(parts, ";")}
		if p.prepare("shadowsocks", Transport{}, TLSOptions{}, false) == nil {
			t.Fatal("invalid options accepted", suffix)
		}
	}
}

func TestCloakIdleStreamIsolation(t *testing.T) {
	in, options := cloakTestInbound(t, "direct", "aes-gcm")
	options += ";StreamTimeout=1"
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := cloakTestOutbound(t, in, s.Address(in.Tag), options)
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	target := relayEchoTCP(t)
	idle, e := c.Dial(context.Background(), "tcp", target)
	if e != nil {
		t.Fatal(e)
	}
	defer idle.Close()
	active, e := c.Dial(context.Background(), "tcp", target)
	if e != nil {
		t.Fatal(e)
	}
	defer active.Close()
	active.SetDeadline(time.Now().Add(4 * time.Second))
	for range 12 {
		if e = writeAll(active, []byte("ok")); e != nil {
			t.Fatal(e)
		}
		var b [2]byte
		if _, e = io.ReadFull(active, b[:]); e != nil || string(b[:]) != "ok" {
			t.Fatal(e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	idle.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, e = idle.Read(make([]byte, 1)); e == nil || os.IsTimeout(e) {
		t.Fatal("idle stream not reclaimed", e)
	}
	if e = writeAll(active, []byte("ok")); e != nil {
		t.Fatal("active stream affected", e)
	}
}
func TestCloakReplayAndExpiredAuthentication(t *testing.T) {
	in, options := cloakTestInbound(t, "direct", "chacha20-poly1305")
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	p := SIP003Options{Plugin: "cloak", PluginOpts: options}
	if e := p.prepare("shadowsocks", Transport{}, TLSOptions{}, false); e != nil {
		t.Fatal(e)
	}
	public, encrypted, shared, e := p.plugin.cloak.auth(42)
	if e != nil {
		t.Fatal(e)
	}
	wire := cloakClientHello("chrome", "example.com", public, encrypted)
	first, e := net.Dial("tcp", s.Address(in.Tag))
	if e != nil {
		t.Fatal(e)
	}
	first.SetDeadline(time.Now().Add(time.Second))
	if e = writeAll(first, wire); e != nil {
		t.Fatal(e)
	}
	if _, e = cloakDirectReply(first, encrypted[:32], shared); e != nil {
		t.Fatal(e)
	}
	first.Close()
	second, e := net.Dial("tcp", s.Address(in.Tag))
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	second.SetDeadline(time.Now().Add(time.Second))
	writeAll(second, wire)
	if _, e = cloakDirectReply(second, encrypted[:32], shared); e == nil {
		t.Fatal("authentication replay accepted")
	}
	server := s.config.Inbounds[0].plugin.cloak
	plain, e := cloakGCM(shared).Open(nil, public[:12], encrypted, nil)
	if e != nil {
		t.Fatal(e)
	}
	binary.BigEndian.PutUint64(plain[29:], uint64(time.Now().Add(-4*time.Minute).Unix()))
	expired := cloakGCM(shared).Seal(nil, public[:12], plain, nil)
	if _, e = server.authenticate(public, expired); e == nil {
		t.Fatal("expired timestamp accepted")
	}
	plain[41] = 1
	binary.BigEndian.PutUint64(plain[29:], uint64(time.Now().Unix()))
	if _, e = server.authenticate(public, cloakGCM(shared).Seal(nil, public[:12], plain, nil)); e == nil {
		t.Fatal("unsupported UDP mode accepted")
	}
}
func TestCloakFallbackTLS(t *testing.T) {
	cover := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("cover-site")) }))
	defer cover.Close()
	in, _ := cloakTestInbound(t, "direct", "aes-gcm")
	in.PluginOpts += ";RedirAddr=" + strings.TrimPrefix(cover.URL, "https://")
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	pool := x509.NewCertPool()
	pool.AddCert(cover.Certificate())
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, s.Address(in.Tag))
	}}}
	defer client.CloseIdleConnections()
	response, e := client.Get("https://example.com/")
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	body, e := io.ReadAll(response.Body)
	if e != nil || string(body) != "cover-site" {
		t.Fatal(string(body), e)
	}
}
func TestCloakConnectionLossAndPoolRecovery(t *testing.T) {
	in, options := cloakTestInbound(t, "direct", "aes-gcm")
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := cloakTestOutbound(t, in, s.Address(in.Tag), options)
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	assertTCP(t, c)
	p := c.cloakClients[o.Tag]
	p.mu.Lock()
	old := p.session
	transport := old.conn.(*cloakMuxConn)
	transport.mu.Lock()
	link := transport.links[0]
	transport.mu.Unlock()
	p.mu.Unlock()
	link.Close()
	select {
	case <-old.done:
	case <-time.After(2 * time.Second):
		t.Fatal("broken link did not close the session")
	}
	assertTCP(t, c)
}
func TestCloakConnectionCounts(t *testing.T) {
	for _, n := range []int{1, 8} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			in, options := cloakTestInbound(t, "direct", "aes-gcm")
			options = strings.Replace(options, "NumConn=4", "NumConn="+strconv.Itoa(n), 1)
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			o := cloakTestOutbound(t, in, s.Address(in.Tag), options)
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			assertTCP(t, c)
			p := c.cloakClients[o.Tag]
			p.mu.Lock()
			transport := p.session.conn.(*cloakMuxConn)
			transport.mu.Lock()
			count := len(transport.links)
			transport.mu.Unlock()
			p.mu.Unlock()
			if count != n {
				t.Fatal("wrong link count", count)
			}
		})
	}
}
func FuzzCloakFrames(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0})
	f.Add(make([]byte, 22))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > cloakWireLimit {
			return
		}
		for method := range byte(4) {
			codec, _ := newCloakCodec([32]byte{}, method)
			codec.open(append([]byte(nil), b...))
		}
		cloakHelloFields(b, false)
		cloakHelloFields(b, true)
		link := &cloakLink{Conn: readerConn(b)}
		link.readFrame()
	})
}

func TestCloakReorderingAndLimits(t *testing.T) {
	r := newTestRuntime(t, Config{})
	a, b := net.Pipe()
	defer b.Close()
	transport, e := newCloakMux(r, [32]byte{}, 1, []*cloakLink{{Conn: a}})
	if e != nil {
		t.Fatal(e)
	}
	defer transport.Close()
	codec := transport.codec
	accept := func(id uint32, seq uint64, body string, closing byte) error {
		f, e := codec.open(codec.seal(cloakFrame{id: id, seq: seq, body: []byte(body), close: closing}))
		if e != nil {
			return e
		}
		f.charge = len(body) + 30
		if !transport.reserve(f.charge) {
			return errors.New("reserve failed")
		}
		return transport.consume(f)
	}
	if e = accept(2, 1, "second", 0); e != nil {
		t.Fatal(e)
	}
	if len(transport.current) != 0 {
		t.Fatal("out-of-order frame emitted")
	}
	if e = accept(2, 0, "first", 0); e != nil {
		t.Fatal(e)
	}
	got := transport.current
	want := cloakSMUXFrame(nil, 0, 2, nil)
	want = cloakSMUXFrame(want, 2, 2, []byte("first"))
	want = cloakSMUXFrame(want, 2, 2, []byte("second"))
	if !bytes.Equal(got, want) {
		t.Fatal("incorrect reassembly")
	}
	transport.release(transport.currentCharge)
	transport.currentCharge = 0
	transport.current = nil
	if e = accept(2, 1, "duplicate", 0); e != nil {
		t.Fatal(e)
	}
	if len(transport.current) != 0 {
		t.Fatal("duplicate emitted")
	}
	if e = accept(2, 3, "close", 1); e != nil {
		t.Fatal(e)
	}
	if e = accept(2, 2, "third", 0); e != nil {
		t.Fatal(e)
	}
	transport.release(transport.currentCharge)
	transport.currentCharge = 0
	transport.current = nil
	if e = accept(2, 0, "old stream replay", 0); e != nil {
		t.Fatal(e)
	}
	if len(transport.states) != 0 {
		t.Fatal("closed stream recreated")
	}
	if e = accept(5, 300, "too far", 0); e == nil {
		t.Fatal("unbounded reordering allowed")
	}
	transport.Close()
	if r.cloakBudget.Load() != 0 {
		t.Fatal("reassembly budget leaked", r.cloakBudget.Load())
	}
	r.cloakBudget.Store(16 << 20)
	if transport.reserve(1) {
		t.Fatal("runtime receive budget exceeded")
	}
	r.cloakBudget.Store(0)
}
func TestCloakServerSessionLimits(t *testing.T) {
	in, options := cloakTestInbound(t, "direct", "aes-gcm")
	_ = options
	r := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	server := r.cloakServers[in.Tag]
	for i := range uint32(32) {
		g, e := server.get(r.config.Inbounds[0], cloakIdentity{id: i, method: 1})
		if e != nil {
			t.Fatal(e)
		}
		if i == 0 {
			for range 7 {
				if _, e = server.get(r.config.Inbounds[0], cloakIdentity{id: i, method: 1}); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = server.get(r.config.Inbounds[0], cloakIdentity{id: i, method: 1}); e == nil {
				t.Fatal("connection admission unbounded")
			}
		}
		if g.session != nil {
			t.Fatal("unattached session started a data stream")
		}
	}
	if _, e := server.get(r.config.Inbounds[0], cloakIdentity{id: 33, method: 1}); e == nil {
		t.Fatal("session registry unbounded")
	}
	server.reset()
	if len(server.sessions) != 0 || r.cloakBudget.Load() != 0 {
		t.Fatal("unattached sessions not reclaimed")
	}
}

func TestCloakRecordBoundsAndEOFDrain(t *testing.T) {
	for _, header := range [][]byte{{23, 3, 3, 0x45, 0}, {23, 3, 3, 0, 1}, {22, 3, 3, 0, 22}} {
		link := &cloakLink{Conn: readerConn(header)}
		if _, e := link.readFrame(); e == nil {
			t.Fatal("invalid record accepted")
		}
	}
	maxCodec, _ := newCloakCodec([32]byte{}, 1)
	maxFrame := maxCodec.seal(cloakFrame{id: 7, seq: 10, body: make([]byte, cloakWireLimit-30)})
	if len(maxFrame) != cloakWireLimit {
		t.Fatal("maximum frame fixture", len(maxFrame))
	}
	link := &cloakLink{Conn: readerConn(shadowFrame(23, maxFrame))}
	record, err := link.readFrame()
	if err != nil || len(record) != cloakWireLimit {
		t.Fatal("upstream maximum record rejected", err)
	}
	if _, err = maxCodec.open(record); err != nil {
		t.Fatal("maximum encrypted record rejected", err)
	}
	r := newTestRuntime(t, Config{})
	a, b := net.Pipe()
	transport, e := newCloakMux(r, [32]byte{}, 1, []*cloakLink{{Conn: a}})
	if e != nil {
		t.Fatal(e)
	}
	defer transport.Close()
	codec := transport.codec
	go func() {
		writeAll(b, shadowFrame(23, codec.seal(cloakFrame{id: 1, seq: 0, body: []byte("last data")})))
		b.Close()
	}()
	transport.workers.Wait()
	want := cloakSMUXFrame(nil, 0, 1, nil)
	want = cloakSMUXFrame(want, 2, 1, []byte("last data"))
	got, e := io.ReadAll(transport)
	if e != nil || !bytes.Equal(got, want) {
		t.Fatal("EOF discarded queued data", len(got), e)
	}
	transport.Close()
	if r.cloakBudget.Load() != 0 {
		t.Fatal("EOF budget leaked")
	}
}

func TestCloakEndpointOverrideAndBrowser(t *testing.T) {
	in, options := cloakTestInbound(t, "direct", "aes-gcm")
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := cloakTestOutbound(t, in, s.Address(in.Tag), options)
	_, port, _ := net.SplitHostPort(s.Address(in.Tag))
	o.Server, o.ServerPort = "unused.invalid", 1
	o.PluginOpts += ";server=127.0.0.1;port=" + port + ";BrowserSig=firefox;AlternativeNames=first.example,second.example"
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	assertTCP(t, c)
}
func TestCloakConcurrentShutdown(t *testing.T) {
	for range 8 {
		in, options := cloakTestInbound(t, "direct", "aes-gcm")
		s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
		o := cloakTestOutbound(t, in, s.Address(in.Tag), options)
		c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
		assertTCP(t, c)
		target := relayEchoTCP(t)
		var work sync.WaitGroup
		for range 16 {
			work.Go(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
				defer cancel()
				conn, e := c.Dial(ctx, "tcp", target)
				if e == nil {
					conn.Close()
				}
			})
		}
		c.Close()
		work.Wait()
		s.Close()
		if c.cloakBudget.Load() != 0 || s.cloakBudget.Load() != 0 {
			t.Fatal("concurrent shutdown leaked receive buffers")
		}
	}
}

func TestCloakIPv6SS2022AndMutualTLS(t *testing.T) {
	for _, variant := range []string{"ipv6", "ss2022", "mutual"} {
		t.Run(variant, func(t *testing.T) {
			mode := "direct"
			if variant == "mutual" {
				mode = "websocket"
			}
			in, options := cloakTestInbound(t, mode, "chacha20-poly1305")
			if variant == "ipv6" {
				in.Listen = "::1"
			}
			if variant == "ss2022" {
				in.Method = "2022-blake3-aes-128-gcm"
				in.Password = "BwcHBwcHBwcHBwcHBwcHBw=="
			}
			var mutual mutualTLSFixture
			if variant == "mutual" {
				mutual = newMutualTLSFixture(t)
				in.TLS = mutual.server()
			}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			o := cloakTestOutbound(t, in, s.Address(in.Tag), options)
			o.Password = in.Password
			if variant == "mutual" {
				o.TLS = mutual.client()
			}
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			assertTCP(t, c)
			kcpLargeTransfer(t, c, 300000)
		})
	}
}

func TestCloakWebSocketECH(t *testing.T) {
	fixture := newMutualTLSFixture(t)
	config, key := testECHPair(t)
	for _, dynamic := range []bool{false, true} {
		t.Run(strconv.FormatBool(dynamic), func(t *testing.T) {
			in, options := cloakTestInbound(t, "websocket", "aes-gcm")
			in.TLS = testECHServer(t, fixture, key)
			s := newECHRuntime(t, Config{Inbounds: []Inbound{in}}, in.Tag)
			o := cloakTestOutbound(t, in, s.Address(in.Tag), options)
			o.TLS = testECHClient(fixture, config)
			dns := DNSConfig{}
			if dynamic {
				o.TLS.ECH.Config = nil
				o.TLS.ECH.QueryServerName = "ech.test"
				dns = echDNSConfig(config, "ech.test")
			}
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o}, DNS: dns})
			assertTCP(t, c)
		})
	}
}

func TestCloakCloseDoesNotWaitForTLSNotify(t *testing.T) {
	a, b := net.Pipe()
	serverConfig, e := certificate(t).config(true, "")
	if e != nil {
		t.Fatal(e)
	}
	serverConfig.SessionTicketsDisabled = true
	server := tls.Server(b, serverConfig)
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- server.Handshake() }()
	client := tls.Client(a, &tls.Config{InsecureSkipVerify: true})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if e = client.HandshakeContext(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	r := newTestRuntime(t, Config{})
	transport, e := newCloakMux(r, [32]byte{}, 1, []*cloakLink{{Conn: client}})
	if e != nil {
		t.Fatal(e)
	}
	closed := make(chan struct{})
	go func() { transport.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		a.Close()
		t.Fatal("close waited for a peer that does not read TLS close_notify")
	}
}
