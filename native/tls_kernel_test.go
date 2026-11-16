package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

func kernelTLSTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	a, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.Accept()
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	for _, c := range []net.Conn{a, b} {
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(10 * time.Second))
	}
	return a, b
}

func TestTLSRecordHandoff(t *testing.T) {
	f := newMutualTLSFixture(t)
	for _, side := range []string{"client", "server", "both"} {
		t.Run(side, func(t *testing.T) {
			a, b := kernelTLSTCPPair(t)
			cfg, err := f.server().config(true, "")
			if err != nil {
				t.Fatal(err)
			}
			cfg.MinVersion = tls.VersionTLS13
			cfg.NextProtos = []string{"h2"}
			loaded := cfg.Clone()
			cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return loaded, nil }
			client, err := f.client().config(false, "example.com")
			if err != nil {
				t.Fatal(err)
			}
			client.NextProtos = []string{"h2"}
			client.ClientSessionCache = tls.NewLRUClientSessionCache(4)
			type result struct {
				conn tlsConnection
				err  error
			}
			done := make(chan result, 1)
			go func() {
				if side != "client" {
					c, e := handoffTLS(context.Background(), b, cfg, true)
					done <- result{&handoffTestConn{c}, e}
				} else {
					c := tls.Server(b, cfg)
					done <- result{c, c.Handshake()}
				}
			}()
			var c tlsConnection
			if side != "server" {
				var secure *realityConn
				secure, err = handoffTLS(context.Background(), a, client, false)
				c = &handoffTestConn{secure}
			} else {
				c = tls.Client(a, client)
				err = c.Handshake()
			}
			if err != nil {
				t.Fatal(err)
			}
			s := <-done
			if s.err != nil {
				t.Fatal(s.err)
			}
			if handed, ok := s.conn.(*handoffTestConn); ok && handed.tls.clientApp.sequence == 0 {
				t.Fatal("server session ticket was not included in the handoff record count")
			}
			cs, ss := c.ConnectionState(), s.conn.ConnectionState()
			if len(cs.VerifiedChains) == 0 || len(ss.VerifiedChains) == 0 || cs.NegotiatedProtocol != "h2" || ss.NegotiatedProtocol != "h2" {
				t.Fatal("lost mTLS or ALPN state")
			}
			cx, e := cs.ExportKeyingMaterial("EXPORTER-Lanboat-handoff", []byte("context"), 32)
			if e != nil {
				t.Fatal(e)
			}
			sx, e := ss.ExportKeyingMaterial("EXPORTER-Lanboat-handoff", []byte("context"), 32)
			if e != nil || !bytes.Equal(cx, sx) {
				t.Fatal("exporter mismatch", e)
			}
			payload := bytes.Repeat([]byte("TLS1.3 authenticated records\x00"), 40000)
			go func() {
				_, e := s.conn.Write(payload)
				if e == nil {
					e = s.conn.CloseWrite()
				}
				done <- result{err: e}
			}()
			got, e := io.ReadAll(c)
			if e != nil || !bytes.Equal(got, payload) {
				t.Fatalf("read: bytes=%d err=%v", len(got), e)
			}
			if e = (<-done).err; e != nil {
				t.Fatal(e)
			}
			go func() {
				_, e := c.Write(payload)
				if e == nil {
					e = c.CloseWrite()
				}
				done <- result{err: e}
			}()
			got, e = io.ReadAll(s.conn)
			if e != nil || !bytes.Equal(got, payload) {
				t.Fatalf("reverse read: bytes=%d err=%v", len(got), e)
			}
			if e = (<-done).err; e != nil {
				t.Fatal(e)
			}
		})
	}
}

// Exercise handoff without installing kernel keys, including the standard TLS peer.
type handoffTestConn struct{ *realityConn }

func (c *handoffTestConn) Handshake() error                       { return nil }
func (c *handoffTestConn) HandshakeContext(context.Context) error { return nil }

func TestTLSRecordHandoffRejectsPeer(t *testing.T) {
	f := newMutualTLSFixture(t)
	a, b := kernelTLSTCPPair(t)
	cfg, _ := f.server().config(true, "")
	client, _ := f.client().config(false, "wrong.example")
	client.ServerName = "wrong.example"
	done := make(chan error, 1)
	go func() { _, e := handoffTLS(context.Background(), b, cfg, true); done <- e }()
	if _, e := handoffTLS(context.Background(), a, client, false); e == nil {
		t.Fatal("invalid hostname authenticated")
	}
	a.Close()
	if e := <-done; e == nil {
		t.Fatal("peer accepted failed handshake")
	}
}

func TestTLSKernelCancellationAndState(t *testing.T) {
	a, b := kernelTLSTCPPair(t)
	defer b.Close()
	c := &kernelTLSHandshake{Conn: a, config: &tls.Config{ServerName: "example.com"}, options: TLSOptions{KernelTX: true}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 10000 {
			c.ConnectionState()
		}
	})
	if e := c.HandshakeContext(ctx); e == nil {
		t.Fatal("uncancelled handshake")
	}
	wg.Wait()
	if _, e := c.Write([]byte("secret")); e == nil {
		t.Fatal("failed handshake became writable")
	}
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal(ctx.Err())
	}
}

func TestTLSKernelConfiguration(t *testing.T) {
	for _, o := range []TLSOptions{
		{KernelTX: true},
		{KernelRX: true},
		{Enabled: true, KernelTX: true, MaxVersion: "1.2"},
		{Enabled: true, KernelRX: true, MaxVersion: "1.0"},
	} {
		if _, e := o.config(false, "example.com"); e == nil {
			t.Fatal("accepted invalid kernel options", o)
		}
	}
	for _, o := range []TLSOptions{{Enabled: true, KernelTX: true}, {Enabled: true, KernelRX: true}, {Enabled: true, KernelTX: true, KernelRX: true, MinVersion: "1.2"}} {
		cfg, e := o.config(false, "example.com")
		if runtime.GOOS != "linux" {
			if e == nil {
				t.Fatal("non-Linux kernel TLS accepted")
			}
			continue
		}
		if e != nil || cfg.MinVersion != tls.VersionTLS13 {
			t.Fatal(cfg, e)
		}
		if e = o.validateQUICVersion(); e == nil {
			t.Fatal("kernel TLS accepted for QUIC")
		}
		if e = validateVision("vless", visionFlow, o, Transport{}, false, ""); e == nil {
			t.Fatal("Vision bypass accepted kernel TLS")
		}
	}
}

func FuzzTLSHandoffRecord(f *testing.F) {
	f.Add([]byte{22, 3, 3, 0, 4, 2, 0, 0, 0})
	f.Add([]byte{23, 3, 3, 0, 0})
	f.Add([]byte{22, 3, 3, 255, 255})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		c := &tlsHandoffWire{}
		for len(b) > 0 {
			n := min(len(b), 17)
			if e := c.observe(0, b[:n]); e != nil {
				return
			}
			b = b[n:]
		}
	})
}
