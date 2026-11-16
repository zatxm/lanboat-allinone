package native

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func naivePair(t *testing.T, quic bool) (*Runtime, *Runtime) {
	t.Helper()
	in := Inbound{Type: "naive", Tag: "server", Listen: "127.0.0.1", Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t)}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, server.Address(in.Tag))
	out.QUIC, out.UDPOverTCP = quic, true
	return server, newTestRuntime(t, Config{Outbounds: []Outbound{out}})
}

func TestNaiveIndependent(t *testing.T) {
	for _, quic := range []bool{false, true} {
		t.Run(fmt.Sprint("quic=", quic), func(t *testing.T) {
			_, client := naivePair(t, quic)
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{0, 1, 511, 4096, 60000, 65507})
			client.resetNetworkTransports()
			assertTCP(t, client)
		})
	}
}

func TestNaivePaddingRecords(t *testing.T) {
	for _, size := range []int{0, 1, 65535, 65536, 180000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			var wire bytes.Buffer
			writer := &naiveConn{Conn: &memoryNetConn{Reader: bytes.NewReader(nil), Writer: &wire}}
			var want []byte
			for i := range 12 {
				p := bytes.Repeat([]byte{byte(i)}, size)
				if n, e := writer.Write(p); e != nil || n != len(p) {
					t.Fatal(n, e)
				}
				want = append(want, p...)
			}
			reader := &naiveConn{Conn: &memoryNetConn{Reader: bytes.NewReader(wire.Bytes()), Writer: io.Discard}}
			var got bytes.Buffer
			if _, e := io.CopyBuffer(&got, reader, make([]byte, 137)); e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(got.Bytes(), want) {
				t.Fatal("padding or eighth-record boundary leaked into payload")
			}
		})
	}
	// Empty padded records are legal. Padding is opaque, and can arrive split
	// from the data by the HTTP transport.
	var wire []byte
	for i := range 8 {
		wire = append(wire, 0, 0, byte(i))
		wire = append(wire, bytes.Repeat([]byte{99}, i)...)
	}
	wire = append(wire, "raw after eight records"...)
	c := &naiveConn{Conn: &memoryNetConn{Reader: bytes.NewReader(wire), Writer: io.Discard}}
	if got, e := io.ReadAll(c); e != nil || string(got) != "raw after eight records" {
		t.Fatal(string(got), e)
	}
	for _, bad := range [][]byte{{0}, {0, 1}, {0, 1, 0}, {0, 0, 1}, {0, 1, 2, 'x', 0}} {
		c := &naiveConn{Conn: &memoryNetConn{Reader: bytes.NewReader(bad), Writer: io.Discard}}
		if _, e := io.ReadAll(c); e != io.ErrUnexpectedEOF {
			t.Fatal("truncated record accepted", bad, e)
		}
		if _, e := c.Read(make([]byte, 1)); e != io.ErrUnexpectedEOF {
			t.Fatal("read error not sticky", e)
		}
	}
}

func TestNaiveRejectAuthentication(t *testing.T) {
	for _, quic := range []bool{false, true} {
		t.Run(fmt.Sprint(quic), func(t *testing.T) {
			server, client := naivePair(t, quic)
			out := client.config.Outbounds[0]
			out.Password = "wrong"
			bad := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			for _, network := range []string{"tcp", "udp"} {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				c, e := bad.Dial(ctx, network, server.Address("server"))
				cancel()
				if e == nil {
					c.Close()
					t.Fatal("wrong password accepted", network)
				}
			}
		})
	}
}

func TestNaiveUnpaddedAndHeaders(t *testing.T) {
	for _, quic := range []bool{false, true} {
		t.Run(fmt.Sprint(quic), func(t *testing.T) {
			server, client := naivePair(t, quic)
			// A regular unpadded HTTP client must still work against a Naive server.
			client.trustClients["proxy"].outbound.Type = "trusttunnel"
			assertTCP(t, client)
			// No-padding negotiation with a plain HTTP/2 proxy must not pad data.
			in := server.config.Inbounds[0]
			in.Type = "trusttunnel"
			if quic {
				in.HTTPVersion = 3
			}
			plain := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, plain.Address("server"))
			out.Type, out.QUIC = "naive", quic
			out.ExtraHeaders = map[string]headerValues{"X-Custom": {"preserved"}}
			assertTCP(t, newTestRuntime(t, Config{Outbounds: []Outbound{out}}))
		})
	}
}

func TestNaiveMultiplexAndHalfClose(t *testing.T) {
	for _, quic := range []bool{false, true} {
		t.Run(fmt.Sprint(quic), func(t *testing.T) {
			_, client := naivePair(t, quic)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var origins sync.WaitGroup
			acceptDone := make(chan struct{})
			go func() {
				defer close(acceptDone)
				for {
					c, e := listener.Accept()
					if e != nil {
						return
					}
					origins.Add(1)
					go func() {
						defer origins.Done()
						defer c.Close()
						c.SetDeadline(time.Now().Add(5 * time.Second))
						p, e := io.ReadAll(c)
						if e == nil {
							_ = writeAll(c, append([]byte("reply:"), p...))
						}
					}()
				}
			}()
			var workers sync.WaitGroup
			for i := range 24 {
				workers.Go(func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					c, e := client.Dial(ctx, "tcp", listener.Addr().String())
					if e != nil {
						t.Error(e)
						return
					}
					defer c.Close()
					c.SetDeadline(time.Now().Add(5 * time.Second))
					payload := bytes.Repeat([]byte{byte(i)}, 128000+i)
					if e = writeAll(c, payload); e != nil {
						t.Error(e)
						return
					}
					if e = c.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
						t.Error(e)
						return
					}
					got, e := io.ReadAll(c)
					if e != nil || !bytes.Equal(got, append([]byte("reply:"), payload...)) {
						t.Error("half-close or crossed streams", i, len(got), e)
					}
				})
			}
			workers.Wait()
			listener.Close()
			<-acceptDone
			origins.Wait()
		})
	}
}

func TestNaiveWriteFailure(t *testing.T) {
	left, right := net.Pipe()
	right.Close()
	defer left.Close()
	c := &naiveConn{Conn: left}
	_, first := c.Write([]byte("first"))
	if first == nil {
		t.Fatal("closed connection write succeeded")
	}
	if _, e := c.Write([]byte("second")); e != first || c.writes != 0 {
		t.Fatal("write failure not sticky", e)
	}
	for _, response := range []bool{false, true} {
		for range 1000 {
			length := len(naiveHeader(response))
			if response && (length < 30 || length > 62) || !response && (length < 16 || length > 32) {
				t.Fatal("padding header length", length)
			}
		}
	}
}

func TestNaiveExtraHeaders(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "GET" {
			if req.Header.Get("Proxy-Authorization") != "" {
				t.Error("preamble leaked credentials")
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if req.ProtoMajor != 2 || req.Method != "CONNECT" || req.Header.Get("X-Custom") != "preserved" || req.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("client:private")) {
			t.Error("CONNECT headers lost")
		}
		if n := len(req.Header.Get("Padding")); n < 16 || n > 32 {
			t.Error("invalid request padding header", n)
		}
		w.Header().Set("Padding", naiveHeader(true))
		w.WriteHeader(200)
		controller := http.NewResponseController(w)
		if err := controller.Flush(); err != nil {
			return
		}
		conn := &naiveConn{Conn: &httpStreamConn{reader: req.Body, writer: &flushingWriter{w: w, controller: controller}}}
		_, _ = io.Copy(conn, conn)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	out := testOutbound(t, Inbound{Type: "naive"}, server.Listener.Addr().String())
	out.TLS = TLSOptions{Enabled: true, Insecure: true}
	out.ExtraHeaders = map[string]headerValues{"X-Custom": {"preserved"}}
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	c, err := client.Dial(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if err = writeAll(c, []byte("header-check")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 12)
	if _, err = io.ReadFull(c, got); err != nil || string(got) != "header-check" {
		t.Fatal(string(got), err)
	}
}

func TestNaivePaddingNegotiation(t *testing.T) {
	for _, tc := range []struct {
		present        bool
		request, reply string
		padded, valid  bool
	}{
		{false, "", "", false, true}, {true, "", "", true, true}, {true, "1, 0", "1", true, true}, {true, "0, 1", "0", false, true}, {false, "1", "1", true, true}, {true, "9, 1", "1", true, true}, {true, "9", "", false, false},
	} {
		padded, reply, err := naivePaddingSelect(tc.present, tc.request)
		if (err == nil) != tc.valid || padded != tc.padded || reply != tc.reply {
			t.Fatal(tc, padded, reply, err)
		}
		if err == nil {
			selected, err := naivePaddingReply(tc.present, reply)
			if err != nil || selected != tc.padded {
				t.Fatal(tc, selected, err)
			}
		}
	}
	if _, err := naivePaddingReply(true, "2"); err == nil {
		t.Fatal("unknown padding type accepted")
	}
	for _, key := range []string{"Padding-Type-Request", "Padding-Type-Reply"} {
		if err := validateNaiveHeaders("naive", map[string]headerValues{key: {"0"}}, false, ""); err == nil {
			t.Fatal("owned padding header override accepted", key)
		}
	}
}

func TestNaiveHTTP2PaddingReply(t *testing.T) {
	for _, mode := range []string{"0", "1"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method == "GET" {
					w.WriteHeader(404)
					return
				}
				if req.Header.Get("Padding-Type-Request") != "1, 0" {
					t.Error("padding types were not offered")
				}
				w.Header().Set("Padding", naiveHeader(true))
				w.Header().Set("Padding-Type-Reply", mode)
				w.WriteHeader(200)
				controller := http.NewResponseController(w)
				if controller.Flush() != nil {
					return
				}
				var conn net.Conn = &httpStreamConn{reader: req.Body, writer: &flushingWriter{w: w, controller: controller}}
				if mode == "1" {
					conn = &naiveConn{Conn: conn}
				}
				_, _ = io.Copy(conn, conn)
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			out := testOutbound(t, Inbound{Type: "naive"}, server.Listener.Addr().String())
			out.TLS = TLSOptions{Enabled: true, Insecure: true}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := client.Dial(ctx, "tcp", "example.com:443")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			if err = writeAll(conn, []byte("negotiated")); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len("negotiated"))
			if _, err = io.ReadFull(conn, got); err != nil || string(got) != "negotiated" {
				t.Fatal(string(got), err)
			}
		})
	}
}

func TestNaiveConfiguration(t *testing.T) {
	in := Inbound{Type: "naive", Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{Username: "client", Password: "p"}}}
	for _, network := range []string{"tcp", "udp", ""} {
		in.Network = network
		r := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
		if r.Address("server") == "" {
			t.Fatal("missing listener")
		}
	}
	for _, name := range []string{"padding", "Proxy-Authorization", "Host", "Connection", ":authority", "Te"} {
		if validateNaiveHeaders("naive", map[string]headerValues{name: {"x"}}, false, "") == nil {
			t.Fatal("reserved header accepted", name)
		}
	}
	if validateNaiveHeaders("naive", map[string]headerValues{"X-Test": {"x\r\ninjected"}}, false, "") == nil {
		t.Fatal("header injection accepted")
	}
	if validateNaiveHeaders("socks", nil, true, "") == nil || validateNaiveHeaders("naive", nil, false, "unix") == nil {
		t.Fatal("ineffective options accepted")
	}
	if validateNaiveTLS(TLSOptions{Enabled: true, MaxVersion: "1.2"}, false, true) == nil {
		t.Fatal("QUIC below TLS1.3 accepted")
	}
	_, client := naivePair(t, false)
	out := client.config.Outbounds[0]
	out.UDPOverTCP = false
	disabled := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	if c, e := disabled.Dial(context.Background(), "udp", "127.0.0.1:53"); e == nil {
		c.Close()
		t.Fatal("UDP enabled without option")
	}
}

func TestNaiveOfficialReference(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if ref == "" {
		t.Fatal("LANBOAT_TEST_SINGBOX15 required")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", ref)
	for _, quic := range []bool{false, true} {
		t.Run(fmt.Sprint("client/quic=", quic), func(t *testing.T) {
			in := Inbound{Type: "naive", Tag: "server", Listen: "127.0.0.1", ListenPort: unusedPort(t), TLS: certificate(t), Users: []User{{Username: "client", Password: "private"}}}
			referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
			out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
			out.QUIC, out.UDPOverTCP = quic, true
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 511, 4096, 14000})
		})
		t.Run(fmt.Sprint("server/quic=", quic), func(t *testing.T) {
			ref := os.Getenv("LANBOAT_TEST_NAIVE")
			if ref == "" {
				t.Fatal("LANBOAT_TEST_NAIVE required")
			}
			f := newMutualTLSFixture(t)
			in := Inbound{Type: "naive", Tag: "server", Listen: "127.0.0.1", TLS: f.server(), Users: []User{{Username: "client", Password: "private"}}}
			in.TLS.ClientAuthentication = ""
			in.TLS.ClientCertificate = nil
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			_, port, _ := net.SplitHostPort(server.Address("server"))
			local := portAddress("127.0.0.1", unusedPort(t))
			protocol := "https"
			if quic {
				protocol = "quic"
			}
			dir := t.TempDir()
			ca := filepath.Join(dir, "ca.pem")
			if e := os.WriteFile(ca, []byte(f.ca), 0600); e != nil {
				t.Fatal(e)
			}
			log, e := os.Create(filepath.Join(dir, "naive.log"))
			if e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(ref, "--listen=socks://"+local, "--proxy="+protocol+"://client:private@example.com:"+port, "--host-resolver-rules=MAP example.com 127.0.0.1", "--log")
			cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+ca)
			cmd.Stdout, cmd.Stderr = log, log
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() {
				cmd.Process.Kill()
				cmd.Wait()
				log.Close()
				if t.Failed() {
					b, _ := os.ReadFile(log.Name())
					t.Log(string(b))
				}
			})
			waitPort(t, local)
			out := testOutbound(t, Inbound{Type: "socks"}, local)
			out.Username, out.Password = "", ""
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
		})
	}
}

// Exercise record parsing independently of HTTP fragmentation, including empty,
// truncated and concatenated frames, without peer-controlled allocations.
func FuzzNaivePadding(f *testing.F) {
	f.Add([]byte{0, 1, 2, 'x', 0, 0})
	f.Add([]byte{0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		c := &naiveConn{Conn: &memoryNetConn{Reader: bytes.NewReader(data), Writer: io.Discard}}
		_, _ = io.Copy(io.Discard, c)
	})
}

func BenchmarkNaiveRecord(b *testing.B) {
	for _, padded := range []bool{false, true} {
		b.Run(fmt.Sprint("padded=", padded), func(b *testing.B) {
			c := &naiveConn{Conn: &memoryNetConn{Reader: bytes.NewReader(nil), Writer: io.Discard}}
			payload := make([]byte, 8192)
			c.Write(payload)
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for range b.N {
				c.writes = 8
				if padded {
					c.writes = 0
				}
				if _, err := c.Write(payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
