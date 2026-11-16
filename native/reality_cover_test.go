package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"testing"
	"time"
)

type realityRecordLog struct {
	net.Conn
	mu      sync.Mutex
	pending []byte
	sizes   []int
}

func (c *realityRecordLog) record(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending = append(c.pending, b...)
	for len(c.pending) >= 5 {
		size := 5 + (int(c.pending[3])<<8 | int(c.pending[4]))
		if size > 65540 {
			panic("invalid fixture record")
		}
		if len(c.pending) < size {
			break
		}
		c.sizes = append(c.sizes, size)
		c.pending = c.pending[size:]
	}
}
func (c *realityRecordLog) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.record(b[:n])
	return n, err
}
func (c *realityRecordLog) snapshot() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.sizes...)
}

type realityReadLog struct{ *realityRecordLog }

func (c realityReadLog) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.record(b[:n])
	return n, err
}
func (c realityReadLog) Write(b []byte) (int, error) { return c.Conn.Write(b) }

type realityObservedFlight struct {
	hello []byte
	wire  *realityRecordLog
}

func TestRealityCoverRecords(t *testing.T) {
	for _, alpn := range []string{"", "http/1.1", "h2"} {
		t.Run("alpn-"+alpn, func(t *testing.T) {
			server, client := realityFixture(t)
			cert, err := certificate(t).config(true, "")
			if err != nil {
				t.Fatal(err)
			}
			cert.MinVersion = tls.VersionTLS13
			cert.NextProtos = []string{"h2", "http/1.1"}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var workers sync.WaitGroup
			observed := make(chan realityObservedFlight, 32)
			workers.Go(func() {
				for {
					raw, err := listener.Accept()
					if err != nil {
						return
					}
					workers.Go(func() {
						defer raw.Close()
						raw.SetDeadline(time.Now().Add(2 * time.Second))
						wire, hello, err := shadowHello(raw)
						if err != nil {
							return
						}
						log := &realityRecordLog{Conn: &bufferedConn{Conn: raw, reader: bufio.NewReader(io.MultiReader(bytes.NewReader(wire), raw))}}
						secure := tls.Server(log, cert)
						if err = secure.Handshake(); err == nil {
							io.Copy(io.Discard, secure)
						}
						observed <- realityObservedFlight{hello, log}
					})
				}
			})
			defer func() { listener.Close(); workers.Wait() }()
			host, port := realityAddress(t, listener.Addr().String())
			server.Reality.Handshake = &ShadowTLSHandshake{Server: host, ServerPort: port}
			if alpn != "" {
				client.ALPN = []string{alpn}
				server.ALPN = []string{alpn}
			}
			in := testInbound(t, "vless")
			in.TLS = server
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			defer s.Close()
			cfg, err := client.config(false, "localhost")
			if err != nil {
				t.Fatal(err)
			}
			raw, err := net.Dial("tcp", s.Address("server"))
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			capture := &realityRecordLog{Conn: raw}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			secure, err := dialReality(ctx, realityReadLog{capture}, cfg, client)
			if err != nil {
				t.Fatal(err)
			}
			raw.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
			if n, err := secure.Read(make([]byte, 1)); n != 0 || !os.IsTimeout(err) {
				t.Fatal("cover padding leaked application bytes", n, err)
			}
			var original, probe []int
			for range 2 {
				select {
				case v := <-observed:
					if _, err := server.Reality.authenticate(v.hello, time.Now()); err == nil {
						original = v.wire.snapshot()
					} else {
						probe = v.wire.snapshot()
					}
				case <-time.After(3 * time.Second):
					t.Fatal("missing cover capture")
				}
			}
			if len(original) < 6 || len(probe) < 6 {
				t.Fatal(original, probe)
			}
			want := append(append([]int(nil), original[:6]...), probe[6:]...)
			got := capture.snapshot()
			if !slices.Equal(got, want) {
				t.Fatal("record lengths differ", got, want)
			}
		})
	}
}

func TestRealityCoverCoalesced(t *testing.T) {
	for _, id := range []uint16{0x1301, 0x1302, 0x1303} {
		t.Run(tls.CipherSuiteName(id), func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			a.SetDeadline(time.Now().Add(3 * time.Second))
			b.SetDeadline(time.Now().Add(3 * time.Second))
			done := make(chan error, 1)
			go func() {
				_, hello, err := shadowHello(b)
				if err != nil {
					done <- err
					return
				}
				profile := syntheticRealityCover(t, hello, id, []int{8192})
				secure, err := realityServerTLS(context.Background(), b, &tls.Config{}, hello, bytes.Repeat([]byte{1}, 32), &RealityOptions{}, profile)
				if err == nil {
					_, err = secure.Write([]byte("coalesced"))
				}
				done <- err
			}()
			// A standard-library client independently verifies the TLS key schedule,
			// padded records,CertificateVerify and Finished in a coalesced flight.
			client := tls.Client(a, &tls.Config{ServerName: "localhost", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 9)
			if _, err := io.ReadFull(client, got); err != nil || string(got) != "coalesced" {
				t.Fatal(string(got), err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func syntheticRealityCover(t testing.TB, hello []byte, id uint16, lengths []int) *realityCover {
	t.Helper()
	serverHello := []byte{3, 3}
	random := make([]byte, 32)
	rand.Read(random)
	serverHello = append(serverHello, random...)
	serverHello = append(serverHello, stVector(hello[39:71], 1)...)
	serverHello = binary.BigEndian.AppendUint16(serverHello, id)
	serverHello = append(serverHello, 0)
	ext := stExtension(nil, 43, []byte{3, 4})
	key := []byte{0, 29, 0, 32}
	key = append(key, make([]byte, 32)...)
	ext = stExtension(ext, 51, key)
	serverHello = stMessage(2, append(serverHello, stVector(ext, 2)...))
	suite, err := stSuite(id)
	if err != nil {
		t.Fatal(err)
	}
	return &realityCover{hello: serverHello, helloSizes: []int{len(serverHello)}, lengths: lengths, suite: suite, group: tls.X25519}
}

func TestRealityCoverBounds(t *testing.T) {
	h, err := newSTHello(&tls.Config{ServerName: "localhost", CurvePreferences: []tls.CurveID{tls.X25519}})
	if err != nil {
		t.Fatal(err)
	}
	hello, _ := h.marshal("", nil, false)
	template := syntheticRealityCover(t, hello, 0x1301, []int{32, 500, 100, 58})
	var wire bytes.Buffer
	template.writeHello(&wire, template.hello)
	for _, size := range template.lengths {
		wire.Write(shadowFrame(23, make([]byte, size-5)))
	}
	got, err := readRealityCover(bytes.NewReader(wire.Bytes()), hello)
	if err != nil || !slices.Equal(got.lengths, template.lengths) {
		t.Fatal(err)
	}
	for _, position := range []int{0, 1, 2, 5, 43, 45, len(wire.Bytes()) - 2} {
		bad := bytes.Clone(wire.Bytes())
		bad[position] ^= 255
		profile, err := readRealityCover(bytes.NewReader(bad), hello)
		if len(profile.wire) > 65536 {
			t.Fatal("unbounded cover capture")
		}
		// Ciphertext contents cannot be authenticated without the cover keys;
		// structural corruption and truncation must be rejected.
		if position < 46 && err == nil {
			t.Fatal("invalid cover header accepted", position)
		}
	}
	for _, size := range []int{0, 21, 22, 16406, 16407} {
		cipher, _ := template.suite.recordCipher(make([]byte, 32))
		seq := cipher.sequence
		_, err := realityPaddedRecord(cipher, 23, []byte("x"), size)
		if size < 23 || size > 16406 {
			if !errors.Is(err, errRealityCoverShape) || cipher.sequence != seq {
				t.Fatal("invalid padding consumed state", size, err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
}

func TestRealityPostCache(t *testing.T) {
	server, _ := realityFixture(t)
	in := testInbound(t, "vless")
	in.TLS = server
	r := newTestRuntime(t, Config{})
	h, _ := newSTHello(&tls.Config{ServerName: "localhost", NextProtos: []string{"h2"}})
	hello, _ := h.marshal("", nil, false)
	var workers sync.WaitGroup
	for range 20 {
		workers.Go(func() {
			if _, err := r.realityPostSizes(in, hello); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	if len(r.realityPosts) != 1 || r.realityProbes.Load() != 0 {
		t.Fatal("unbounded or unshared probes", len(r.realityPosts), r.realityProbes.Load())
	}
	// Many authenticated ALPN variants cannot grow the cache beyond64 entries.
	for i := 0; i < 70; i++ {
		h, _ := newSTHello(&tls.Config{ServerName: "localhost", NextProtos: []string{fmt.Sprint("custom-", i)}})
		hello, _ := h.marshal("", nil, false)
		r.realityPostSizes(in, hello)
	}
	if len(r.realityPosts) > 64 {
		t.Fatal("post-handshake cache grew without a bound")
	}
}

func FuzzRealityCover(f *testing.F) {
	h, _ := newSTHello(&tls.Config{ServerName: "localhost", CurvePreferences: []tls.CurveID{tls.X25519}})
	hello, _ := h.marshal("", nil, false)
	template := syntheticRealityCover(f, hello, 0x1301, []int{32, 500, 100, 58})
	var wire bytes.Buffer
	template.writeHello(&wire, template.hello)
	for _, size := range template.lengths {
		wire.Write(shadowFrame(23, make([]byte, size-5)))
	}
	f.Add(hello, wire.Bytes())
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, ch, data []byte) {
		if len(ch) > 65536 || len(data) > 100000 {
			return
		}
		profile, _ := readRealityCover(bytes.NewReader(data), ch)
		if len(profile.wire) > 65536 {
			t.Fatal("cover capture exceeds bound")
		}
	})
}

func TestRealityPostCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	remote := make(chan net.Conn, 1)
	go func() { c, _ := listener.Accept(); remote <- c }()
	server, _ := realityFixture(t)
	host, port := realityAddress(t, listener.Addr().String())
	server.Reality.Handshake = &ShadowTLSHandshake{Server: host, ServerPort: port}
	in := testInbound(t, "vless")
	in.TLS = server
	r := newTestRuntime(t, Config{})
	h, _ := newSTHello(&tls.Config{ServerName: "localhost"})
	hello, _ := h.marshal("", nil, false)
	done := make(chan error, 1)
	go func() { _, err := r.realityPostSizes(in, hello); done <- err }()
	c := <-remote
	defer c.Close()
	r.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled probe succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cover probe ignored shutdown")
	}
}
