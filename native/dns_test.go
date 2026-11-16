package native

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

func dnsAnswer(query []byte) []byte {
	reply := append([]byte{}, query...)
	reply[2], reply[3], reply[7] = 0x81, 0x80, 1
	_, end, _ := dnsName(query, 12)
	typ := binary.BigEndian.Uint16(query[end:])
	reply = append(reply, 0xc0, 0x0c)
	reply = binary.BigEndian.AppendUint16(reply, typ)
	reply = binary.BigEndian.AppendUint16(reply, 1)
	reply = binary.BigEndian.AppendUint32(reply, 60)
	address := netip.MustParseAddr("192.0.2.42").AsSlice()
	if typ == 28 {
		address = netip.MustParseAddr("2001:db8::42").AsSlice()
	}
	reply = binary.BigEndian.AppendUint16(reply, uint16(len(address)))
	return append(reply, address...)
}

func TestDNSTransportsCacheAndCoalescing(t *testing.T) {
	for _, kind := range []string{"udp", "tcp", "tls", "https"} {
		t.Run(kind, func(t *testing.T) {
			var requests atomic.Int64
			answer := func(b []byte) []byte { requests.Add(1); time.Sleep(5 * time.Millisecond); return dnsAnswer(b) }
			var address string
			if kind == "https" {
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, _ := io.ReadAll(r.Body)
					w.Header().Set("Content-Type", "application/dns-message")
					_, _ = w.Write(answer(body))
				}))
				defer server.Close()
				address = server.Listener.Addr().String()
			} else if kind == "udp" {
				server, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				address = server.LocalAddr().String()
				go func() {
					b := make([]byte, 4096)
					for {
						n, from, err := server.ReadFrom(b)
						if err != nil {
							return
						}
						_, _ = server.WriteTo(answer(b[:n]), from)
					}
				}()
			} else {
				var server net.Listener
				var err error
				if kind == "tls" {
					cfg, err := certificate(t).config(true, "")
					if err != nil {
						t.Fatal(err)
					}
					server, err = tls.Listen("tcp", "127.0.0.1:0", cfg)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					server, err = net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
				}
				defer server.Close()
				address = server.Addr().String()
				go func() {
					for {
						c, err := server.Accept()
						if err != nil {
							return
						}
						go func() {
							defer c.Close()
							var size [2]byte
							if _, err := io.ReadFull(c, size[:]); err != nil {
								return
							}
							q := make([]byte, int(binary.BigEndian.Uint16(size[:])))
							if _, err := io.ReadFull(c, q); err != nil {
								return
							}
							reply := answer(q)
							_ = writeAll(c, binary.BigEndian.AppendUint16(nil, uint16(len(reply))))
							_ = writeAll(c, reply)
						}()
					}
				}()
			}
			host, port, _ := net.SplitHostPort(address)
			p, _ := strconv.ParseUint(port, 10, 16)
			cfg := Config{DNS: DNSConfig{Servers: []DNSServer{{Type: kind, Tag: "resolver", Server: host, ServerPort: uint16(p), TLS: TLSOptions{Insecure: true}}}}}
			raw, _ := json.Marshal(cfg)
			client, err := New(context.Background(), raw, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			var group sync.WaitGroup
			for range 20 {
				group.Add(1)
				go func() {
					defer group.Done()
					ips, err := client.LookupIP(context.Background(), "test.example")
					if err != nil || len(ips) != 2 {
						t.Errorf("DNS transport: %v %v", ips, err)
					}
				}()
			}
			group.Wait()
			if requests.Load() != 2 {
				t.Fatalf("wanted 2 coalesced queries, got %d", requests.Load())
			}
			_, err = client.LookupIP(context.Background(), "test.example")
			if err != nil {
				t.Fatal(err)
			}
			if requests.Load() != 2 {
				t.Fatal("cache missed")
			}
		})
	}
}

func TestDNSRejectsForgedResponse(t *testing.T) {
	query, _ := makeDNSQuery("safe.example", 1)
	for _, mutate := range []func([]byte){func(b []byte) { b[0] ^= 1 }, func(b []byte) { b[2] = 0 }, func(b []byte) { b[13] = 'x' }, func(b []byte) { b[3] |= 3 }} {
		reply := dnsAnswer(query)
		mutate(reply)
		if _, _, err := parseDNSReply(query, reply); err == nil {
			t.Fatal("forged response was accepted")
		}
	}
	if _, _, err := dnsName([]byte{0xc0, 0}, 0); err == nil {
		t.Fatal("compression loop accepted")
	}
}

func FuzzDNSReply(f *testing.F) {
	query, _ := makeDNSQuery("test.example", 1)
	f.Add(dnsAnswer(query))
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, reply []byte) { _, _, _ = parseDNSReply(query, reply) })
}

func TestDNSResponseMappedIPv4(t *testing.T) {
	q, _ := makeDNSQuery("example.test", 1)
	_, end, _, err := dnsQuestion(q)
	if err != nil {
		t.Fatal(err)
	}
	reply := dnsResponse(q, end, []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.42")}, 60, 0)
	ips, _, err := parseDNSReply(q, reply)
	if err != nil || len(ips) != 1 || !ips[0].Is4() || ips[0].String() != "192.0.2.42" {
		t.Fatal(ips, err)
	}
}
