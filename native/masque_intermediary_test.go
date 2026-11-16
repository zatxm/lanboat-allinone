package native

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// This hop forwards HTTP/3 streams to an HTTP/1 origin and drops all QUIC
// datagrams. A first-hop DATAGRAM setting is not an end-to-end capability.
func masqueIntermediary(t *testing.T, origin *Runtime, responseVia, capsules bool) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert := certificate(t)
	cert.ALPN = []string{"h3"}
	cfg, err := cert.config(true, "")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := listenQUIC(ctx, packet, cfg, quicOptions{packetSize: 1400})
	if err != nil {
		packet.Close()
		t.Fatal(err)
	}
	var upstream *Runtime
	if origin.config.Inbounds[0].HTTPVersion == 3 {
		upstream = masqueIntermediaryClient(t, origin.Address("server"), "ip", nil)
	}
	var workers sync.WaitGroup
	t.Cleanup(func() { cancel(); endpoint.Close(); workers.Wait() })
	workers.Go(func() {
		for {
			q, err := endpoint.Accept(ctx)
			if err != nil {
				return
			}
			workers.Go(func() {
				m, err := newMasqueSession(q)
				if err != nil {
					t.Error(err)
					return
				}
				defer func() { m.close(); m.workers.Wait() }()
				m.start(func(s *quicStream) {
					s.SetDeadline(time.Now().Add(5 * time.Second))
					kind, block, err := h3ReadFrame(s)
					if err != nil || kind != 1 {
						return
					}
					h, err := h3Decode(block)
					if err != nil {
						t.Error(err)
						return
					}
					if upstream != nil {
						client := upstream.masqueClients["proxy"]
						client.mu.Lock()
						u, err := client.ensure(ctx, 3)
						client.mu.Unlock()
						if err != nil {
							t.Error(err)
							return
						}
						f, err := client.open(ctx, u, h[":protocol"], h[":path"], h[":authority"])
						if err != nil {
							t.Error(err)
							return
						}
						defer f.Close()
						stop := context.AfterFunc(m.ctx, func() { f.Close() })
						defer stop()
						headers := [][2]string{{":status", "200"}, {"capsule-protocol", "?1"}}
						if responseVia {
							headers = append(headers, [2]string{"via", "3 test-hop"})
						}
						if h3WriteFrame(s, 1, h3Encode(headers)) != nil {
							return
						}
						s.SetDeadline(time.Time{})
						origin.relay(&trustH3Conn{quicStream: s}, f.body)
						return
					}
					raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", origin.Address("server"))
					if err != nil {
						t.Error(err)
						return
					}
					defer raw.Close()
					stop := context.AfterFunc(m.ctx, func() { raw.Close() })
					defer stop()
					raw.SetDeadline(time.Now().Add(5 * time.Second))
					method, target, upgrade := "CONNECT", h[":authority"], ""
					if protocol := h[":protocol"]; protocol != "" {
						method, target = "GET", h[":path"]
						upgrade = "Connection: Upgrade\r\nUpgrade: " + protocol + "\r\nCapsule-Protocol: ?1\r\n"
					}
					_, err = fmt.Fprintf(raw, "%s %s HTTP/1.1\r\nHost: %s\r\nAuthorization: %s\r\nProxy-Authorization: %s\r\nVia: 3 test-hop\r\n%s\r\n", method, target, h[":authority"], h["authorization"], h["proxy-authorization"], upgrade)
					if err != nil {
						return
					}
					reader := bufio.NewReader(raw)
					response, err := http.ReadResponse(reader, &http.Request{Method: method})
					if err != nil {
						t.Error(err)
						return
					}
					status := response.StatusCode
					if status == 101 {
						status = 200
					}
					headers := [][2]string{{":status", fmt.Sprint(status)}}
					if responseVia {
						headers = append(headers, [2]string{"via", "1.1 test-hop"})
					}
					if capsules && response.Header.Get("Capsule-Protocol") == "?1" {
						headers = append(headers, [2]string{"capsule-protocol", "?1"})
					}
					if h3WriteFrame(s, 1, h3Encode(headers)) != nil || status != 200 {
						return
					}
					s.SetDeadline(time.Time{})
					raw.SetDeadline(time.Time{})
					origin.relay(&trustH3Conn{quicStream: s}, &bufferedConn{Conn: raw, reader: reader})
				})
				<-m.done
			})
		}
	})
	return packet.LocalAddr().String()
}

func masqueIntermediaryClient(t *testing.T, address, mode string, headers map[string]headerValues) *Runtime {
	t.Helper()
	host, port, _ := net.SplitHostPort(address)
	n, _ := shadowPort(port)
	return newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "masque", Tag: "proxy", Server: host, ServerPort: n, Username: "client", Password: "private", TLS: TLSOptions{Enabled: true, Insecure: true}, MasqueOptions: MasqueOptions{Mode: mode, Headers: headers, DisableVersionFallback: true}}}})
}

func TestMasqueIntermediary(t *testing.T) {
	for _, mode := range []string{"ip", "udp"} {
		for _, via := range []string{"response", "request"} {
			t.Run(mode+"/"+via, func(t *testing.T) {
				in := Inbound{Type: "masque", Tag: "server", Listen: "127.0.0.1", HTTPVersion: 1, Users: []User{{Username: "client", Password: "private"}}}
				origin := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				address := masqueIntermediary(t, origin, via == "response", true)
				var headers map[string]headerValues
				if via == "request" {
					headers = map[string]headerValues{"ViA": {"3 previous-hop"}}
				}
				client := masqueIntermediaryClient(t, address, mode, headers)
				for range 2 {
					assertTCP(t, client)
					assertUDPAddress(t, client, []int{0, 1, 511, 1232, 4096, 60000}, masqueEcho(t, "udp", "127.0.0.1:0"))
					assertUDPAddress(t, client, []int{0, 1, 1232, 4096, 60000}, masqueEcho(t, "udp", "[::1]:0"))
					if mode == "ip" && !client.masqueClients["proxy"].ip.Load().flow.via {
						t.Fatal("intermediary not detected")
					}
					client.resetNetworkTransports()
				}
			})
		}
	}
}

func TestMasqueIntermediaryRequiresCapsules(t *testing.T) {
	in := Inbound{Type: "masque", Tag: "server", Listen: "127.0.0.1", HTTPVersion: 1, Users: []User{{Username: "client", Password: "private"}}}
	origin := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	for _, mode := range []string{"ip", "udp"} {
		t.Run(mode, func(t *testing.T) {
			client := masqueIntermediaryClient(t, masqueIntermediary(t, origin, true, false), mode, nil)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := client.Dial(ctx, "udp", "127.0.0.1:53")
			if conn != nil {
				conn.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "did not negotiate capsules") {
				t.Fatal("unsafe datagram-only intermediary accepted", err)
			}
		})
	}
}

func TestMasqueIntermediaryFlowIsolation(t *testing.T) {
	_, runtime := masquePair(t, "udp")
	client := runtime.masqueClients["proxy"]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client.mu.Lock()
	m, err := client.ensure(ctx, 3)
	client.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	address := echoUDP(t)
	host, port, _ := net.SplitHostPort(address)
	path := "/.well-known/masque/udp/" + url.PathEscape(host) + "/" + port + "/"
	for _, via := range []bool{false, true, false, true} {
		caller := &masqueClient{runtime: runtime, outbound: client.outbound}
		if via {
			caller.outbound.Headers = map[string]headerValues{"Via": {"3 previous-hop"}}
		}
		f, err := caller.open(ctx, m, "connect-udp", path, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if f.via != via {
			t.Fatal("Via policy leaked between streams")
		}
		f.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = f.Write([]byte("separate stream")); err != nil {
			t.Fatal(err)
		}
		if via {
			kind, err := readQUICVar(f.body)
			if err != nil || kind != 0 {
				t.Fatal("server did not switch to capsules", kind, err)
			}
			n, err := readQUICVar(f.body)
			if err != nil || n != 16 {
				t.Fatal("wrong capsule length", n, err)
			}
			b := make([]byte, n)
			if _, err := io.ReadFull(f.body, b); err != nil || string(b) != "\x00separate stream" {
				t.Fatal("server capsule damaged", err)
			}
		} else {
			var b [32]byte
			if n, err := f.Read(b[:]); err != nil || string(b[:n]) != "separate stream" {
				t.Fatal("direct stream lost QUIC datagrams", err)
			}
		}
	}
}

func TestMasqueUnknownContexts(t *testing.T) {
	for _, reliable := range []bool{false, true} {
		t.Run(fmt.Sprint(reliable), func(t *testing.T) {
			m := newMasqueHTTPSession(context.Background())
			defer m.close()
			f := &masqueFlow{session: m, incoming: make(chan masqueDatagram, 1), done: make(chan struct{}), notify: make(chan struct{}, 1)}
			for _, id := range []uint64{1, 2, 63, 64, 16384, 1<<30 - 1, 1<<62 - 1} {
				for _, size := range []int{0, 1, 65535} {
					if err := f.deliver(append(quicVar(nil, id), make([]byte, size)...), reliable); err != nil {
						t.Fatal(id, err)
					}
					if len(f.incoming) != 0 || m.buffered.Load() != 0 {
						t.Fatal("unknown context queued as IP/UDP payload")
					}
				}
			}
			// RFC9484 permits non-minimal variable-length integers, including zero.
			for _, encoded := range [][]byte{{0}, {0x40, 0}, {0x80, 0, 0, 0}, {0xc0, 0, 0, 0, 0, 0, 0, 0}} {
				if err := f.deliver(append(encoded, 42), reliable); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 1)
				if n, err := f.Read(b); err != nil || n != 1 || b[0] != 42 || m.buffered.Load() != 0 {
					t.Fatal("valid context affected", n, err)
				}
			}
			for _, b := range [][]byte{nil, {0x40}, {0x80, 0}, {0xc0, 0, 0, 0}} {
				if err := f.deliver(b, reliable); err == nil {
					t.Fatal("truncated context accepted")
				}
			}
		})
	}
}

func TestMasqueUnknownContextCapsules(t *testing.T) {
	m := newMasqueHTTPSession(context.Background())
	defer m.close()
	a, b := net.Pipe()
	defer b.Close()
	f, err := m.registerFlow(a, 0, a)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m.goWork(func() { _ = f.readCapsules() })
	var wire []byte
	for _, id := range []uint64{2, 1<<62 - 1, 0} {
		data := append(quicVar(nil, id), []byte("payload")...)
		wire = quicVar(wire, 0)
		wire = quicVar(wire, uint64(len(data)))
		wire = append(wire, data...)
	}
	written := make(chan error, 1)
	go func() { written <- writeAll(b, wire) }()
	f.SetReadDeadline(time.Now().Add(time.Second))
	var got [32]byte
	if n, err := f.Read(got[:]); err != nil || !bytes.Equal(got[:n], []byte("payload")) {
		t.Fatal("unknown capsule context damaged stream", n, err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if m.buffered.Load() != 0 {
		t.Fatal("unknown context retained budget")
	}
}

func FuzzMasqueContext(f *testing.F) {
	for _, b := range [][]byte{{0, 42}, {0x40, 0, 42}, {1}, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, {0xc0}} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65544 {
			return
		}
		m := newMasqueHTTPSession(context.Background())
		defer m.close()
		flow := &masqueFlow{session: m, incoming: make(chan masqueDatagram, 1), done: make(chan struct{}), notify: make(chan struct{}, 1)}
		r := quicReader(b)
		id, parseErr := r.v()
		err := flow.deliver(b, false)
		if parseErr != nil || id == 0 && len(r) > 65535 {
			if err == nil {
				t.Fatal("malformed context accepted")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if id != 0 {
			if len(flow.incoming) != 0 || m.buffered.Load() != 0 {
				t.Fatal("unknown context allocated queue space")
			}
			return
		}
		select {
		case got := <-flow.incoming:
			if !bytes.Equal(got.data, r) || got.reliable || m.buffered.Load() != int64(len(r)) {
				t.Fatal("payload changed")
			}
		default:
			t.Fatal("valid datagram lost")
		}
	})
}
