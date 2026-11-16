package native

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

var wsEarlyCarriers = []struct{ name, header, path string }{
	{"path", "", "/early/"},
	{"subprotocol", "Sec-WebSocket-Protocol", "/early/"},
	{"custom-header", "X-Lanboat-Early", "/early?tag=1"},
}

func TestWSTrojanEarlyLimits(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if ref == "" {
		t.Fatal("LANBOAT_TEST_SINGBOX15 required")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", ref)
	for _, limit := range []int{1, 8, 55, 56, 57, 58, 59, 64, 128, 2048} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			in := testInbound(t, "trojan")
			in.ListenPort = unusedPort(t)
			in.Transport = Transport{Type: "ws", Path: "/early/", MaxEarlyData: limit, EarlyDataHeaderName: "Sec-WebSocket-Protocol"}
			referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
			out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
			out.Transport = in.Transport
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 511, 4096})
		})
	}
}

func TestWSEarlyDataTCPUDP(t *testing.T) {
	for _, protocol := range []string{"vmess", "vless", "trojan", "shadowsocks", "relay"} {
		for _, carrier := range wsEarlyCarriers {
			t.Run(protocol+"/"+carrier.name, func(t *testing.T) {
				in := testInbound(t, protocol)
				in.Transport = Transport{Type: "ws", Path: carrier.path, MaxEarlyData: 8, EarlyDataHeaderName: carrier.header}
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out := testOutbound(t, in, server.Address("server"))
				out.Transport = in.Transport
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, client)
				sizes := []int{1, 511, 4096}
				if protocol != "vmess" {
					sizes = append(sizes, 60000)
				}
				assertUDPSizes(t, client, sizes)
			})
		}
	}
}

func TestWSEarlyDataOfficial(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if ref == "" {
		t.Fatal("LANBOAT_TEST_SINGBOX15 required for WebSocket early data interoperability")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", ref)
	for _, protocol := range []string{"vmess", "vless", "trojan"} {
		for _, carrier := range wsEarlyCarriers {
			for _, direction := range []string{"client", "server"} {
				t.Run(protocol+"/"+carrier.name+"/"+direction, func(t *testing.T) {
					in := testInbound(t, protocol)
					in.Transport = Transport{Type: "ws", Path: carrier.path, MaxEarlyData: 8, EarlyDataHeaderName: carrier.header}
					var client *Runtime
					if direction == "client" {
						in.ListenPort = unusedPort(t)
						referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
						out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
						out.Transport = in.Transport
						client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
					} else {
						server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						out := testOutbound(t, in, server.Address("server"))
						out.Transport = in.Transport
						out.Username = ""
						if protocol == "trojan" {
							out.UUID = ""
						} else {
							out.Password = ""
						}
						local := Inbound{Type: "mixed", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
						referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{out}})
						front := testOutbound(t, local, portAddress(local.Listen, local.ListenPort))
						front.Username, front.Password, front.UUID = "", "", ""
						client = newTestRuntime(t, Config{Outbounds: []Outbound{front}})
					}
					assertTCP(t, client)
					assertUDPSizes(t, client, []int{1, 511, 4096})
				})
			}
		}
	}
}

func TestWSEarlyDataFirstWriteWire(t *testing.T) {
	for _, carrier := range wsEarlyCarriers {
		t.Run(carrier.name, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			left.SetDeadline(time.Now().Add(time.Second))
			right.SetDeadline(time.Now().Add(time.Second))
			payload := []byte("first write larger than early data limit")
			result := make(chan error, 1)
			go func() {
				reader := bufio.NewReader(right)
				req, err := http.ReadRequest(reader)
				if err != nil {
					result <- err
					return
				}
				encoded := req.Header.Get(carrier.header)
				if carrier.header == "" {
					encoded = strings.TrimPrefix(req.URL.Path, carrier.path)
				} else if req.URL.Path != carrier.path {
					result <- io.ErrUnexpectedEOF
					return
				}
				early, err := base64.RawURLEncoding.DecodeString(encoded)
				if err != nil || !bytes.Equal(early, payload[:8]) {
					result <- io.ErrUnexpectedEOF
					return
				}
				_, err = io.WriteString(right, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: "+websocketAccept(req.Header.Get("Sec-WebSocket-Key"))+"\r\n\r\n")
				if err != nil {
					result <- err
					return
				}
				stream := &websocketConn{Conn: &bufferedConn{Conn: right, reader: reader}}
				rest := make([]byte, len(payload)-8)
				_, err = io.ReadFull(stream, rest)
				if err == nil && !bytes.Equal(rest, payload[8:]) {
					err = io.ErrUnexpectedEOF
				}
				result <- err
			}()
			conn, err := dialTransport(left, Outbound{Server: "example.com", Transport: Transport{Type: "ws", Path: carrier.path, MaxEarlyData: 8, EarlyDataHeaderName: carrier.header}})
			if err != nil {
				t.Fatal(err)
			}
			if n, err := conn.Write(payload); err != nil || n != len(payload) {
				t.Fatal(n, err)
			}
			if err := <-result; err != nil {
				t.Fatal("early data wire", err)
			}
		})
	}
}

func TestWSEarlyDataRejectInvalid(t *testing.T) {
	for _, v := range []struct {
		name, path, extra string
		header            bool
	}{
		{"invalid-base64", "/early/!", "", false},
		{"too-large", "/early/" + base64.RawURLEncoding.EncodeToString([]byte("123456789")), "", false},
		{"wrong-path", "/wrong/", "", false},
		{"duplicate-header", "/early/", "X-Early: YQ\r\nX-Early: Yg\r\n", true},
		{"invalid-header", "/early/", "X-Early: %%\r\n", true},
		{"http-body", "/early/", "Content-Length: 1\r\n", false},
	} {
		t.Run(v.name, func(t *testing.T) {
			raw := "GET " + v.path + " HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" + v.extra + "\r\n"
			var wire bytes.Buffer
			conn := memoryNetConn{Reader: strings.NewReader(raw), Writer: &wire}
			opts := Transport{Type: "ws", Path: "/early/", MaxEarlyData: 8}
			if v.header {
				opts.EarlyDataHeaderName = "X-Early"
			}
			if _, err := acceptTransport(&bufferedConn{Conn: conn, reader: bufio.NewReader(conn)}, opts); err == nil {
				t.Fatal("accepted invalid early data")
			}
			if wire.Len() != 0 {
				t.Fatal("upgrade succeeded before early data validation")
			}
		})
	}
	for _, opts := range []Transport{
		{Type: "ws", MaxEarlyData: -1}, {Type: "ws", MaxEarlyData: 32769}, {Type: "httpupgrade", MaxEarlyData: 8},
		{Type: "ws", MaxEarlyData: 8, EarlyDataHeaderName: "Host"},
		{Type: "ws", MaxEarlyData: 8, EarlyDataHeaderName: "Connection"},
		{Type: "ws", MaxEarlyData: 8, EarlyDataHeaderName: "Sec-WebSocket-Key"},
		{Type: "ws", MaxEarlyData: 8, EarlyDataHeaderName: "X\r\nEarly"},
		{Type: "ws", MaxEarlyData: 8, EarlyDataHeaderName: "X-Early", Headers: map[string]headerValues{"x-early": {"duplicate"}}},
	} {
		if err := opts.validate(); err == nil {
			t.Fatal("accepted invalid early data options", opts)
		}
	}
	if err := (Transport{Type: "ws", MaxEarlyData: 8}).validateFor("brook"); err == nil {
		t.Fatal("Brook accepted V2Ray early data")
	}
}

func TestWSEarlyDataHandshakeFailureSticky(t *testing.T) {
	var wire bytes.Buffer
	conn, err := dialTransport(memoryNetConn{Reader: strings.NewReader("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"), Writer: &wire}, Outbound{Server: "example.com", Transport: Transport{Type: "ws", MaxEarlyData: 8}})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write(nil); err != nil || n != 0 || wire.Len() != 0 {
		t.Fatal("empty write triggered handshake")
	}
	for range 2 {
		if n, err := conn.Write([]byte("early")); err == nil || n != 0 {
			t.Fatal("failed upgrade accepted write")
		}
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("failed upgrade accepted read")
	}
	if count := strings.Count(wire.String(), "GET "); count != 1 {
		t.Fatal("failed handshake retried", count)
	}
}

func TestWSEarlyDataConcurrentFirstIO(t *testing.T) {
	for _, readFirst := range []bool{false, true} {
		t.Run(fmt.Sprint("read-first=", readFirst), func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			left.SetDeadline(time.Now().Add(2 * time.Second))
			right.SetDeadline(time.Now().Add(2 * time.Second))
			opts := Transport{Type: "ws", Path: "/early", MaxEarlyData: 8}
			client, err := dialTransport(left, Outbound{Server: "example.com", Transport: opts})
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 2)
			ready := make(chan struct{})
			go func() {
				server, err := acceptTransport(&bufferedConn{Conn: right, reader: bufio.NewReader(right)}, opts)
				close(ready)
				if err == nil && readFirst {
					err = writeAll(server, []byte("hello"))
				}
				if err == nil {
					b := make([]byte, 5)
					_, err = io.ReadFull(server, b)
					if err == nil && string(b) != "world" {
						err = io.ErrUnexpectedEOF
					}
				}
				if err == nil && !readFirst {
					err = writeAll(server, []byte("hello"))
				}
				result <- err
			}()
			go func() {
				b := make([]byte, 5)
				_, err := io.ReadFull(client, b)
				if err == nil && string(b) != "hello" {
					err = io.ErrUnexpectedEOF
				}
				result <- err
			}()
			if readFirst {
				<-ready
			}
			if err := writeAll(client, []byte("world")); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := <-result; err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
