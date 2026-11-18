package native

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTransportTCPUDP(t *testing.T) {
	for _, protocol := range []string{"vmess", "vless", "trojan", "shadowsocks", "relay"} {
		for _, transport := range []string{"ws", "httpupgrade", "http", "grpc"} {
			t.Run(protocol+"/"+transport, func(t *testing.T) {
				in := testInbound(t, protocol)
				in.Transport = Transport{Type: transport, Path: "/proxy?test=1", Host: "proxy.example"}
				if transport == "grpc" {
					in.Transport.Path = ""
					in.Transport.ServiceName = "lanboat"
				}
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out := testOutbound(t, in, server.Address("server"))
				out.Transport = in.Transport
				out.Transport.Host = ""
				out.Transport.Headers = map[string]headerValues{"Host": {"proxy.example"}}
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 511, 4096})
			})
		}
	}
}

func TestTransportReferenceInterop(t *testing.T) {
	for _, protocol := range []string{"vmess", "vless", "trojan"} {
		for _, transport := range []string{"ws", "httpupgrade", "http", "grpc", "http-clear", "grpc-clear"} {
			if protocol == "trojan" && strings.HasSuffix(transport, "-clear") {
				continue
			}
			for _, direction := range []string{"client", "server"} {
				t.Run(protocol+"/"+transport+"/"+direction, func(t *testing.T) {
					in := testInbound(t, protocol)
					if transport == "http" || transport == "grpc" {
						in.TLS = certificate(t)
					}
					in.Transport = Transport{Type: strings.TrimSuffix(transport, "-clear"), Path: "/proxy"}
					if in.Transport.Type == "grpc" {
						in.Transport.Path = ""
						in.Transport.ServiceName = "lanboat"
					}
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
						out.Transport, out.Username = in.Transport, ""
						if protocol == "trojan" {
							out.UUID = ""
						} else {
							out.Password = ""
						}
						local := Inbound{Type: "mixed", Tag: "local", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
						referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{out}, Route: Route{Final: "proxy"}})
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

func TestWebSocketFragmentationAndPing(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(time.Second))
	_ = right.SetDeadline(time.Now().Add(time.Second))
	server := &websocketConn{Conn: left}
	result := make(chan error, 1)
	go func() {
		// Two masked binary fragments with a ping between them.
		for _, frame := range [][]byte{{2, 0x83, 1, 2, 3, 4, 'a' ^ 1, 'b' ^ 2, 'c' ^ 3}, {0x89, 0x81, 4, 3, 2, 1, 'x' ^ 4}} {
			if err := writeAll(right, frame); err != nil {
				result <- err
				return
			}
		}
		var pong [3]byte
		if _, err := io.ReadFull(right, pong[:]); err != nil {
			result <- err
			return
		}
		if !bytes.Equal(pong[:], []byte{0x8a, 1, 'x'}) {
			result <- io.ErrUnexpectedEOF
			return
		}
		result <- writeAll(right, []byte{0x80, 0x83, 1, 2, 3, 4, 'd' ^ 1, 'e' ^ 2, 'f' ^ 3})
	}()
	payload := make([]byte, 6)
	if _, err := io.ReadFull(server, payload); err != nil || string(payload) != "abcdef" {
		t.Fatalf("fragments: %q %v", payload, err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestWebSocketRejectsInvalidFrames(t *testing.T) {
	for name, frame := range map[string][]byte{
		"unmasked client":        {0x82, 1, 'a'},
		"reserved bits":          {0xc2, 0x80},
		"unstarted continuation": {0x80, 0x80, 0, 0, 0, 0},
		"text":                   {0x81, 0x80, 0, 0, 0, 0},
		"fragmented ping":        {0x09, 0x80},
		"noncanonical size":      {0x82, 0xfe, 0, 1},
		"too large":              {0x82, 0xff, 0, 0, 0, 0, 1, 0, 0, 1},
	} {
		t.Run(name, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			_ = left.SetDeadline(time.Now().Add(time.Second))
			go func() { _, _ = right.Write(frame); right.Close() }()
			server := &websocketConn{Conn: left}
			if _, err := server.Read(make([]byte, 32)); err == nil {
				t.Fatal("accepted invalid frame")
			}
		})
	}
}

func TestTransportRejectsHeaderInjectionAndBadHandshake(t *testing.T) {
	for _, transport := range []Transport{
		{Type: "ws", Path: "/\r\nInjected: yes"},
		{Type: "ws", Host: "example.org\r\nInjected: yes"},
		{Type: "ws", Headers: map[string]headerValues{"X-Test": {"a\r\nb"}}},
		{Type: "ws", Headers: map[string]headerValues{"Bad:Name": {"a"}}},
	} {
		if err := transport.validate(); err == nil {
			t.Fatalf("accepted injected transport: %+v", transport)
		}
	}
	for _, raw := range []string{
		"GET /wrong HTTP/1.1\r\nHost: example.org\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: example.org\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: bad\r\n\r\n",
	} {
		left, right := net.Pipe()
		_ = left.SetDeadline(time.Now().Add(time.Second))
		go func() { _, _ = right.Write([]byte(raw)); right.Close() }()
		_, err := acceptTransport(&bufferedConn{Conn: left, reader: bufio.NewReader(left)}, Transport{Type: "ws"})
		left.Close()
		if err == nil {
			t.Fatal("accepted invalid handshake")
		}
	}
}

func TestWebSocketLengthBoundaries(t *testing.T) {
	for _, size := range []int{1, 125, 126, 127, 128, 65535, 65536} {
		for _, masked := range []bool{false, true} {
			var wire bytes.Buffer
			sender := &websocketConn{Conn: memoryNetConn{Reader: bytes.NewReader(nil), Writer: &wire}, client: masked}
			want := bytes.Repeat([]byte{byte(size)}, size)
			if e := sender.writeFrame(2, want); e != nil {
				t.Fatal(e)
			}
			receiver := &websocketConn{Conn: readerConn(wire.Bytes()), client: !masked}
			got := make([]byte, size)
			if _, e := io.ReadFull(receiver, got); e != nil || !bytes.Equal(got, want) {
				t.Fatalf("size=%d,masked=%v: %v", size, masked, e)
			}
		}
	}
}

func TestWebSocketGracefulClose(t *testing.T) {
	for _, client := range []bool{false, true} {
		var wire bytes.Buffer
		sender := &websocketConn{Conn: memoryNetConn{Reader: bytes.NewReader(nil), Writer: &wire}, client: client}
		want := bytes.Repeat([]byte("final record"), 3000)
		if _, err := sender.Write(want); err != nil {
			t.Fatal(err)
		}
		if err := sender.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		size := wire.Len()
		if err := sender.CloseWrite(); err != nil || wire.Len() != size {
			t.Fatal("duplicate close frame", err)
		}
		if _, err := sender.Write([]byte("late data")); err != io.ErrClosedPipe || wire.Len() != size {
			t.Fatal("data after close frame", err)
		}
		receiver := &websocketConn{Conn: readerConn(wire.Bytes()), client: !client}
		got, err := io.ReadAll(receiver)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("close frame lost final data", len(got), err)
		}
	}
}

func TestWebSocketPluginCloseProbe(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	left.SetDeadline(time.Now().Add(3 * time.Second))
	right.SetDeadline(time.Now().Add(3 * time.Second))
	sender := &websocketConn{Conn: left, closeProbe: true}
	receiver := &websocketConn{Conn: right, client: true}
	done := make(chan error, 1)
	go func() { _, err := io.Copy(io.Discard, sender); done <- err }()
	want := bytes.Repeat([]byte("last plugin data"), 20000)
	got := make(chan []byte, 1)
	go func() {
		data, err := io.ReadAll(receiver)
		if err != nil {
			t.Error(err)
		}
		got <- data
		receiver.CloseWrite()
	}()
	if _, err := sender.Write(want); err != nil {
		t.Fatal(err)
	}
	if err := sender.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if data := <-got; !bytes.Equal(data, want) {
		t.Fatal("close probe lost final message", len(data))
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	sender.writeMu.Lock()
	defer sender.writeMu.Unlock()
	if sender.closePong != nil {
		t.Fatal("peer did not acknowledge drain probe")
	}
}

func TestWebSocketCloseProbeCancellation(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	sender := &websocketConn{Conn: left, closeProbe: true}
	done := make(chan error, 1)
	go func() { done <- sender.CloseWrite() }()
	var ping [10]byte
	right.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(right, ping[:]); err != nil || ping[0] != 0x89 {
		t.Fatal("close probe missing", err)
	}
	sender.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed connection accepted Close frame")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("shutdown waited for probe timeout")
	}
}

func TestWebSocketMaskOffsets(t *testing.T) {
	mask := [4]byte{0x12, 0x34, 0x56, 0x78}
	for size := range 40 {
		for offset := range 4 {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i * 7)
			}
			got := bytes.Clone(data)
			wsMask(got, mask, offset)
			for i := range data {
				if got[i] != data[i]^mask[(offset+i)&3] {
					t.Fatalf("size %d offset %d byte %d", size, offset, i)
				}
			}
		}
	}
}
