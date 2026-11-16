package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func brookInbound(t *testing.T, variant string) Inbound {
	t.Helper()
	in := Inbound{Type: "brook", Tag: "server", Listen: "127.0.0.1", Password: "private"}
	if variant == "ws" || variant == "wss" {
		in.Transport = Transport{Type: "ws", Path: "/brook"}
	}
	if variant == "wss" {
		in.TLS = certificate(t)
	}
	if variant == "hkdf" {
		in.ClientHKDFInfo, in.ServerHKDFInfo = "client-test-info", "server-test-info"
	}
	return in
}

func brookOutbound(t *testing.T, in Inbound, address string) Outbound {
	o := testOutbound(t, in, address)
	o.Transport, o.BrookOptions = in.Transport, in.BrookOptions
	return o
}

func TestBrookRoundTrip(t *testing.T) {
	for _, variant := range []string{"tcp", "udp-over-tcp", "ws", "wss", "hkdf"} {
		t.Run(variant, func(t *testing.T) {
			in := brookInbound(t, variant)
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := brookOutbound(t, in, server.Address(in.Tag))
			out.UDPOverTCP = variant == "udp-over-tcp"
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{0, 1, 511, 4096, 60000, 65440})
		})
	}
}

func startBrookReference(t *testing.T, args ...string) {
	t.Helper()
	binary := os.Getenv("LANBOAT_TEST_BROOK")
	if binary == "" {
		t.Skip("LANBOAT_TEST_BROOK is required for official Brook interoperability")
	}
	log, err := os.Create(filepath.Join(t.TempDir(), "brook.log"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, args...)
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		command.Process.Kill()
		_ = command.Wait()
		log.Close()
		if t.Failed() {
			data, _ := os.ReadFile(log.Name())
			t.Log(string(data))
		}
	})
}

func TestBrookOfficialReference(t *testing.T) {
	for _, variant := range []string{"tcp", "udp-over-tcp", "ws", "wss", "hkdf"} {
		for _, direction := range []string{"client", "server"} {
			t.Run(variant+"/"+direction, func(t *testing.T) {
				in := brookInbound(t, variant)
				var client *Runtime
				if direction == "client" {
					in.ListenPort = unusedPort(t)
					address := portAddress(in.Listen, in.ListenPort)
					var args []string
					if variant == "hkdf" {
						args = []string{"--clientHKDFInfo", in.ClientHKDFInfo, "--serverHKDFInfo", in.ServerHKDFInfo}
					}
					if variant == "ws" {
						args = append(args, "wsserver", "--listen", address, "--path", in.Transport.Path)
					} else if variant == "wss" {
						dir := t.TempDir()
						cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
						if err := os.WriteFile(cert, []byte(strings.Join(in.TLS.Certificate, "\n")), 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(key, []byte(strings.Join(in.TLS.Key, "\n")), 0600); err != nil {
							t.Fatal(err)
						}
						args = append(args, "wssserver", "--domainaddress", address, "--path", in.Transport.Path, "--cert", cert, "--certkey", key)
					} else {
						args = append(args, "server", "--listen", address)
					}
					startBrookReference(t, append(args, "--password", in.Password)...)
					waitPort(t, address)
					out := brookOutbound(t, in, address)
					out.UDPOverTCP = variant == "udp-over-tcp"
					client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				} else {
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					kind, uri := "server", server.Address(in.Tag)
					if variant == "ws" || variant == "wss" {
						kind, uri = variant+"server", variant+"://"+uri+in.Transport.Path
					}
					query := url.Values{"password": {in.Password}, kind: {uri}}
					if variant == "wss" {
						query.Set("insecure", "true")
					}
					if variant == "udp-over-tcp" {
						query.Set("udpovertcp", "true")
					}
					if variant == "hkdf" {
						query.Set("clientHKDFInfo", in.ClientHKDFInfo)
						query.Set("serverHKDFInfo", in.ServerHKDFInfo)
					}
					link := "brook://" + kind + "?" + query.Encode()
					// The reference SOCKS frontend waits for application bytes before
					// connecting. A fixed relay exercises its official Brook engine
					// without depending on that frontend's SOCKS handshake behavior.
					assertBrookReferenceServer(t, link)
					return
				}
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 511, 4096, 60000})
			})
		}
	}
}

func assertBrookReferenceServer(t *testing.T, link string, sizes ...int) {
	t.Helper()
	if len(sizes) == 0 {
		sizes = []int{1, 511, 4096, 60000}
	}
	want := strings.Repeat("Brook official client transfer\n", 10000)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, want)
	}))
	defer origin.Close()
	address := portAddress("127.0.0.1", unusedPort(t))
	startBrookReference(t, "relayoverbrook", "--link", link, "--from", address, "--to", strings.TrimPrefix(origin.URL, "http://"))
	waitPort(t, address)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + address)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(b) != want {
		t.Fatal("official client TCP", len(b), err)
	}
	address = portAddress("127.0.0.1", unusedPort(t))
	startBrookReference(t, "relayoverbrook", "--link", link, "--from", address, "--to", echoUDP(t))
	waitPort(t, address)
	direct := newTestRuntime(t, Config{})
	assertUDPAddress(t, direct, sizes, address)
}

func brookWire(t *testing.T, data []byte, packets bool) []byte {
	t.Helper()
	var wire bytes.Buffer
	c := newBrookConn(memoryNetConn{bytes.NewReader(nil), &wire}, "private", BrookOptions{}, true, &replayWindow{})
	c.packets = packets
	if _, err := c.Write(data); err != nil {
		t.Fatal(err)
	}
	return wire.Bytes()
}

func TestBrookRecordSecurity(t *testing.T) {
	want := []byte("authenticated record")
	wire := brookWire(t, want, false)
	replay := &replayWindow{}
	decode := func(b []byte, password string, w *replayWindow) ([]byte, error) {
		return newBrookConn(readerConn(b), password, BrookOptions{}, false, w).readFrame()
	}
	if b, err := decode(wire, "private", replay); err != nil || !bytes.Equal(b, want) {
		t.Fatal(b, err)
	}
	if _, err := decode(wire, "private", replay); err == nil {
		t.Fatal("replay accepted")
	}
	if _, err := decode(wire, "wrong", &replayWindow{}); err == nil {
		t.Fatal("wrong password accepted")
	}
	for i := range wire {
		bad := append([]byte(nil), wire...)
		bad[i] ^= 1
		if _, err := decode(bad, "private", &replayWindow{}); err == nil {
			t.Fatalf("tamper accepted at%d", i)
		}
	}
	for i := range len(wire) {
		if _, err := decode(wire[:i], "private", &replayWindow{}); err == nil {
			t.Fatalf("truncation accepted at%d", i)
		}
	}
	// A forged frame must not poison the replay cache for the authentic frame.
	bad := append([]byte(nil), wire...)
	bad[len(bad)-1] ^= 1
	replay = &replayWindow{}
	_, _ = decode(bad, "private", replay)
	if _, err := decode(wire, "private", replay); err != nil {
		t.Fatal("unauthenticated nonce poisoned cache", err)
	}
	// Claiming an outbound nonce also blocks reflecting its encrypted first record.
	replay = &replayWindow{}
	if err := brookClaim(replay, "private", "", wire[:12]); err != nil {
		t.Fatal(err)
	}
	if _, err := decode(wire, "private", replay); err == nil {
		t.Fatal("reflected nonce accepted")
	}
	c := newBrookConn(readerConn(bad), "private", BrookOptions{}, false, &replayWindow{})
	_, first := c.readFrame()
	_, second := c.readFrame()
	if first == nil || second != first {
		t.Fatal("failed record did not retain its error")
	}
}

func TestBrookPacketSecurity(t *testing.T) {
	plain := []byte("authenticated datagram")
	packet, err := brookSeal("private", "client-info", plain, &replayWindow{})
	if err != nil {
		t.Fatal(err)
	}
	replay := &replayWindow{}
	if b, err := brookOpen("private", "client-info", packet, replay); err != nil || !bytes.Equal(b, plain) {
		t.Fatal(b, err)
	}
	if _, err := brookOpen("private", "client-info", packet, replay); err == nil {
		t.Fatal("UDP replay accepted")
	}
	for i := range packet {
		bad := append([]byte(nil), packet...)
		bad[i] ^= 1
		if _, err := brookOpen("private", "client-info", bad, &replayWindow{}); err == nil {
			t.Fatalf("UDP tamper accepted at%d", i)
		}
	}
	if _, err := brookOpen("private", "server-info", packet, &replayWindow{}); err == nil {
		t.Fatal("incorrect HKDF info accepted")
	}
	if _, err := brookSeal("private", "", make([]byte, 65507-27), &replayWindow{}); err == nil {
		t.Fatal("oversize UDP accepted")
	}
	for _, delta := range []int64{-300, 300} {
		if brookTimestamp(binary.BigEndian.AppendUint32(nil, uint32(time.Now().Unix()+delta))) == nil {
			t.Fatal("stale/future timestamp accepted")
		}
	}
}

func TestBrookPacketBoundariesAndNonce(t *testing.T) {
	var wire bytes.Buffer
	c := newBrookConn(memoryNetConn{bytes.NewReader(nil), &wire}, "private", BrookOptions{}, true, &replayWindow{})
	c.packets = true
	for _, b := range [][]byte{bytes.Repeat([]byte{7}, 8), {}, {3, 2, 1}} {
		if _, err := c.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	reader := newBrookConn(readerConn(wire.Bytes()), "private", BrookOptions{}, false, &replayWindow{})
	reader.packets = true
	var small [4]byte
	if _, err := reader.Read(small[:]); err != io.ErrShortBuffer {
		t.Fatal("oversize datagram did not return short buffer", err)
	}
	if n, err := reader.Read(small[:]); n != 0 || err != nil {
		t.Fatal("empty datagram lost", n, err)
	}
	if n, err := reader.Read(small[:]); n != 3 || err != nil || !bytes.Equal(small[:n], []byte{3, 2, 1}) {
		t.Fatal("datagram boundary lost", n, err)
	}
	if _, err := c.Write(make([]byte, brookUDPChunk+1)); err == nil {
		t.Fatal("oversize UDP over TCP accepted")
	}
	var nonce brookNonce
	binary.LittleEndian.PutUint64(nonce.value[:8], ^uint64(0))
	if _, err := nonce.take(); err != nil {
		t.Fatal(err)
	}
	if _, err := nonce.take(); err == nil {
		t.Fatal("nonce wrapped")
	}
}

func TestBrookInvalidConfig(t *testing.T) {
	for _, value := range []string{
		`{"type":"brook","server":"localhost","server_port":1}`,
		`{"type":"brook","server":"localhost","server_port":1,"password":"x","transport":{"type":"grpc"}}`,
		`{"type":"socks","server":"localhost","server_port":1,"client_hkdf_info":"x"}`,
	} {
		if _, err := Parse([]byte(`{"outbounds":[` + value + `]}`)); err == nil {
			t.Fatal("invalid Brook config accepted", value)
		}
	}
	if _, err := Parse([]byte(`{"inbounds":[{"type":"brook","password":"x","udp_over_tcp":true}]}`)); err == nil {
		t.Fatal("inbound-only option ignored")
	}
}

func TestBrookHalfClose(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	done := make(chan error, 1)
	go func() {
		c, err := origin.Accept()
		if err == nil {
			defer c.Close()
			var b []byte
			b, err = io.ReadAll(c)
			if err == nil {
				err = writeAll(c, append([]byte("reply:"), b...))
			}
		}
		done <- err
	}()
	in := brookInbound(t, "tcp")
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := brookOutbound(t, in, server.Address(in.Tag))
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	c, err := client.Dial(context.Background(), "tcp", origin.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if err := writeAll(c, []byte("half-close")); err != nil {
		t.Fatal(err)
	}
	if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(c)
	if err != nil || string(b) != "reply:half-close" {
		t.Fatal(string(b), err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func FuzzBrookRecords(f *testing.F) {
	f.Add([]byte{}, false)
	f.Add([]byte("not an authenticated record"), true)
	var wire bytes.Buffer
	c := newBrookConn(memoryNetConn{bytes.NewReader(nil), &wire}, "fuzz", BrookOptions{}, true, &replayWindow{})
	if _, err := c.Write([]byte("authenticated fuzz seed")); err != nil {
		f.Fatal(err)
	}
	f.Add(wire.Bytes(), false)
	packet, err := brookSeal("fuzz", "", []byte("authenticated datagram seed"), &replayWindow{})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(packet, true)
	f.Fuzz(func(t *testing.T, b []byte, packets bool) {
		if len(b) > 70000 {
			return
		}
		c := newBrookConn(readerConn(b), "fuzz", BrookOptions{}, false, &replayWindow{})
		c.packets = packets
		_, _ = c.readFrame()
		_, _ = brookOpen("fuzz", "", b, &replayWindow{})
	})
}

func BenchmarkBrookTCPRecords(b *testing.B) {
	for _, size := range []int{128, 2014, 32768} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			c := newBrookConn(memoryNetConn{bytes.NewReader(nil), io.Discard}, "benchmark", BrookOptions{}, true, &replayWindow{})
			payload := make([]byte, size)
			_, _ = c.Write(payload)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				if _, err := c.Write(payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
