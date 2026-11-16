package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type wechatTestConn struct {
	net.Conn
	packets [][]byte
	send    func([]byte) (int, error)
}

func (c *wechatTestConn) Read(b []byte) (int, error) {
	if len(c.packets) == 0 {
		return 0, io.EOF
	}
	p := c.packets[0]
	c.packets = c.packets[1:]
	return copy(b, p), nil
}
func (c *wechatTestConn) Write(b []byte) (int, error) { return c.send(b) }

func TestWechatWireAndBounds(t *testing.T) {
	for _, size := range []int{0, 1, 1200, 65507 - wechatHeaderSize} {
		payload := bytes.Repeat([]byte{0x5a}, size)
		var packet []byte
		n, err := writeWechat(payload, 0x12345678, func(b []byte) (int, error) { packet = bytes.Clone(b); return len(b), nil })
		if err != nil || n != size || hex.EncodeToString(packet[:13]) != "a1081234567800101118302230" || !bytes.Equal(packet[13:], payload) {
			t.Fatal(size, n, err)
		}
	}
	if _, err := writeWechat(make([]byte, 65507-12), 0, func([]byte) (int, error) { t.Fatal("sent oversized packet"); return 0, nil }); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal(err)
	}
	if _, err := writeWechat([]byte{1}, 0, func(b []byte) (int, error) { return len(b) - 1, nil }); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	wantErr := errors.New("send failed")
	if _, err := writeWechat([]byte{1}, 0, func(b []byte) (int, error) { return 0, wantErr }); err != wantErr {
		t.Fatal(err)
	}
	var seen []uint32
	c := newWechatConn(&wechatTestConn{send: func(b []byte) (int, error) { seen = append(seen, binary.BigEndian.Uint32(b[2:6])); return len(b), nil }})
	c.sequence.Store(^uint32(0))
	c.Write([]byte{1})
	c.Write([]byte{1})
	if len(seen) != 2 || seen[0] != ^uint32(0) || seen[1] != 0 {
		t.Fatal("camouflage sequence wrap", seen)
	}
}

func TestWechatDatagramsAndCancellation(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	wrapped := newWechatPacket(server)
	client, err := net.Dial("udp", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	wrapped.SetDeadline(time.Now().Add(2 * time.Second))
	for size := 0; size <= wechatHeaderSize; size++ {
		client.Write(make([]byte, size))
	}
	var packet []byte
	writeWechat([]byte("payload"), 99, func(b []byte) (int, error) { packet = bytes.Clone(b); return len(b), nil })
	client.Write(packet)
	buffer := make([]byte, 100)
	n, remote, err := wrapped.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "payload" {
		t.Fatal(n, err)
	}
	if n, err = wrapped.WriteTo(buffer[:n], remote); err != nil || n != 7 {
		t.Fatal(n, err)
	}
	n, err = client.Read(buffer)
	if err != nil || n != 20 || string(buffer[13:n]) != "payload" {
		t.Fatal(n, err)
	}
	conn := newWechatConn(client)
	conn.SetReadDeadline(time.Now().Add(time.Millisecond))
	if _, err = conn.Read(buffer); !os.IsTimeout(err) {
		t.Fatal("read deadline", err)
	}
	conn.SetReadDeadline(time.Time{})
	done := make(chan error, 1)
	go func() { _, e := conn.Read(buffer); done <- e }()
	conn.Close()
	select {
	case e := <-done:
		if !errors.Is(e, net.ErrClosed) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("close blocked")
	}
}

func TestWechatConcurrentWrites(t *testing.T) {
	var mu sync.Mutex
	seen := map[uint32]bool{}
	c := newWechatConn(&wechatTestConn{send: func(b []byte) (int, error) {
		if len(b) != 1213 || !bytes.Equal(b[13:], bytes.Repeat([]byte{7}, 1200)) {
			t.Error("corrupt concurrent payload")
		}
		seq := binary.BigEndian.Uint32(b[2:6])
		mu.Lock()
		if seen[seq] {
			t.Error("duplicate sequence")
		}
		seen[seq] = true
		mu.Unlock()
		return len(b), nil
	}})
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				if _, err := c.Write(bytes.Repeat([]byte{7}, 1200)); err != nil {
					t.Error(err)
				}
			}
		})
	}
	workers.Wait()
	if len(seen) != 800 {
		t.Fatal(len(seen))
	}
}

func TestHysteriaWechatConfig(t *testing.T) {
	for _, protocol := range []string{"", "udp", "wechat-video"} {
		in := Inbound{Type: "hysteria", Tag: "server", TLS: certificate(t), Protocol: protocol, Users: []User{{Password: "private"}}}
		out := Outbound{Type: "hysteria", Tag: "proxy", Server: "127.0.0.1", ServerPort: 443, Password: "private", Protocol: protocol, TLS: TLSOptions{Enabled: true}}
		b, _ := json.Marshal(Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{out}})
		if _, err := Parse(b); err != nil {
			t.Fatal(protocol, err)
		}
		for _, bad := range []struct{ kind, protocol, param string }{{"hysteria", "origin", ""}, {"hysteria2", "wechat-video", ""}, {"hysteria", "wechat-video", "unused"}} {
			in.Type, in.Protocol, in.ProtocolParam = bad.kind, bad.protocol, bad.param
			b, _ = json.Marshal(Config{Inbounds: []Inbound{in}})
			if _, err := Parse(b); err == nil {
				t.Fatal("accepted inbound", bad)
			}
			out.Type, out.Protocol, out.ProtocolParam = bad.kind, bad.protocol, bad.param
			b, _ = json.Marshal(Config{Outbounds: []Outbound{out}})
			if _, err := Parse(b); err == nil {
				t.Fatal("accepted outbound", bad)
			}
		}
	}
}

func TestHysteriaWechatIndependent(t *testing.T) {
	for _, mask := range []string{"", "xplus"} {
		t.Run("hop/"+mask, func(t *testing.T) { testHysteriaHop(t, "hysteria", mask, "", false, false, "wechat-video") })
	}
	t.Run("ipv6", func(t *testing.T) { testHysteriaHop(t, "hysteria", "xplus", "", true, false, "wechat-video") })
	t.Run("detour-and-loss", func(t *testing.T) { testHysteriaHop(t, "hysteria", "xplus", "", false, true, "wechat-video") })
}

func TestHysteriaWechatAuthentication(t *testing.T) {
	in := Inbound{Type: "hysteria", Tag: "server", Listen: "127.0.0.1", Protocol: "wechat-video", TLS: certificate(t), Users: []User{{Password: "private"}}, Obfs: "mask-fixture"}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	target := tcpEcho(t)
	for _, failure := range []string{"password", "certificate", "mask", "transport"} {
		t.Run(failure, func(t *testing.T) {
			out := testOutbound(t, in, server.Address("server"))
			out.Username, out.UUID, out.Protocol, out.Obfs = "", "", "wechat-video", in.Obfs
			out.TLS.Insecure = false
			out.TLS.Certificate = in.TLS.Certificate
			switch failure {
			case "password":
				out.Password = "wrong-password"
			case "certificate":
				out.TLS.ServerName = "wrong.example"
			case "mask":
				out.Obfs = "wrong-mask"
			case "transport":
				out.Protocol = "udp"
			}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, err := client.Dial(ctx, "tcp", target)
			if conn != nil {
				conn.Close()
			}
			if err == nil {
				t.Fatal("invalid authentication/transport accepted")
			}
		})
	}
}

func startHysteria1Reference(t *testing.T, config map[string]any, role, ready string) {
	t.Helper()
	binary := os.Getenv("LANBOAT_TEST_HYSTERIA1")
	if binary == "" {
		t.Fatal("LANBOAT_TEST_HYSTERIA1 required")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	b, _ := json.Marshal(config)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(dir, "reference.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "--no-check", "--log-level", "error", "-c", path, role)
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
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
	if ready == "" {
		return
	}
	for range 200 {
		c, err := net.DialTimeout("tcp", ready, 20*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("official HY1 did not listen")
}

func TestHysteriaWechatReference(t *testing.T) {
	for _, mask := range []string{"", "xplus"} {
		for _, direction := range []string{"client", "server"} {
			t.Run(mask+"/"+direction, func(t *testing.T) {
				in := Inbound{Type: "hysteria", Tag: "server", Listen: "127.0.0.1", Protocol: "wechat-video", TLS: certificate(t), Users: []User{{Password: "private"}}}
				if mask != "" {
					in.Obfs = "mask-fixture"
				}
				dir := t.TempDir()
				cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
				if err := os.WriteFile(cert, []byte(strings.Join(in.TLS.Certificate, "\n")), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(key, []byte(strings.Join(in.TLS.Key, "\n")), 0600); err != nil {
					t.Fatal(err)
				}
				var client *Runtime
				if direction == "client" {
					in.ListenPort = unusedPort(t)
					ready := portAddress("127.0.0.1", unusedPort(t))
					startHysteria1Reference(t, map[string]any{"listen": portAddress(in.Listen, in.ListenPort), "protocol": "wechat-video", "cert": cert, "key": key, "up_mbps": 100, "down_mbps": 100, "obfs": string(in.Obfs), "auth": map[string]any{"mode": "passwords", "config": []string{"private"}}, "prometheus_listen": ready}, "server", ready)
					out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
					out.Username, out.UUID = "", ""
					out.Protocol = "wechat-video"
					out.Obfs = in.Obfs
					out.TLS.Insecure = false
					out.TLS.Certificate = in.TLS.Certificate
					client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				} else {
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					local := portAddress("127.0.0.1", unusedPort(t))
					startHysteria1Reference(t, map[string]any{"server": server.Address("server"), "protocol": "wechat-video", "up_mbps": 100, "down_mbps": 100, "obfs": string(in.Obfs), "auth_str": "private", "server_name": "example.com", "ca": cert, "socks5": map[string]any{"listen": local}}, "client", local)
					front := testOutbound(t, Inbound{Type: "socks"}, local)
					front.Username, front.Password, front.UUID = "", "", ""
					client = newTestRuntime(t, Config{Outbounds: []Outbound{front}})
				}
				assertTCP(t, client)
				sizes := []int{1, 511, 4096}
				if direction == "server" {
					sizes = []int{1, 511, 4000}
				}
				assertUDPSizes(t, client, sizes)
			})
		}
	}
}

func TestHysteriaWechatOfficialWire(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	listener.SetReadDeadline(time.Now().Add(5 * time.Second))
	startHysteria1Reference(t, map[string]any{"server": listener.LocalAddr().String(), "protocol": "wechat-video", "up_mbps": 100, "down_mbps": 100, "auth_str": "private", "insecure": true, "socks5": map[string]any{"listen": portAddress("127.0.0.1", unusedPort(t))}}, "client", "")
	buffer := make([]byte, 65535)
	var first uint32
	for i := range 3 {
		n, _, err := listener.ReadFrom(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if n < 1213 || !bytes.Equal(buffer[:2], wechatHeader[:2]) || !bytes.Equal(buffer[6:13], wechatHeader[6:]) {
			t.Fatal("official wire header mismatch", hex.EncodeToString(buffer[:min(n, 13)]))
		}
		seq := binary.BigEndian.Uint32(buffer[2:6])
		if i == 0 {
			first = seq
		} else if seq != first+uint32(i) {
			t.Fatal("official sequence mismatch", first, seq)
		}
	}
}

func FuzzWechatReceive(f *testing.F) {
	for _, seed := range [][]byte{nil, {1}, make([]byte, 13), append(make([]byte, 13), 1), bytes.Repeat([]byte{0xff}, 1400)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 65535 {
			return
		}
		c := newWechatConn(&wechatTestConn{packets: [][]byte{packet}})
		buffer := make([]byte, len(packet))
		n, err := c.Read(buffer)
		if len(packet) <= 13 {
			if n != 0 || err != io.EOF {
				t.Fatal(n, err)
			}
			return
		}
		if err != nil || !bytes.Equal(buffer[:n], packet[13:]) {
			t.Fatal("payload mismatch", n, err)
		}
	})
}

func BenchmarkWechatWrite(b *testing.B) {
	payload := make([]byte, 1200)
	send := func(p []byte) (int, error) { return len(p), nil }
	writeWechat(payload, 0, send)
	b.ReportAllocs()
	b.SetBytes(1200)
	b.ResetTimer()
	for i := range b.N {
		if _, err := writeWechat(payload, uint32(i), send); err != nil {
			b.Fatal(err)
		}
	}
}
