package native

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func trojanSSOptions(method string) *TrojanShadowsocksOptions {
	return &TrojanShadowsocksOptions{Enabled: true, Method: method, Password: "inner-encryption-test-password"}
}

func TestTrojanShadowsocksIndependent(t *testing.T) {
	for _, method := range []string{"AES-128-GCM", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		for _, transport := range []string{"", "ws", "ws-early", "httpupgrade", "http", "grpc"} {
			t.Run(method+"/"+transport, func(t *testing.T) {
				in := testInbound(t, "trojan")
				in.Shadowsocks = trojanSSOptions(method)
				in.Transport = Transport{Type: transport}
				if transport == "ws-early" {
					in.Transport = Transport{Type: "ws", MaxEarlyData: 2048, EarlyDataHeaderName: "Sec-WebSocket-Protocol"}
				}
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out := testOutbound(t, in, server.Address("server"))
				out.Transport, out.Shadowsocks = in.Transport, in.Shadowsocks
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 511, 4096, 60000})
			})
		}
	}
}

func TestTrojanShadowsocksValidation(t *testing.T) {
	for _, opts := range []*TrojanShadowsocksOptions{
		{Enabled: true}, {Enabled: true, Method: "aes-256-cfb", Password: "p"},
		{Enabled: true, Method: "2022-blake3-aes-128-gcm", Password: "p"},
		{Enabled: true, Method: "unknown", Password: "p"},
	} {
		if err := opts.validate("trojan"); err == nil {
			t.Fatal("accepted unsupported Trojan-Go encryption")
		}
	}
	if err := (&TrojanShadowsocksOptions{}).validate("socks"); err == nil {
		t.Fatal("accepted encryption on a different protocol")
	}
	if err := (&TrojanShadowsocksOptions{Method: "inactive-choice"}).validate("trojan"); err != nil {
		t.Fatal("inactive settings should remain editable", err)
	}
	key, err := trojanSSOptions("").key()
	if err != nil || key.method != "aes-128-gcm" {
		t.Fatal("default cipher", err)
	}
	for _, side := range []string{"inbounds", "outbounds"} {
		protocol := "socks"
		if side == "outbounds" {
			protocol = "direct"
		}
		raw := `{"` + side + `":[{"type":"` + protocol + `","tag":"x","shadowsocks":{}}]}`
		if _, err := Parse([]byte(raw)); err == nil || !strings.Contains(err.Error(), "requires trojan") {
			t.Fatal("encryption scope validation", err)
		}
	}
}

func TestTrojanShadowsocksRejectCredentials(t *testing.T) {
	for _, bad := range []string{"encryption-password", "trojan-password", "disabled"} {
		t.Run(bad, func(t *testing.T) {
			in := testInbound(t, "trojan")
			in.Shadowsocks = trojanSSOptions("")
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Shadowsocks = trojanSSOptions("")
			switch bad {
			case "encryption-password":
				out.Shadowsocks.Password = "wrong-inner-password"
			case "trojan-password":
				out.Password = "wrong-user-password"
			case "disabled":
				out.Shadowsocks.Enabled = false
			}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			origin, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer origin.Close()
			origin.(*net.TCPListener).SetDeadline(time.Now().Add(400 * time.Millisecond))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			c, err := client.Dial(ctx, "tcp", origin.Addr().String())
			if err == nil {
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				c.Write([]byte("credential-rejection-test"))
				if _, err := c.Read(make([]byte, 1)); err == nil {
					t.Fatal("invalid credentials accepted")
				}
			}
			if c, err := origin.Accept(); err == nil {
				c.Close()
				t.Fatal("unauthenticated request reached origin")
			}
		})
	}
}

func trojanGoReference(t *testing.T, cfg map[string]any, port uint16) {
	t.Helper()
	binary := os.Getenv("LANBOAT_TEST_TROJAN_GO")
	if binary == "" {
		t.Fatal("LANBOAT_TEST_TROJAN_GO required for official Trojan-Go interoperability")
	}
	dir := t.TempDir()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(dir, "reference.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-config", path)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		log.Close()
		if t.Failed() {
			raw, _ := os.ReadFile(log.Name())
			t.Log(string(raw))
		}
	})
	for range 200 {
		c, err := net.DialTimeout("tcp", portAddress("127.0.0.1", port), 10*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Trojan-Go reference did not listen")
}

func TestTrojanShadowsocksReference(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		for _, transport := range []string{"", "ws"} {
			for _, direction := range []string{"client", "server"} {
				t.Run(method+"/"+transport+"/"+direction, func(t *testing.T) {
					in := testInbound(t, "trojan")
					in.Shadowsocks = trojanSSOptions(method)
					if transport != "" {
						in.Transport = Transport{Type: "ws", Path: "/encrypted-test", Host: "example.com"}
					}
					port := unusedPort(t)
					ref := map[string]any{"local_addr": "127.0.0.1", "local_port": port, "password": []string{"private"}, "disable_http_check": true,
						"shadowsocks": map[string]any{"enabled": true, "method": strings.ToUpper(method), "password": in.Shadowsocks.Password},
						"websocket":   map[string]any{"enabled": transport != "", "path": "/encrypted-test", "host": "example.com"}}
					var client *Runtime
					if direction == "client" {
						dir := t.TempDir()
						cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
						if err := os.WriteFile(cert, []byte(strings.Join(in.TLS.Certificate, "\n")), 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(key, []byte(strings.Join(in.TLS.Key, "\n")), 0600); err != nil {
							t.Fatal(err)
						}
						ref["run_type"], ref["remote_addr"], ref["remote_port"] = "server", "127.0.0.1", 80
						ref["ssl"] = map[string]any{"cert": cert, "key": key, "alpn": []string{"http/1.1"}}
						trojanGoReference(t, ref, port)
						out := testOutbound(t, in, portAddress("127.0.0.1", port))
						out.Shadowsocks, out.Transport = in.Shadowsocks, in.Transport
						client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
					} else {
						server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						host, p, _ := net.SplitHostPort(server.Address("server"))
						ref["run_type"], ref["remote_addr"] = "client", host
						remotePort, _ := strconv.Atoi(p)
						ref["remote_port"] = remotePort
						ref["ssl"] = map[string]any{"verify": false, "verify_hostname": false, "sni": "example.com"}
						trojanGoReference(t, ref, port)
						front := Outbound{Type: "socks", Tag: "front", Server: "127.0.0.1", ServerPort: port}
						client = newTestRuntime(t, Config{Outbounds: []Outbound{front}})
					}
					assertTCP(t, client)
					assertUDPSizes(t, client, []int{1, 511, 4096})
				})
			}
		}
	}
}

func TestTrojanShadowsocksLineSalt(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		key, _ := trojanSSOptions(method).key()
		seen := make(map[string]bool)
		for range 128 {
			var wire bytes.Buffer
			c := &ssConn{Conn: memoryNetConn{Reader: bytes.NewReader(nil), Writer: &wire}, key: key, replay: &replayWindow{}, lineSalt: true}
			if _, err := c.Write([]byte("encrypted Trojan")); err != nil {
				t.Fatal(err)
			}
			salt := wire.Bytes()[:len(key.master)]
			if !bytes.Contains(salt, []byte{'\n'}) || seen[string(salt)] {
				t.Fatal("line salt missing delimiter or repeated")
			}
			seen[string(salt)] = true
			reader := newSSConn(readerConn(wire.Bytes()), key, &replayWindow{})
			plain, err := io.ReadAll(reader)
			if err != nil || string(plain) != "encrypted Trojan" {
				t.Fatal("standard SIP004 reader rejected salt", err)
			}
		}
	}
}

func TestTrojanGoLegacyWebSocketText(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		left, right := net.Pipe()
		left.SetDeadline(time.Now().Add(time.Second))
		right.SetDeadline(time.Now().Add(time.Second))
		server := &websocketConn{Conn: left, legacyText: legacy}
		client := &websocketConn{Conn: right, client: true}
		done := make(chan error, 1)
		go func() { done <- client.writeFrame(1, []byte{255, 0, 128}) }()
		got := make([]byte, 3)
		_, err := io.ReadFull(server, got)
		left.Close()
		right.Close()
		<-done
		if legacy && (err != nil || !bytes.Equal(got, []byte{255, 0, 128})) {
			t.Fatal("Trojan-Go text compatibility", err)
		}
		if !legacy && err == nil {
			t.Fatal("enabled legacy text on normal WebSocket")
		}
	}
}
