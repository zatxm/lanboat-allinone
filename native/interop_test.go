package native

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func referenceRuntime(t *testing.T, config Config) {
	t.Helper()
	binary := os.Getenv("LANBOAT_TEST_REFERENCE")
	if binary == "" {
		t.Skip("LANBOAT_TEST_REFERENCE is required for independent implementation interoperability tests")
	}
	config.Log.Disabled = config.Log.Level == ""
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	// Adapt the native password spelling to the compatible legacy HY1 auth_str field.
	var document map[string]any
	if err = json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"inbounds", "outbounds"} {
		if nodes, ok := document[key].([]any); ok {
			for _, item := range nodes {
				node := item.(map[string]any)
				if key == "outbounds" {
					if options, ok := node["tls"].(map[string]any); ok && options["reality"] != nil {
						// The official client requires uTLS; the native client does
						// its own handshake and has no uTLS dependency.
						options["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
					}
				}
				if node["type"] != "hysteria" {
					continue
				}
				if pass, ok := node["password"]; ok {
					node["auth_str"] = pass
					delete(node, "password")
				}
				if users, ok := node["users"].([]any); ok {
					for _, item := range users {
						u := item.(map[string]any)
						u["auth_str"] = u["password"]
						delete(u, "password")
						delete(u, "uuid")
					}
				}
				delete(node, "uuid")
				delete(node, "username")
				for _, rate := range []string{"up_mbps", "down_mbps"} {
					if _, configured := node[rate]; !configured {
						node[rate] = 100
					}
				}
			}
		}
	}
	data, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "reference.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	logs, err := os.CreateTemp(t.TempDir(), "reference-log-*")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "run", "-c", path)
	command.Stdout, command.Stderr = logs, logs
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		command.Process.Kill()
		_ = command.Wait()
		logs.Close()
		if t.Failed() {
			if b, err := os.ReadFile(logs.Name()); err == nil {
				t.Log(string(b))
			}
		}
	})
	if len(config.Inbounds) == 0 {
		t.Fatal("reference needs an inbound")
	}
	address := portAddress(config.Inbounds[0].Listen, config.Inbounds[0].ListenPort)
	for range 200 {
		c, err := net.DialTimeout("tcp", address, 20*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("reference did not listen")
}

func unusedPort(t *testing.T, excluded ...uint16) uint16 {
	t.Helper()
	for range 32 {
		l, e := net.Listen("tcp", ":0")
		if e != nil {
			t.Fatal(e)
		}
		port := uint16(l.Addr().(*net.TCPAddr).Port)
		reserved := false
		for _, v := range excluded {
			if v == port {
				reserved = true
				break
			}
		}
		if reserved {
			l.Close()
			continue
		}
		p, e := net.ListenPacket("udp", portAddress("", port))
		if e == nil {
			p.Close()
			l.Close()
			return port
		}
		l.Close()
	}
	t.Fatal("no free TCP/UDP test port")
	return 0
}

func TestIndependentReferenceInterop(t *testing.T) {
	for _, test := range []struct{ kind, method string }{{"socks", ""}, {"http", ""}, {"shadowsocks", "aes-128-gcm"}, {"shadowsocks", "aes-192-gcm"}, {"shadowsocks", "aes-256-gcm"}, {"shadowsocks", "chacha20-ietf-poly1305"}, {"shadowsocks", "xchacha20-ietf-poly1305"}, {"trojan", ""}, {"vless", ""}, {"anytls", ""}} {
		kind := test.kind
		name := kind
		if test.method != "" {
			name += "/" + test.method
		}
		for _, direction := range []string{"client", "server"} {
			t.Run(name+"/"+direction, func(t *testing.T) {
				if os.Getenv("LANBOAT_TEST_REFERENCE") == "" {
					t.Skip("set LANBOAT_TEST_REFERENCE to an independent sing-box-compatible reference executable")
				}
				in := testInbound(t, kind)
				if test.method != "" {
					in.Method = test.method
				}
				var client *Runtime
				if direction == "client" {
					in.ListenPort = unusedPort(t)
					referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
					out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
					client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				} else {
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					out := testOutbound(t, in, server.Address("server"))
					// Keep only fields accepted by the reference for each protocol.
					switch kind {
					case "socks", "http":
						out.UUID = ""
					case "shadowsocks", "trojan", "anytls":
						out.UUID = ""
						out.Username = ""
					case "vless":
						out.Password = ""
						out.Username = ""
					}
					local := Inbound{Type: "mixed", Tag: "local", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
					referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{out}, Route: Route{Final: "proxy"}})
					front := testOutbound(t, local, portAddress(local.Listen, local.ListenPort))
					front.Username, front.Password, front.UUID, front.Method = "", "", "", ""
					client = newTestRuntime(t, Config{Outbounds: []Outbound{front}})
				}
				assertTCP(t, client)
				if kind != "http" {
					assertUDPSizes(t, client, []int{1, 511, 4096})
				}
			})
		}
	}
}

func TestHTTPConnectPreservesEarlyBytes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	want := "HTTP header and tunnel data share one TCP write"
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 1024)
		_, _ = c.Read(b)
		_ = writeAll(c, []byte("HTTP/1.1 200 Connection Established\r\n\r\n"+want))
		_, _ = io.Copy(io.Discard, c)
	}()
	out := testOutbound(t, Inbound{Type: "http"}, listener.Addr().String())
	out.Username, out.Password = "", ""
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := client.Dial(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, len(want))
	if _, err := io.ReadFull(c, b); err != nil || string(b) != want {
		t.Fatalf("lost tunneled bytes: %q %v", b, err)
	}
}
