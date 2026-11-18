package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func visionPair(t *testing.T) (*Runtime, *Runtime) {
	t.Helper()
	in := testInbound(t, "vless")
	in.Users[0].Flow = visionFlow
	in.TLS = certificate(t)
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, s.Address("server"))
	out.Flow = visionFlow
	return s, newTestRuntime(t, Config{Outbounds: []Outbound{out}})
}
func visionHTTPS(t *testing.T, c *Runtime, version uint16, requireDirect bool, pacedPeer ...bool) {
	t.Helper()
	want := bytes.Repeat([]byte("Vision transfer\n"), 40000)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("credentials reached origin")
		}
		if len(pacedPeer) > 0 && pacedPeer[0] {
			// Some reference writers require a complete read batch before
			// switching. Keep a small record separate; bulk-only is tested too.
			time.Sleep(10 * time.Millisecond)
			w.Write(want[:64])
			w.(http.Flusher).Flush()
			time.Sleep(10 * time.Millisecond)
			w.Write(want[64:])
		} else {
			w.Write(want)
		}
	}))
	origin.TLS = &tls.Config{MinVersion: version, MaxVersion: version}
	origin.StartTLS()
	defer origin.Close()
	var connections []*visionConn
	var mu sync.Mutex
	tr := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: version, MaxVersion: version, InsecureSkipVerify: true}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, e := c.Dial(ctx, network, address)
		if e == nil {
			if own, ok := withoutConnectionLog(conn).(*ownedConn); ok {
				if v, ok := own.Conn.(*visionConn); ok {
					mu.Lock()
					connections = append(connections, v)
					mu.Unlock()
				}
			}
		}
		return conn, e
	}}
	defer tr.CloseIdleConnections()
	for range 2 {
		response, e := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get(origin.URL)
		if e != nil {
			t.Fatal(e)
		}
		got, e := io.ReadAll(response.Body)
		response.Body.Close()
		if e != nil || !bytes.Equal(got, want) {
			t.Fatal("TLS transfer", len(got), e)
		}
	}
	if requireDirect {
		if len(connections) != 2 {
			t.Fatal("Vision connection missing")
		}
		for _, v := range connections {
			if version == tls.VersionTLS13 {
				if !v.readDirect.Load() || !v.writeDirect.Load() {
					t.Fatal("TLS1.3 was not direct", v.readDirect.Load(), v.writeDirect.Load())
				}
			} else if v.readDirect.Load() || v.writeDirect.Load() {
				t.Fatal("TLS1.2 bypassed outer TLS")
			}
		}
	}
}
func TestVisionIndependent(t *testing.T) {
	_, c := visionPair(t)
	assertTCP(t, c)
	visionHTTPS(t, c, tls.VersionTLS13, true)
	visionHTTPS(t, c, tls.VersionTLS12, true)
	assertUDPSizes(t, c, []int{0, 1, 511, 4096, 60000})
	assertUDPAddress(t, c, []int{1, 4096}, masqueEcho(t, "udp", "[::1]:0"))
	c.resetNetworkTransports()
	visionHTTPS(t, c, tls.VersionTLS13, true)
}
func TestVisionReference(t *testing.T) {
	if os.Getenv("LANBOAT_TEST_XRAY") == "" {
		t.Fatal("LANBOAT_TEST_XRAY required")
	}
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			f := newMutualTLSFixture(t)
			dir := t.TempDir()
			cert, key := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
			os.WriteFile(cert, []byte(f.serverCert), 0600)
			os.WriteFile(key, []byte(f.serverKey), 0600)
			port := unusedPort(t)
			stream := map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"minVersion": "1.3", "serverName": "example.com", "certificates": []any{map[string]any{"certificateFile": cert, "keyFile": key}}}}
			cfg := map[string]any{"log": map[string]any{"loglevel": "debug"}}
			var c *Runtime
			if side == "client" {
				cfg["inbounds"] = []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "vless", "settings": map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": testUUID, "flow": visionFlow}}}, "streamSettings": stream}}
				cfg["outbounds"] = []any{map[string]any{"protocol": "freedom"}}
				xrayMuxReference(t, cfg, port)
				out := Outbound{Type: "vless", Tag: "proxy", Server: "127.0.0.1", ServerPort: port, UUID: testUUID, Flow: visionFlow, TLS: TLSOptions{Enabled: true, ServerName: "example.com", Certificate: []string{f.ca}}}
				c = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			} else {
				in := testInbound(t, "vless")
				in.Users[0].Flow = visionFlow
				in.TLS = TLSOptions{Enabled: true, Certificate: []string{f.serverCert}, Key: []string{f.serverKey}}
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				port = unusedPort(t)
				host, p, _ := net.SplitHostPort(s.Address("server"))
				n, _ := shadowPort(p)
				block, _ := pem.Decode([]byte(f.serverCert))
				digest := sha256.Sum256(block.Bytes)
				stream["tlsSettings"] = map[string]any{"minVersion": "1.3", "serverName": "example.com", "pinnedPeerCertSha256": hex.EncodeToString(digest[:])}
				cfg["inbounds"] = []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"udp": true}}}
				cfg["outbounds"] = []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": host, "port": n, "users": []any{map[string]any{"id": testUUID, "encryption": "none", "flow": visionFlow}}}}}, "streamSettings": stream}}
				xrayMuxReference(t, cfg, port)
				c = newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "front", Server: "127.0.0.1", ServerPort: port}}})
			}
			assertTCP(t, c)
			visionHTTPS(t, c, tls.VersionTLS13, false)
			visionHTTPS(t, c, tls.VersionTLS13, side == "client", true)
			visionHTTPS(t, c, tls.VersionTLS12, side == "client")
			assertUDPSizes(t, c, []int{1, 511, 4096})
			assertUDPAddress(t, c, []int{1, 4096}, masqueEcho(t, "udp", "[::1]:0"))
		})
	}
}

func TestVisionSingBoxReference(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if ref == "" {
		t.Fatal("LANBOAT_TEST_SINGBOX15 required")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", ref)
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			in := testInbound(t, "vless")
			in.TLS = certificate(t)
			in.Users[0].Flow = visionFlow
			var c *Runtime
			if side == "client" {
				in.ListenPort = unusedPort(t)
				referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
				out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
				out.Flow = visionFlow
				c = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			} else {
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out := testOutbound(t, in, s.Address("server"))
				out.Flow = visionFlow
				out.Username, out.Password = "", ""
				local := Inbound{Type: "mixed", Tag: "local", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
				referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{out}, Route: Route{Final: out.Tag}})
				front := testOutbound(t, Inbound{Type: "socks"}, portAddress(local.Listen, local.ListenPort))
				front.Username, front.Password = "", ""
				c = newTestRuntime(t, Config{Outbounds: []Outbound{front}})
			}
			assertTCP(t, c)
			visionHTTPS(t, c, tls.VersionTLS13, false)
			visionHTTPS(t, c, tls.VersionTLS13, side == "client", true)
			visionHTTPS(t, c, tls.VersionTLS12, side == "client")
			assertUDPSizes(t, c, []int{1, 511, 4096})
			assertUDPAddress(t, c, []int{1, 4096}, masqueEcho(t, "udp", "[::1]:0"))
		})
	}
}

func TestVisionServerHello(t *testing.T) {
	// RFC8446 layout, session ID0, AES128-GCM, selected TLS1.3.
	hello := append([]byte{3, 3}, make([]byte, 32)...)
	hello = append(hello, 0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4)
	if !visionServerHello(hello) {
		t.Fatal("valid TLS1.3 hello rejected")
	}
	for _, offset := range []int{0, 35, 37, 38, 41, 44} {
		bad := bytes.Clone(hello)
		bad[offset] ^= 255
		if visionServerHello(bad) {
			t.Fatal("malformed hello accepted", offset)
		}
	}
	handshake := append([]byte{2, 0, 0, byte(len(hello))}, hello...)
	record := append([]byte{22, 3, 3, 0, byte(len(handshake))}, handshake...)
	for split := 1; split < len(record); split++ {
		var p visionProbe
		var s visionState
		p.observe(record[:split], &s)
		p.observe(record[split:], &s)
		if !s.tls13.Load() {
			t.Fatal("split hello not recognized", split)
		}
	}
}
func TestVisionConcurrent(t *testing.T) {
	_, c := visionPair(t)
	var workers sync.WaitGroup
	for i := range 8 {
		workers.Go(func() { t.Run(fmt.Sprint(i), func(t *testing.T) { visionHTTPS(t, c, tls.VersionTLS13, true) }) })
	}
	workers.Wait()
}

func TestVisionTrust(t *testing.T) {
	s, c := visionPair(t)
	bad := c.config.Outbounds[0]
	bad.TLS.Insecure = false
	bad.TLS.ServerName = "wrong.example"
	client := newTestRuntime(t, Config{Outbounds: []Outbound{bad}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if conn, e := client.Dial(ctx, "tcp", s.Address("server")); e == nil {
		conn.Close()
		t.Fatal("untrusted server accepted")
	}
}
