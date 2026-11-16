package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func masqueCleartextPair(t *testing.T, version int, mode string) (*Runtime, *Runtime) {
	t.Helper()
	s := masqueEndpointRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": []int{1, 2}, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "users": []User{{Username: "client", Password: "private"}}})
	host, port, _ := net.SplitHostPort(s.Address("server"))
	p, _ := shadowPort(port)
	if mode == "ip" {
		return s, masqueEndpointRuntime(t, map[string]any{"type": "masque-client", "tag": "proxy", "server": host, "server_port": p, "username": "client", "password": "private", "version": version, "disable_version_fallback": true})
	}
	return s, newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "masque", Tag: "proxy", Server: host, ServerPort: p, Username: "client", Password: "private", HTTPVersion: version, MasqueOptions: MasqueOptions{Mode: mode, DisableVersionFallback: true}}}})
}

func TestMasqueCleartext(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, mode := range []string{"ip", "udp"} {
			t.Run(fmt.Sprintf("%d/%s", version, mode), func(t *testing.T) {
				_, c := masqueCleartextPair(t, version, mode)
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{0, 1, 511, 4096, 60000})
				assertUDPAddress(t, c, []int{1, 4096}, masqueEcho(t, "udp", "[::1]:0"))
				var jobs sync.WaitGroup
				for range 8 {
					jobs.Go(func() { assertTCP(t, c) })
				}
				jobs.Wait()
				conn, err := c.Dial(context.Background(), "udp", echoUDP(t))
				if err != nil {
					t.Fatal(err)
				}
				conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
				if _, err = conn.Read(make([]byte, 1)); !os.IsTimeout(err) {
					t.Fatal("read deadline ignored", err)
				}
				conn.Close()
				if version == 2 {
					client := c.masqueClients["proxy"]
					if got := client.session.http.MaxConnsPerHost; got != 1 {
						t.Fatal("HTTP2 connection pooling changed", got)
					}
				}
				c.resetNetworkTransports()
				assertTCP(t, c)
			})
		}
	}
}

func TestMasqueCleartextFallback(t *testing.T) {
	s := masqueEndpointRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": 1, "address": []string{"10.44.0.1/24"}})
	host, port, _ := net.SplitHostPort(s.Address("server"))
	p, _ := shadowPort(port)
	c := masqueEndpointRuntime(t, map[string]any{"type": "masque-client", "tag": "proxy", "server": host, "server_port": p, "version": 2})
	assertTCP(t, c)
	if got := c.masqueClients["proxy"].session.version; got != 1 {
		t.Fatal("cleartext fallback did not select HTTP1", got)
	}
	assertUDPAddress(t, c, []int{1, 4096}, echoUDP(t))
}

func TestMasqueCleartextLifecycle(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, mode := range []string{"ip", "udp"} {
			t.Run(fmt.Sprintf("%d/%s", version, mode), func(t *testing.T) {
				s, c := masqueCleartextPair(t, version, mode)
				conn, err := c.Dial(context.Background(), "udp", echoUDP(t))
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err = conn.Write([]byte("live")); err != nil {
					t.Fatal(err)
				}
				if _, err = conn.Read(make([]byte, 32)); err != nil {
					t.Fatal(err)
				}
				blocked := make(chan error, 1)
				go func() { _, e := conn.Read(make([]byte, 32)); blocked <- e }()
				stopped := make(chan struct{})
				go func() { c.Close(); s.Close(); close(stopped) }()
				select {
				case <-stopped:
				case <-time.After(2 * time.Second):
					t.Fatal("runtime close blocked")
				}
				select {
				case err := <-blocked:
					if err == nil {
						t.Fatal("read survived close")
					}
				case <-time.After(time.Second):
					t.Fatal("reader leaked")
				}
			})
		}
	}
}

func TestMasqueCleartextConfig(t *testing.T) {
	for _, version := range []int{0, 1, 2, 3, 4} {
		o := MasqueOptions{}
		if err := o.validate("masque", TLSOptions{}, version, 0, nil, false); (err == nil) != (version == 1 || version == 2) {
			t.Fatal(version, err)
		}
	}
	for _, options := range []TLSOptions{{Insecure: true}, {ServerName: "vpn.test"}, {ClientAuthentication: "require-and-verify"}, {ClientCertificate: []string{"ignored"}}, {CertificatePublicKeySHA256: []string{"ignored"}}, {Reality: &RealityOptions{Enabled: true}}} {
		o := MasqueOptions{}
		if err := o.validate("masque", options, 2, 0, nil, false); err == nil {
			t.Fatal("disabled TLS options accepted", options)
		}
	}
	for _, versions := range [][]int{nil, {3}, {1, 3}, {1, 2, 3}} {
		b, _ := json.Marshal(map[string]any{"endpoints": []any{map[string]any{"type": "masque-server", "version": versions, "address": []string{"10.44.0.1/24"}}}})
		if _, err := Parse(b); err == nil {
			t.Fatal("HTTP3 accepted without TLS", versions)
		}
	}
	if _, err := Parse([]byte(`{"inbounds":[{"type":"masque","http_version":1}]}`)); err == nil {
		t.Fatal("extension lost its authentication requirement")
	}
}

func TestMasqueCleartextAuthentication(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			_, c := masqueCleartextPair(t, version, "ip")
			client := c.masqueClients["proxy"]
			client.outbound.Password = "wrong"
			client.outbound.DisableVersionFallback = false
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := c.Dial(ctx, "tcp", relayEchoTCP(t))
			if err == nil {
				conn.Close()
				t.Fatal("wrong credentials accepted")
			}
			if client.session.version != version {
				t.Fatal("authentication failure caused fallback")
			}
		})
	}
}

func TestMasqueCleartextNeverTLSFallback(t *testing.T) {
	var mu sync.Mutex
	var prefixes []byte
	sink, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := sink.Accept()
			if err != nil {
				return
			}
			conn.SetDeadline(time.Now().Add(time.Second))
			var b [1]byte
			if _, err := io.ReadFull(conn, b[:]); err == nil {
				mu.Lock()
				prefixes = append(prefixes, b[0])
				mu.Unlock()
			}
			conn.Close()
		}
	}()
	host, text, _ := net.SplitHostPort(sink.Addr().String())
	port, _ := shadowPort(text)
	c := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "masque", Tag: "proxy", Server: host, ServerPort: port, HTTPVersion: 2, Username: "client", Password: "private", TLS: TLSOptions{Enabled: true, Insecure: true}}}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if conn, err := c.Dial(ctx, "tcp", "127.0.0.1:1"); err == nil {
		conn.Close()
		t.Fatal("unexpected tunnel")
	}
	sink.Close()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(prefixes) < 2 {
		t.Fatal("fallback was not exercised", prefixes)
	}
	for _, b := range prefixes {
		if b != 0x16 {
			t.Fatal("TLS failure sent unencrypted credentials", prefixes)
		}
	}
}

func TestMasqueCleartextHeaderScheme(t *testing.T) {
	for _, scheme := range []string{"http", "https", "ftp", ""} {
		fields := [][2]string{{":method", "CONNECT"}, {":protocol", "connect-ip"}, {":authority", "vpn.test"}, {":scheme", scheme}, {":path", "/vpn"}}
		_, err := masqueRewriteHeaders(fields)
		if (err == nil) != (scheme == "http" || scheme == "https") {
			t.Fatal(scheme, err)
		}
		for _, secure := range []bool{false, true} {
			wire := &masqueHTTPWire{reader: bufio.NewReader(bytes.NewReader(nil)), decoder: masqueHPACK{limit: 4096}}
			expected := "http"
			if secure {
				wire.tls = new(tls.Conn)
				expected = "https"
			}
			block, _ := masqueLiteralHeaders(fields)
			_, err = wire.headers(masqueH2Frame(1, 4, 1, block))
			if (err == nil) != (scheme == expected) {
				t.Fatal("scheme does not match wire security", scheme, secure, err)
			}
		}
	}
}
