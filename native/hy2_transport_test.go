package native

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func hy2PluginInbound(t *testing.T) Inbound {
	t.Helper()
	in := testInbound(t, "shadowsocks")
	in.TLS = certificate(t)
	in.Plugin = "v2ray-plugin"
	in.PluginOpts = "server;mode=hysteria2;host=example.com;password=transport-secret"
	return in
}

func hy2PluginOutbound(t *testing.T, in Inbound, address string) Outbound {
	t.Helper()
	o := testOutbound(t, in, address)
	o.TLS = TLSOptions{Enabled: true, Certificate: in.TLS.Certificate, ServerName: "example.com"}
	o.Plugin, o.PluginOpts = in.Plugin, strings.TrimPrefix(in.PluginOpts, "server;")
	return o
}

func TestHY2PluginIndependent(t *testing.T) {
	for _, method := range []string{"aes-256-cfb", "aes-128-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-chacha20-poly1305"} {
		t.Run(method, func(t *testing.T) {
			in := hy2PluginInbound(t)
			in.Method = method
			if isSS2022(method) {
				in.Password = "BwcHBwcHBwcHBwcHBwcHBw=="
				if strings.Contains(method, "chacha") {
					in.Password = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="
				}
			}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			o := hy2PluginOutbound(t, in, s.Address(in.Tag))
			o.Password = in.Password
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			assertTCP(t, c)
			assertTCP(t, c)
			if conn, err := c.Dial(context.Background(), "udp", echoUDP(t)); err == nil {
				conn.Close()
				t.Fatal("transport-only plugin exposed raw SS UDP")
			}
			c.resetNetworkTransports()
			assertTCP(t, c)
			for _, cfg := range []Config{s.config, c.config} {
				b, err := json.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = Parse(b); err != nil {
					t.Fatal("saved plugin configuration cannot reload", err)
				}
			}
		})
	}
}

func TestHY2PluginAuthentication(t *testing.T) {
	for _, mode := range []string{"password", "missing-password", "ss-password", "wrong-host", "untrusted", "detour", "mutual"} {
		t.Run(mode, func(t *testing.T) {
			in := hy2PluginInbound(t)
			var mutual mutualTLSFixture
			if mode == "mutual" {
				mutual = newMutualTLSFixture(t)
				in.TLS = mutual.server()
			}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			o := hy2PluginOutbound(t, in, s.Address(in.Tag))
			switch mode {
			case "password":
				o.PluginOpts = "mode=hysteria2;host=example.com;password=wrong"
			case "missing-password":
				o.PluginOpts = "mode=hysteria2;host=example.com"
			case "ss-password":
				o.Password = "wrong"
			case "wrong-host":
				o.TLS.ServerName = "wrong.example"
			case "untrusted":
				o.TLS.Certificate = nil
			case "detour":
				o.Detour = "deny"
			case "mutual":
				o.TLS = mutual.client()
			}
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o, {Type: "block", Tag: "deny"}}})
			if mode == "mutual" {
				assertTCP(t, c)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := c.Dial(ctx, "tcp", relayEchoTCP(t))
			if err == nil {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
				err = writeAll(conn, []byte("must not forward"))
				if err == nil {
					_, err = conn.Read(make([]byte, 16))
				}
			}
			if err == nil {
				t.Fatal("invalid authentication bypassed transport")
			}
		})
	}
}

func TestHY2PluginCertificatesAndOptions(t *testing.T) {
	in := hy2PluginInbound(t)
	block, _ := pem.Decode([]byte(in.TLS.Certificate[0]))
	if block == nil {
		t.Fatal("missing certificate fixture")
	}
	raw := strings.Join(strings.Fields(strings.TrimSuffix(strings.TrimPrefix(string(pem.EncodeToMemory(block)), "-----BEGIN CERTIFICATE-----"), "-----END CERTIFICATE-----\n")), "")
	dir := t.TempDir()
	key := filepath.Join(dir, "server.key")
	cert := filepath.Join(dir, "server.pem")
	for name, value := range map[string]string{key: in.TLS.Key[0], cert: in.TLS.Certificate[0]} {
		if err := os.WriteFile(name, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	in.TLS = TLSOptions{}
	in.PluginOpts += ";certRaw=" + raw + ";key=" + key + ";path=/ignored;mux=ignored"
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := testOutbound(t, in, s.Address(in.Tag))
	o.Plugin = "v2ray-plugin"
	o.PluginOpts = "mode=hysteria2;host=example.com;password=transport-secret;certRaw=" + raw
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	assertTCP(t, c)
	o.PluginOpts = "mode=hysteria2;host=example.com;password=transport-secret;cert=" + cert + ";certRaw=invalid"
	c = newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	assertTCP(t, c)
	for _, options := range []string{"mode=hysteria2;unknown=yes", "mode=quic;password=secret", "mode=websocket;password=secret", "mode=hysteria2;certRaw=broken", "mode=hysteria2;tls=yes", "mode=hysteria2;host=bad host", "mode=hysteria2;password=" + strings.Repeat("x", 4097)} {
		p := SIP003Options{Plugin: "v2ray-plugin", PluginOpts: options}
		if p.prepare("shadowsocks", Transport{}, TLSOptions{}, false) == nil {
			t.Fatal("invalid options accepted", options[:min(len(options), 50)])
		}
	}
	p := SIP003Options{Plugin: "v2ray-plugin", PluginOpts: "mode=hysteria2"}
	if p.prepare("shadowsocks", Transport{}, TLSOptions{MaxVersion: "1.2"}, false) == nil {
		t.Fatal("TLS1.2 accepted for QUIC")
	}
}

func TestHY2PluginConcurrentLifecycle(t *testing.T) {
	in := hy2PluginInbound(t)
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := hy2PluginOutbound(t, in, s.Address(in.Tag))
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	target := relayEchoTCP(t)
	var workers sync.WaitGroup
	for i := range 16 {
		workers.Go(func() {
			conn, err := c.Dial(context.Background(), "tcp", target)
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(4 * time.Second))
			want := bytes.Repeat([]byte{byte(i)}, 70000)
			written := make(chan error, 1)
			go func() { written <- writeAll(conn, want) }()
			got := make([]byte, len(want))
			_, err = io.ReadFull(conn, got)
			if err != nil || !bytes.Equal(got, want) {
				t.Error("crossed HY2 plugin streams", err)
			}
			if err = <-written; err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if conn, err := c.Dial(ctx, "tcp", target); err == nil {
		conn.Close()
		t.Fatal("canceled dial succeeded")
	}
	conn, err := c.Dial(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	if err = writeAll(conn, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatal("active stream", err)
	}
	done := make(chan struct{})
	go func() { c.Close(); s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("retained transport workers")
	}
	if _, err = conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("active stream survived runtime close")
	}
}

func TestHY2PluginTransportDeadline(t *testing.T) {
	in := hy2PluginInbound(t)
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := hy2PluginOutbound(t, in, s.Address(in.Tag))
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, err := c.quicTransports[o.Tag].dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetReadDeadline(time.Now().Add(-time.Second))
	if _, err := raw.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("transport read deadline", err)
	}
	raw.SetDeadline(time.Now().Add(time.Second))
	conn := newSSConn(raw, c.keys["out:"+o.Tag], &c.replay)
	address, err := encodeAddress(relayEchoTCP(t))
	if err != nil {
		t.Fatal(err)
	}
	if err = writeAll(conn, append(address, []byte("after-deadline")...)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len("after-deadline"))
	if _, err = io.ReadFull(conn, b); err != nil || string(b) != "after-deadline" {
		t.Fatal("transport deadline recovery", err)
	}
}

func TestHY2PluginAuthorizationGate(t *testing.T) {
	in := hy2PluginInbound(t)
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := hy2PluginOutbound(t, in, s.Address(in.Tag))
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	q, err := c.quicTransports[o.Tag].connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	go receiveHY2TransportStreams(q)
	stream, err := q.OpenStream(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeAll(stream, quicVar(nil, 0x401)); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(time.Second))
		accepted <- struct{}{}
		body := make([]byte, len("authorized"))
		_, err = io.ReadFull(conn, body)
		if err == nil {
			err = writeAll(conn, body)
		}
		done <- err
	}()
	ss := newSSConn(stream, c.keys["out:"+o.Tag], &c.replay)
	address, err := encodeAddress(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err = writeAll(ss, append(address, []byte("authorized")...)); err != nil {
		t.Fatal(err)
	}
	stream.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, err = stream.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("unauthenticated stream was served", err)
	}
	select {
	case <-accepted:
		t.Fatal("unauthenticated stream dialed upstream")
	default:
	}
	stream.SetDeadline(time.Now().Add(time.Second))
	session := quicProxySession{conn: q}
	if err = session.authenticateHY2(ctx, Outbound{Password: "transport-secret"}); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len("authorized"))
	if _, err = io.ReadFull(ss, b); err != nil || string(b) != "authorized" {
		t.Fatal("authenticated queued stream", err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestHY2PluginIPv6(t *testing.T) {
	in := hy2PluginInbound(t)
	in.Listen = "::1"
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	c := newTestRuntime(t, Config{Outbounds: []Outbound{hy2PluginOutbound(t, in, s.Address(in.Tag))}})
	assertTCP(t, c)
}

func TestHY2PluginHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(4 * time.Second))
		body, err := io.ReadAll(conn)
		if err == nil {
			err = writeAll(conn, body)
		}
		done <- err
	}()
	in := hy2PluginInbound(t)
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	c := newTestRuntime(t, Config{Outbounds: []Outbound{hy2PluginOutbound(t, in, s.Address(in.Tag))}})
	conn, err := c.Dial(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	want := bytes.Repeat([]byte("half-close"), 7000)
	if err = writeAll(conn, want); err != nil {
		t.Fatal(err)
	}
	if err = conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("truncated half-close response", len(got), err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
