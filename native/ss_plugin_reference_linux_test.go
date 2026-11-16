//go:build linux

package native

import (
	"context"
	ctls "crypto/tls"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startSIP003Reference(t *testing.T, kind, listen, target, mask string, tls TLSOptions) {
	t.Helper()
	dir := os.Getenv("LANBOAT_TEST_SIP003")
	if dir == "" {
		t.Skip("LANBOAT_TEST_SIP003 required for unmodified plugin reference processes")
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		t.Fatal(err)
	}
	rh, rp, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	var binary string
	var args []string
	quic := strings.HasPrefix(kind, "quic-")
	hy2 := strings.HasPrefix(kind, "hy2-")
	websocket := strings.HasPrefix(kind, "ws-")
	server := strings.HasSuffix(kind, "-server")
	if quic || websocket || hy2 {
		binary = filepath.Join(dir, "v2ray-plugin_linux_amd64")
		mode, mux := "quic", "0"
		if websocket {
			mode, mux = "websocket", mask
		} else if hy2 {
			mode = "hysteria2"
		}
		args = []string{"-mode", mode, "-mux", mux, "-localAddr", host, "-localPort", port, "-remoteAddr", rh, "-remotePort", rp, "-host", "example.com", "-loglevel", "warning"}
		if hy2 {
			args = append(args, "-password", mask)
		}
		if websocket {
			args = append(args, "-path", "/plugin")
		}
		if tls.Enabled {
			args = append(args, "-tls")
		}
		if tls.Enabled || quic || hy2 {
			cert := filepath.Join(t.TempDir(), "server.pem")
			if err := os.WriteFile(cert, []byte(strings.Join(tls.Certificate, "\n")), 0600); err != nil {
				t.Fatal(err)
			}
			args = append(args, "-cert", cert)
			if server {
				key := filepath.Join(t.TempDir(), "server.key")
				if err := os.WriteFile(key, []byte(strings.Join(tls.Key, "\n")), 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-server", "-key", key)
			}
		} else if server {
			args = append(args, "-server")
		}
	} else {
		binary = filepath.Join(dir, "root/usr/bin", kind)
		if server {
			args = []string{"--obfs", mask, "-s", host, "-p", port, "-r", target}
		} else {
			args = []string{"--obfs", mask, "-s", rh, "-p", rp, "-l", port, "-b", host, "--obfs-host", "cdn.example"}
		}
	}
	log, err := os.Create(filepath.Join(t.TempDir(), "plugin.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+filepath.Join(dir, "root/usr/lib/x86_64-linux-gnu"))
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		log.Close()
		if t.Failed() {
			data, _ := os.ReadFile(log.Name())
			t.Log(string(data))
		}
	})
	if (quic || hy2) && server {
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			raw, err := net.Dial("udp", listen)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			q, err := dialQUIC(ctx, context.Background(), raw, &ctls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}})
			cancel()
			if err == nil {
				q.Close()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("reference QUIC handshake did not become ready")
	}
	for range 100 {
		c, err := net.DialTimeout("tcp", listen, 20*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("plugin reference did not listen", fmt.Sprint(args))
}

func TestWebSocketPluginReference(t *testing.T) {
	for _, secured := range []bool{false, true} {
		for _, mux := range []string{"0", "1", "8"} {
			for _, side := range []string{"client", "server"} {
				t.Run(fmt.Sprint(secured, "/", mux, "/", side), func(t *testing.T) {
					in := testInbound(t, "shadowsocks")
					cert := TLSOptions{}
					if secured {
						cert = certificate(t)
					}
					public := portAddress("127.0.0.1", unusedPort(t))
					var c *Runtime
					options := "mode=websocket;host=example.com;path=/plugin;mux=" + mux
					if side == "client" {
						s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						startSIP003Reference(t, "ws-server", public, s.Address("server"), mux, cert)
						o := testOutbound(t, in, public)
						o.TLS = TLSOptions{Enabled: secured, Insecure: true, ServerName: "example.com"}
						o.SIP003Options = SIP003Options{Plugin: "v2ray-plugin", PluginOpts: options}
						c = newTestRuntime(t, Config{Outbounds: []Outbound{o}})
					} else {
						in.TLS = cert
						in.SIP003Options = SIP003Options{Plugin: "v2ray-plugin", PluginOpts: "server;" + options}
						s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						startSIP003Reference(t, "ws-client", public, s.Address("server"), mux, cert)
						o := testOutbound(t, in, public)
						o.TLS = TLSOptions{}
						c = newTestRuntime(t, Config{Outbounds: []Outbound{o}})
					}
					assertTCP(t, c)
					assertTCP(t, c)
				})
			}
		}
	}
}

func TestSimpleObfsReference(t *testing.T) {
	for _, mask := range []string{"http", "tls"} {
		for _, side := range []string{"client", "server"} {
			t.Run(mask+"/"+side, func(t *testing.T) {
				in := testInbound(t, "shadowsocks")
				public := portAddress("127.0.0.1", unusedPort(t))
				var c *Runtime
				if side == "client" {
					s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					startSIP003Reference(t, "obfs-server", public, s.Address("server"), mask, TLSOptions{})
					out := testOutbound(t, in, public)
					out.SIP003Options = SIP003Options{Plugin: "obfs-local", PluginOpts: "obfs=" + mask + ";obfs-host=cdn.example"}
					c = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				} else {
					in.SIP003Options = SIP003Options{Plugin: "obfs-local", PluginOpts: "obfs=" + mask}
					s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					startSIP003Reference(t, "obfs-local", public, s.Address("server"), mask, TLSOptions{})
					out := testOutbound(t, in, public)
					c = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				}
				assertTCP(t, c)
			})
		}
	}
}

func TestQUICTransportPluginReference(t *testing.T) {
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			in := testInbound(t, "shadowsocks")
			cert := certificate(t)
			public := portAddress("127.0.0.1", unusedPort(t))
			var c *Runtime
			if side == "client" {
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				startSIP003Reference(t, "quic-server", public, s.Address("server"), "", cert)
				out := testOutbound(t, in, public)
				out.TLS = TLSOptions{Enabled: true, Insecure: true, ServerName: "example.com"}
				out.SIP003Options = SIP003Options{Plugin: "v2ray-plugin", PluginOpts: "mode=quic;host=example.com"}
				c = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			} else {
				in.TLS = cert
				in.SIP003Options = SIP003Options{Plugin: "v2ray-plugin", PluginOpts: "server;mode=quic;host=example.com"}
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				startSIP003Reference(t, "quic-client", public, s.Address("server"), "", cert)
				out := testOutbound(t, in, public)
				out.TLS = TLSOptions{}
				c = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			}
			assertTCP(t, c)
		})
	}
}
