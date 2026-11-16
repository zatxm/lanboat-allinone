//go:build linux

package native

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestHY2PluginReference(t *testing.T) {
	for _, mode := range []string{"password", "no-password", "open-server", "wrong-password"} {
		for _, side := range []string{"client", "server"} {
			t.Run(mode+"/"+side, func(t *testing.T) {
				serverPassword, clientPassword := "transport-secret", "transport-secret"
				if mode == "no-password" || mode == "open-server" {
					serverPassword = ""
				}
				if mode == "no-password" {
					clientPassword = ""
				}
				if mode == "wrong-password" {
					clientPassword = "wrong"
				}
				in := hy2PluginInbound(t)
				cert := in.TLS
				public := portAddress("127.0.0.1", unusedPort(t))
				var c *Runtime
				if side == "client" {
					in.TLS, in.Plugin, in.PluginOpts = TLSOptions{}, "", ""
					s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					startSIP003Reference(t, "hy2-server", public, s.Address(in.Tag), serverPassword, cert)
					in.TLS, in.Plugin = cert, "v2ray-plugin"
					in.PluginOpts = "mode=hysteria2;host=example.com;password=" + clientPassword
					c = newTestRuntime(t, Config{Outbounds: []Outbound{hy2PluginOutbound(t, in, public)}})
				} else {
					in.PluginOpts = "server;mode=hysteria2;host=example.com;password=" + serverPassword
					s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					startSIP003Reference(t, "hy2-client", public, s.Address(in.Tag), clientPassword, cert)
					o := testOutbound(t, in, public)
					o.TLS = TLSOptions{}
					c = newTestRuntime(t, Config{Outbounds: []Outbound{o}})
				}
				if mode != "wrong-password" {
					assertTCP(t, c)
					assertTCP(t, c)
					c.resetNetworkTransports()
					assertTCP(t, c)
					return
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				conn, err := c.Dial(ctx, "tcp", relayEchoTCP(t))
				if err == nil {
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(time.Second))
					err = writeAll(conn, []byte("must not forward"))
					if err == nil {
						_, err = io.ReadFull(conn, make([]byte, 16))
					}
				}
				if err == nil {
					t.Fatal("reference accepted wrong transport password")
				}
			})
		}
	}
}
