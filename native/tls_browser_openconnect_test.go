package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestBrowserOCTLSExporter(t *testing.T) {
	f := newMutualTLSFixture(t)
	for _, profile := range []string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"} {
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			t.Run(profile+"/"+tls.VersionName(version), func(t *testing.T) {
				o := f.client()
				o.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
				cfg, err := o.config(false, "example.com")
				if err != nil {
					t.Fatal(err)
				}
				server, err := f.server().config(true, "")
				if err != nil {
					t.Fatal(err)
				}
				server.MinVersion, server.MaxVersion = version, version
				server.CurvePreferences = []tls.CurveID{tls.CurveP256}
				a, b := kernelTLSTCPPair(t)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				state := make(chan tls.ConnectionState, 1)
				done := make(chan error, 1)
				go func() {
					defer b.Close()
					s := tls.Server(b, server)
					err := s.HandshakeContext(ctx)
					if err == nil {
						state <- s.ConnectionState()
						_, err = io.Copy(s, s)
					}
					done <- err
				}()
				c, err := handshakeOCTLS(ctx, a, cfg, o, false)
				if err != nil {
					t.Fatal(err)
				}
				peer := <-state
				wrapped := &bufferedConn{Conn: c, reader: bufio.NewReader(c)}
				for _, context := range [][]byte{nil, {}, []byte("bound\x00context")} {
					for _, length := range []int{0, 1, 32, 512} {
						want, err := peer.ExportKeyingMaterial("EXPORTER-test", context, length)
						if err != nil {
							t.Fatal(err)
						}
						got, err := tlsExport(wrapped, "EXPORTER-test", context, length)
						if err != nil || !bytes.Equal(got, want) {
							t.Fatal("exporter/context mismatch", length, err)
						}
					}
				}
				if version == tls.VersionTLS13 {
					inner := (*c.(*kernelTLSHandshake).secure.Load()).(*realityConn)
					inner.writeMu.Lock()
					err = inner.updateWriteKey()
					inner.writeMu.Unlock()
					if err != nil {
						t.Fatal(err)
					}
				}
				payload := []byte("exporter survives key update")
				if err := writeAll(c, payload); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, payload) {
					t.Fatal("key update echo", err)
				}
				want, err := peer.ExportKeyingMaterial("EXPORTER-openconnect-psk", nil, 32)
				got, err2 := ocExporter(c)
				if err != nil || err2 != nil || !bytes.Equal(got, want) {
					t.Fatal("OpenConnect exporter mismatch", err, err2)
				}
				for _, label := range []string{"client finished", "server finished", "master secret", "key expansion"} {
					if _, err := tlsExport(c, label, nil, 32); err == nil {
						t.Fatal("reserved exporter label accepted")
					}
				}
				for _, length := range []int{-1, 65536} {
					if _, err := tlsExport(c, "test", nil, length); err == nil {
						t.Fatal("invalid exporter length accepted")
					}
				}
				if err := c.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				c.Close()
				if _, err := ocExporter(c); !errors.Is(err, net.ErrClosed) && version == tls.VersionTLS13 || err == nil {
					t.Fatal("closed exporter accepted", err)
				}
			})
		}
	}
}

func TestBrowserOpenConnectTunnel(t *testing.T) {
	for _, profile := range []string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"} {
		for _, version := range []string{"1.2", "1.3"} {
			for _, dtls := range []string{"1.2", "1.3"} {
				t.Run(fmt.Sprintf("%s/TLS%s/DTLS%s", profile, version, dtls), func(t *testing.T) {
					in := Inbound{Type: "openconnect", Tag: "server", Listen: "127.0.0.1", Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t), OpenConnectOptions: OpenConnectOptions{DTLSVersion: dtls, RekeyMethod: "ssl", RekeyTime: "3600s"}}
					in.TLS.MinVersion, in.TLS.MaxVersion = version, version
					if version == "1.3" {
						in.RekeyTime, in.RekeyMethod = "", ""
					}
					s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					o := testOutbound(t, in, s.Address("server"))
					o.Username, o.Password = "client", "private"
					o.DTLSVersion = dtls
					o.TLS.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
					c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					tunnel, err := c.ocClients[o.Tag].session(ctx)
					if err != nil {
						t.Fatal(err)
					}
					d := ocWaitDTLS(t, tunnel)
					assertTCP(t, c)
					assertUDPSizes(t, c, []int{0, 1, 4096, 60000})
					if version == "1.2" {
						secured := ocCSTPTLS(tunnel.conn)
						if secured == nil || tunnel.rekeyMethod != "ssl" {
							t.Fatal("lost in-place CSTP rekey")
						}
						before, err := ocExporter(tunnel.conn)
						if err != nil {
							t.Fatal(err)
						}
						for range 2 {
							if err := secured.renegotiate(ctx); err != nil {
								t.Fatal(err)
							}
							assertTCP(t, c)
							assertUDPSizes(t, c, []int{1, 4096})
						}
						after, err := ocExporter(tunnel.conn)
						if err != nil || bytes.Equal(before, after) || c.ocClients[o.Tag].tunnel.Load() != tunnel || ocWaitDTLS(t, tunnel) != d {
							t.Fatal("CSTP was replaced or exporter did not rotate", err)
						}
					}
					// A new DTLS handshake must bind to the current CSTP exporter.
					d.conn.Close()
					deadline := time.Now().Add(5 * time.Second)
					for time.Now().Before(deadline) {
						tunnel.dtlsMu.Lock()
						next := tunnel.dtls
						tunnel.dtlsMu.Unlock()
						if next != nil && next != d && next.ready.Load() {
							d = next
							break
						}
						time.Sleep(10 * time.Millisecond)
					}
					if !d.ready.Load() {
						t.Fatal("DTLS could not renew")
					}
					assertUDPSizes(t, c, []int{1, 4096})
				})
			}
		}
	}
}
