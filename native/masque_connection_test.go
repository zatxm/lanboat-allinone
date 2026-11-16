package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMasqueConnectionConfig(t *testing.T) {
	for _, kind := range []string{"masque-client", "masque-server"} {
		for _, version := range []int{2, 3} {
			base := map[string]any{"type": kind, "tag": "proxy", "version": version, "tls": certificate(t)}
			if kind == "masque-client" {
				base["server"], base["server_port"] = "localhost", 443
				base["tls"] = TLSOptions{Enabled: true, Insecure: true}
			} else {
				base["address"] = []string{"10.44.0.1/24"}
			}
			check := func(extra string, valid bool) {
				t.Helper()
				b, _ := json.Marshal(base)
				raw := `{"endpoints":[` + strings.TrimSuffix(string(b), "}") + "," + extra + `}]}`
				if _, err := Parse([]byte(raw)); (err == nil) != valid {
					t.Fatalf("%s/%d %s: %v", kind, version, extra, err)
				}
			}
			for _, extra := range []string{`"initial_packet_size":1200,"disable_path_mtu_discovery":true`, `"initial_packet_size":1472`, `"initial_packet_size":0`, `"idle_timeout":"2s","keep_alive_period":"100ms"`, `"idle_timeout":"0s","keep_alive_period":"0s"`, `"stream_receive_window":"64 MB","connection_receive_window":"64MiB","max_concurrent_streams":8`, `"stream_receive_window":"1.5KiB","connection_receive_window":"65535"`, `"stream_receive_window":1048576,"connection_receive_window":2097152`} {
				check(extra, true)
			}
			for _, extra := range []string{`"initial_packet_size":1199`, `"initial_packet_size":1473`, `"initial_packet_size":-1`, `"idle_timeout":"-1s"`, `"idle_timeout":"1ns"`, `"keep_alive_period":"tomorrow"`, `"keep_alive_period":"25h"`, `"stream_receive_window":"NaN"`, `"stream_receive_window":"Inf"`, `"stream_receive_window":"64.01MiB"`, `"stream_receive_window":"1.5B"`, `"connection_receive_window":"4096"`, `"max_concurrent_streams":129`, `"max_concurrent_streams":-1`} {
				check(extra, false)
			}
		}
	}
}

func TestMasqueConnectionData(t *testing.T) {
	for _, version := range []int{2, 3} {
		for _, window := range []string{"1024", "2 MiB"} {
			t.Run(fmt.Sprintf("%d/%s", version, window), func(t *testing.T) {
				settings := func(ep map[string]any) map[string]any {
					ep["stream_receive_window"], ep["connection_receive_window"] = window, "3 MiB"
					ep["idle_timeout"], ep["keep_alive_period"], ep["max_concurrent_streams"] = "2s", "100ms", 4
					return ep
				}
				s := masqueEndpointRuntime(t, settings(map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": version, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "tls": certificate(t)}))
				host, port, _ := net.SplitHostPort(s.Address("server"))
				n, _ := shadowPort(port)
				c := masqueEndpointRuntime(t, settings(map[string]any{"type": "masque-client", "tag": "proxy", "server": host, "server_port": n, "version": version, "disable_version_fallback": true, "tls": TLSOptions{Enabled: true, Insecure: true}}))
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{1, 4096, 60000})
				assertUDPAddress(t, c, []int{1, 4096}, masqueEcho(t, "udp", "[::1]:0"))
				c.resetNetworkTransports()
				assertTCP(t, c)
			})
		}
	}
}

// Read the settings and PINGs that actually leave net/http's connection,
// rather than checking only the values passed into its configuration struct.
func TestMasqueConnectionHTTP2Wire(t *testing.T) {
	for _, client := range []bool{false, true} {
		t.Run(fmt.Sprintf("client-%t", client), func(t *testing.T) {
			var peer net.Conn
			if client {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				host, port, _ := net.SplitHostPort(listener.Addr().String())
				n, _ := shadowPort(port)
				c := masqueEndpointRuntime(t, map[string]any{"type": "masque-client", "tag": "proxy", "server": host, "server_port": n, "version": 2, "disable_version_fallback": true, "stream_receive_window": "2 MiB", "connection_receive_window": "3 MiB", "keep_alive_period": "30ms"})
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				done := make(chan struct{})
				go func() {
					defer close(done)
					conn, _ := c.Dial(ctx, "tcp", "127.0.0.1:1")
					if conn != nil {
						conn.Close()
					}
				}()
				t.Cleanup(func() { cancel(); c.Close(); <-done })
				listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
				peer, err = listener.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
				peer.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err = io.ReadFull(peer, make([]byte, len(masqueH2Preface))); err != nil {
					t.Fatal(err)
				}
				if err = writeAll(peer, healthFrame(4, 0, 0, []byte{0, 8, 0, 0, 0, 1})); err != nil {
					t.Fatal(err)
				}
			} else {
				s := masqueEndpointRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": 2, "address": []string{"10.44.0.1/24"}, "stream_receive_window": "2 MiB", "connection_receive_window": "3 MiB", "max_concurrent_streams": 4, "keep_alive_period": "30ms", "idle_timeout": "0s"})
				var err error
				peer, err = net.Dial("tcp", s.Address("server"))
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
				peer.SetDeadline(time.Now().Add(2 * time.Second))
				if err = writeAll(peer, append([]byte(masqueH2Preface), healthFrame(4, 0, 0, nil)...)); err != nil {
					t.Fatal(err)
				}
			}
			settings := map[uint16]uint32{}
			connectionWindow, pings := uint32(65535), 0
			for pings < 2 {
				frame, err := healthReadFrame(peer)
				if err != nil {
					t.Fatal(err, settings, pings)
				}
				switch frame[3] {
				case 4:
					if frame[4]&1 == 0 {
						for b := frame[9:]; len(b) >= 6; b = b[6:] {
							settings[binary.BigEndian.Uint16(b)] = binary.BigEndian.Uint32(b[2:])
						}
						if err := writeAll(peer, healthFrame(4, 1, 0, nil)); err != nil {
							t.Fatal(err)
						}
					}
				case 8:
					if binary.BigEndian.Uint32(frame[5:9]) == 0 {
						connectionWindow += binary.BigEndian.Uint32(frame[9:13])
					}
				case 6:
					if frame[4]&1 == 0 {
						pings++
						if err := writeAll(peer, healthFrame(6, 1, 0, frame[9:])); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			wantConnection := uint32(3 << 20)
			if client {
				wantConnection += 65535
			}
			if settings[4] != 2<<20 || connectionWindow != wantConnection || !client && settings[3] != 4 {
				t.Fatal("wire settings not applied", settings, connectionWindow)
			}
		})
	}
}

func TestMasqueConnectionHTTP2Idle(t *testing.T) {
	for _, idle := range []string{"50ms", "0s"} {
		t.Run(idle, func(t *testing.T) {
			s := masqueEndpointRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": 2, "address": []string{"10.44.0.1/24"}, "idle_timeout": idle})
			peer, err := net.Dial("tcp", s.Address("server"))
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			peer.SetDeadline(time.Now().Add(300 * time.Millisecond))
			if err = writeAll(peer, append([]byte(masqueH2Preface), healthFrame(4, 0, 0, nil)...)); err != nil {
				t.Fatal(err)
			}
			for {
				b, err := healthReadFrame(peer)
				if err != nil {
					if idle == "0s" && os.IsTimeout(err) {
						return
					}
					t.Fatal("no idle GOAWAY", err)
				}
				if b[3] == 7 {
					if idle == "0s" {
						t.Fatal("disabled idle eviction sent GOAWAY")
					}
					return
				}
			}
		})
	}
}

func FuzzMasqueConnectionSettings(f *testing.F) {
	for _, s := range []string{`{}`, `{"idle_timeout":"1s","stream_receive_window":"64 MB"}`, `{"keep_alive_period":"-1s"}`, `{"max_concurrent_streams":129}`, `{"initial_packet_size":1200,"disable_path_mtu_discovery":true}`, `{"initial_packet_size":1472}`, `{"initial_packet_size":1473}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var o masqueConnectionOptions
		if len(s) > 4096 || decodeOptions([]byte(s), &o) != nil {
			return
		}
		v, err := o.settings()
		if err != nil || v == nil {
			return
		}
		if v.streamWindow < 0 || v.streamWindow > 64<<20 || v.connWindow < 0 || v.connWindow > 64<<20 || v.streams < 0 || v.streams > 128 {
			t.Fatal(v)
		}
		q := v.quic()
		if q.initial < 1200 || q.initial > 1472 || q.discoverMTU == o.DisablePathMTUDiscovery {
			t.Fatal(q)
		}
	})
}

func TestQUICReceiveLargeWindow(t *testing.T) {
	var buffer quicBuffer
	want := bytes.Repeat([]byte("large-window"), 180000)
	for offset := 0; offset < len(want); {
		end := min(len(want), offset+1000)
		if err := buffer.put(uint64(offset), want[offset:end]); err != nil {
			t.Fatal(offset, err)
		}
		offset = end
	}
	if len(buffer.parts) > 16 {
		t.Fatal("one allocation retained per packet", len(buffer.parts))
	}
	got := make([]byte, len(want))
	if n := buffer.read(got); n != len(want) || !bytes.Equal(got, want) {
		t.Fatal(n)
	}
	if len(buffer.parts) != 0 {
		t.Fatal("buffer retained after consumption")
	}
}

func TestQUICConnectionSettings(t *testing.T) {
	o := quicOptions{streamWindow: 3 << 20, connectionWindow: 4 << 20, streams: 1, idleTimeout: 3 * time.Second, keepAlive: 100 * time.Millisecond}
	l := testQUICListener(t, o)
	client := testQUICDial(t, l.packet.LocalAddr().String(), o)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	server, err := l.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []*quicConn{client, server} {
		if q.peer.bidiRemote != o.streamWindow || q.peer.uni != o.streamWindow || q.peer.maxData != o.connectionWindow || q.peer.maxBi != o.streams || q.peer.idle != o.idleTimeout {
			t.Fatal("negotiated QUIC parameters differ", q.peer)
		}
	}
	stream, err := client.OpenStream(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	stream.SetDeadline(time.Now().Add(6 * time.Second))
	want := bytes.Repeat([]byte("receive-window"), 150000)
	written := make(chan error, 1)
	go func() { written <- writeAll(stream, want) }()
	remote, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	remote.SetDeadline(time.Now().Add(6 * time.Second))
	limited, stop := context.WithTimeout(ctx, 30*time.Millisecond)
	if extra, e := client.OpenStream(limited, false); e == nil {
		extra.Close()
		t.Fatal("peer stream limit ignored")
	}
	stop()
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(remote, got); err != nil || !bytes.Equal(got, want) {
		t.Fatal("large unread window failed", err)
	}
	remote.Close()
	stream.Close()
	second, err := client.OpenStream(ctx, false)
	if err != nil {
		t.Fatal("closed stream did not return credit", err)
	}
	defer second.Close()
	if err := writeAll(second, []byte("next")); err != nil {
		t.Fatal(err)
	}
	next, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if _, err := io.ReadFull(next, got[:4]); err != nil || string(got[:4]) != "next" {
		t.Fatal(err)
	}
}

func TestQUICConnectionIdle(t *testing.T) {
	for _, keep := range []bool{false, true} {
		t.Run(fmt.Sprint(keep), func(t *testing.T) {
			o := quicOptions{idleTimeout: 400 * time.Millisecond, keepAlive: -1}
			if keep {
				o.keepAlive = 10 * time.Second
			}
			l := testQUICListener(t, o)
			client := testQUICDial(t, l.packet.LocalAddr().String(), o)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			server, err := l.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if keep {
				select {
				case <-client.done:
					t.Fatal("keepalive failed", client.failure.Load())
				case <-server.done:
					t.Fatal("server keepalive failed", server.failure.Load())
				case <-time.After(900 * time.Millisecond):
				}
			} else {
				select {
				case <-client.done:
					if e := client.failure.Load(); e == nil || !strings.Contains(e.err.Error(), "idle timeout") {
						t.Fatal(e)
					}
				case <-ctx.Done():
					t.Fatal("idle connection retained")
				}
			}
		})
	}
	c := quicConn{idleTimeout: 10 * time.Second, peer: quicPeerParams{idle: 3 * time.Second}, keepAlive: 10 * time.Second}
	if c.idleDuration() != 3*time.Second || c.keepAliveDuration() != 1500*time.Millisecond {
		t.Fatal("peer timeout not respected")
	}
}
