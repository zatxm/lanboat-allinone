package nativecmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zatxm/lanboat-allinone/native"
)

type relayReadyWriter chan string

func (w relayReadyWriter) Write(p []byte) (int, error) {
	w <- strings.TrimSpace(string(p))
	return len(p), nil
}

func TestRelayBindCommand(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			raw := []byte(`{"log":{"disabled":true},"inbounds":[{"type":"relay","tag":"server","listen":"127.0.0.1","bind":true,"users":[{"username":"client","password":"private"}]}]}`)
			server, err := native.New(context.Background(), raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			if err = server.Start(); err != nil {
				t.Fatal(err)
			}
			host, port, _ := net.SplitHostPort(server.Address("server"))
			config := map[string]any{"log": map[string]any{"disabled": true}, "outbounds": []any{map[string]any{"type": "relay", "tag": "proxy", "server": host, "server_port": json.Number(port), "username": "client", "password": "private"}}}
			data, _ := json.Marshal(config)
			path := filepath.Join(t.TempDir(), "client.json")
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			var target string
			if network == "tcp" {
				l, e := net.Listen("tcp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer l.Close()
				target = l.Addr().String()
				go func() {
					for {
						c, e := l.Accept()
						if e != nil {
							return
						}
						go func() { defer c.Close(); io.Copy(c, c) }()
					}
				}()
			} else {
				p, e := net.ListenPacket("udp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer p.Close()
				target = p.LocalAddr().String()
				go func() {
					b := make([]byte, 65507)
					for {
						n, a, e := p.ReadFrom(b)
						if e != nil {
							return
						}
						p.WriteTo(b[:n], a)
					}
				}()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ready := make(relayReadyWriter, 1)
			done := make(chan error, 1)
			go func() {
				done <- Execute(ctx, []string{"relay-bind", "-c", path, "-target", target, "-network", network}, ready)
			}()
			var address string
			select {
			case address = <-ready:
			case e := <-done:
				t.Fatal(e)
			case <-time.After(2 * time.Second):
				t.Fatal("CLI did not report bound port")
			}
			c, e := net.DialTimeout(network, address, time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(2 * time.Second))
			payload := bytes.Repeat([]byte("CLI reverse forwarding"), 200)
			if _, e = c.Write(payload); e != nil {
				t.Fatal(e)
			}
			got := make([]byte, len(payload))
			if _, e = io.ReadFull(c, got); e != nil || !bytes.Equal(got, payload) {
				t.Fatal(e)
			}
			cancel()
			select {
			case e := <-done:
				if e != nil {
					t.Fatal(e)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("CLI shutdown blocked")
			}
		})
	}
	for _, args := range [][]string{{"relay-bind"}, {"relay-bind", "-target"}, {"relay-bind", "extra"}} {
		if Execute(context.Background(), args, io.Discard) == nil {
			t.Fatal("invalid arguments accepted", args)
		}
	}
}
