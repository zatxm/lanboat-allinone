package native

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSudokuWebSocketForward(t *testing.T) {
	for _, scheme := range []string{"ws", "wss"} {
		t.Run(scheme, func(t *testing.T) {
			server, publisher, address := nativeSudokuReverseHTTP(t, "poll", sudokuReverseHTTPRoutes(sudokuReverseOrigin(t)), false)
			waitSudokuReverseHTTP(t, address, "/app/ready")
			endpoint := "ws://" + address + "/app"
			options := TLSOptions{}
			if scheme == "wss" {
				front := httptest.NewTLSServer(server.sudokuReverseServers["server"])
				defer front.Close()
				endpoint = "wss" + strings.TrimPrefix(front.URL, "https") + "/app"
				options.Certificate = []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: front.TLS.Certificates[0].Certificate[0]}))}
				bad := newTestRuntime(t, Config{})
				forward, err := bad.ForwardSudokuWebSocket(context.Background(), "127.0.0.1:0", endpoint, TLSOptions{})
				if err != nil {
					t.Fatal(err)
				}
				_, _, _, err = sudokuReverseHTTPGet(forward.Addr().String(), "/rejected", nil)
				if err == nil {
					t.Fatal("untrusted WSS certificate accepted")
				}
				forward.Close()
				bad.Close()
			}
			client := newTestRuntime(t, Config{})
			forward, err := client.ForwardSudokuWebSocket(context.Background(), "127.0.0.1:0", endpoint, options)
			if err != nil {
				t.Fatal(err)
			}
			var workers sync.WaitGroup
			for range 16 {
				workers.Go(func() {
					status, _, body, err := sudokuReverseHTTPGet(forward.Addr().String(), "/through-forward", nil)
					if err != nil || status != 200 || !strings.HasPrefix(body, "/through-forward|") {
						t.Error(status, body, err)
					}
				})
			}
			workers.Wait()
			// Closing the runtime also drains an idle local connection and forwarder.
			idle, err := net.Dial("tcp", forward.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer idle.Close()
			client.Close()
			if err = forward.Wait(); err != nil {
				t.Fatal(err)
			}
			idle.SetReadDeadline(time.Now().Add(time.Second))
			var b [1]byte
			if _, err = idle.Read(b[:]); err == nil {
				t.Fatal("idle connection retained")
			}
			publisher.Close()
			server.Close()
		})
	}
}

func TestSudokuWebSocketForwardValidation(t *testing.T) {
	r := newTestRuntime(t, Config{})
	for _, endpoint := range []string{"", "http://example.com/app", "ws:///app", "ws://u:p@example.com/app", "ws://example.com/app#fragment", "ws://example.com:65536/app"} {
		if f, err := r.ForwardSudokuWebSocket(context.Background(), "127.0.0.1:0", endpoint, TLSOptions{}); err == nil {
			f.Close()
			t.Fatal("bad endpoint accepted", endpoint)
		}
	}
	if f, err := r.ForwardSudokuWebSocket(context.Background(), ":0", "ws://example.com/app", TLSOptions{}); err == nil {
		f.Close()
		t.Fatal("implicit listen accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.ForwardSudokuWebSocket(ctx, "127.0.0.1:0", "ws://example.com/app", TLSOptions{}); err != context.Canceled {
		t.Fatal(err)
	}
	r.Close()
	if f, err := r.ForwardSudokuWebSocket(context.Background(), "127.0.0.1:0", "ws://example.com/app", TLSOptions{}); err == nil {
		f.Close()
		t.Fatal("closed runtime accepted")
	}
}

func TestSudokuWebSocketForwardSubprotocol(t *testing.T) {
	for _, protocol := range []string{"", "wrong"} {
		t.Run(protocol, func(t *testing.T) {
			fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer c.Close()
				rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: " + websocketAccept(r.Header.Get("Sec-WebSocket-Key")) + "\r\nSec-WebSocket-Protocol: " + protocol + "\r\n\r\n")
				rw.Flush()
				c.SetReadDeadline(time.Now().Add(time.Second))
				var b [1]byte
				if _, err = c.Read(b[:]); err == nil {
					t.Error("application data sent after subprotocol rejection")
				}
			}))
			defer fake.Close()
			client := newTestRuntime(t, Config{})
			forward, err := client.ForwardSudokuWebSocket(context.Background(), "127.0.0.1:0", "ws"+strings.TrimPrefix(fake.URL, "http"), TLSOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err = sudokuReverseHTTPGet(forward.Addr().String(), "/must-not-reach", nil); err == nil {
				t.Fatal("missing/mismatched subprotocol accepted")
			}
			forward.Close()
			client.Close()
		})
	}
}
