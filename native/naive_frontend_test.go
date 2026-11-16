package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func naiveFrontendServer(t *testing.T, address string) *Runtime {
	t.Helper()
	return newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "naive", Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{Username: "client", Password: "private"}}, NaiveFrontend: address}}})
}

func naiveWebsiteClient(t *testing.T, version int) *http.Client {
	t.Helper()
	if version == 3 {
		o := http3ClientOptions(TLSOptions{Insecure: true})
		r := newTestRuntime(t, Config{HTTPClients: []HTTPClientOptions{o}})
		client := http3Client(t, r, "h3")
		client.Timeout = 5 * time.Second
		return client
	}
	p := new(http.Protocols)
	p.SetHTTP1(version == 1)
	p.SetHTTP2(version == 2)
	transport := &http.Transport{Protocols: p, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func TestNaiveFrontendWebsite(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			requests := make(chan *http.Request, 8)
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				requests <- req.Clone(req.Context())
				w.Header().Set("Padding", "do-not-expose")
				w.Header().Set("Proxy-Authenticate", "do-not-expose")
				w.Header().Add("Set-Cookie", "a=1")
				w.Header().Add("Set-Cookie", "b=2")
				w.Header().Set("Content-Type", "application/octet-stream")
				if req.Method == "POST" {
					_, _ = io.Copy(w, req.Body)
				} else {
					_, _ = io.WriteString(w, "website")
				}
			}))
			defer backend.Close()
			r := naiveFrontendServer(t, backend.URL+"/site")
			client := naiveWebsiteClient(t, version)
			for _, method := range []string{"GET", "HEAD", "POST"} {
				var payload []byte
				if method == "POST" {
					payload = bytes.Repeat([]byte("streamed"), 65536)
				}
				req, _ := http.NewRequest(method, "https://"+r.Address("server")+"/docs/a%2Fb?x=1", bytes.NewReader(payload))
				req.Host = "public.example"
				req.Header.Set("Proxy-Authorization", "Basic secret")
				req.Header.Set("Authorization", "Bearer website-only")
				req.Header.Set("Padding", "secret")
				req.Header.Set("X-Forwarded-For", "spoofed")
				req.Header.Set("X-Forwarded-Proto", "http")
				req.Header.Set("Forwarded", "for=spoofed")
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(method, err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				want := []byte("website")
				if method == "HEAD" {
					want = nil
				} else if method == "POST" {
					want = payload
				}
				if err != nil || resp.ProtoMajor != version || resp.StatusCode != 200 || !bytes.Equal(body, want) || resp.Header.Get("Padding") != "" || resp.Header.Get("Proxy-Authenticate") != "" || len(resp.Header.Values("Set-Cookie")) != 2 {
					t.Fatal(method, resp.Status, resp.Proto, len(body), resp.Header, err)
				}
				got := <-requests
				if got.Host != strings.TrimPrefix(backend.URL, "http://") || got.URL.RequestURI() != "/site/docs/a%2Fb?x=1" || got.Header.Get("Proxy-Authorization") != "" || got.Header.Get("Padding") != "" || got.Header.Get("Authorization") != "Bearer website-only" || got.Header.Get("Forwarded") != "" || got.Header.Get("X-Forwarded-For") != "127.0.0.1" || got.Header.Get("X-Forwarded-Host") != "public.example" || got.Header.Get("X-Forwarded-Proto") != "https" {
					t.Fatal("frontend target or header boundary", got.Host, got.URL, got.Header)
				}
			}
		})
	}
}

func TestNaiveFrontendAuthentication(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "GET" || req.URL.Path != "/" {
			t.Error("proxy request reached website", req.Method, req.URL.Path)
		}
		if req.Header.Get("Proxy-Authorization") != "" || req.Header.Get("Padding") != "" {
			t.Error("preamble leaked proxy credentials or padding")
		}
		w.WriteHeader(200)
	}))
	defer backend.Close()
	r := naiveFrontendServer(t, backend.URL)
	in := r.config.Inbounds[0]
	for _, quic := range []bool{false, true} {
		t.Run(fmt.Sprint(quic), func(t *testing.T) {
			out := testOutbound(t, in, r.Address("server"))
			out.QUIC, out.UDPOverTCP = quic, true
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 511, 4096, 60000})
			out.Password = "wrong"
			bad := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if conn, err := bad.Dial(ctx, "tcp", "127.0.0.1:9"); err == nil {
				conn.Close()
				t.Fatal("unauthenticated proxy accepted")
			} else if !strings.Contains(err.Error(), "404") {
				t.Fatal("authentication disclosed", err)
			}
			assertTCP(t, client)
		})
	}
	for _, version := range []int{1, 2} {
		client := naiveWebsiteClient(t, version)
		req, _ := http.NewRequest("CONNECT", "https://"+r.Address("server"), nil)
		req.Host = "127.0.0.1:9"
		req.Header.Set("Padding", "request")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 || resp.Header.Get("Padding") != "" || resp.Header.Get("Proxy-Authenticate") != "" {
			t.Fatal("proxy signature in unauthenticated response", resp.Status, resp.Header)
		}
	}
}

func TestNaiveFrontendCloseAndFailure(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			entered := make(chan struct{}, 1)
			backend := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) { entered <- struct{}{}; <-req.Context().Done() }))
			defer backend.Close()
			r := naiveFrontendServer(t, backend.URL)
			client := naiveWebsiteClient(t, version)
			done := make(chan struct{})
			go func() {
				defer close(done)
				resp, err := client.Get("https://" + r.Address("server") + "/")
				if err == nil {
					resp.Body.Close()
				}
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("frontend did not reach backend")
			}
			closed := make(chan struct{})
			go func() { r.Close(); close(closed) }()
			select {
			case <-closed:
			case <-time.After(3 * time.Second):
				t.Fatal("runtime close blocked on website")
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("website request survived close")
			}
		})
	}
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("untrusted backend accepted")
		w.WriteHeader(200)
	}))
	defer backend.Close()
	r := naiveFrontendServer(t, backend.URL)
	resp, err := naiveWebsiteClient(t, 2).Get("https://" + r.Address("server") + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Fatal("backend certificate not verified", resp.Status)
	}
}

func TestNaiveFrontendCapacity(t *testing.T) {
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { <-release; w.WriteHeader(200) }))
	defer backend.Close()
	r := naiveFrontendServer(t, backend.URL)
	p := r.config.Inbounds[0].naiveFrontend
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() { p.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "https://website.test/", nil)) })
	}
	defer workers.Wait()
	defer close(release)
	deadline := time.Now().Add(3 * time.Second)
	for len(p.slots) != 32 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(p.slots) != 32 {
		t.Fatal("website requests did not occupy slots")
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "https://website.test/", nil))
	if w.Code != 503 {
		t.Fatal("unbounded frontend requests", w.Code)
	}
}

func TestNaiveFrontendTruncatedResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
	}))
	defer backend.Close()
	r := naiveFrontendServer(t, backend.URL)
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			resp, err := naiveWebsiteClient(t, version).Get("https://" + r.Address("server") + "/")
			if err == nil {
				defer resp.Body.Close()
				_, err = io.ReadAll(resp.Body)
			}
			if err == nil {
				t.Fatal("truncated backend response reported as complete")
			}
		})
	}
}

func TestNaiveFrontendConfig(t *testing.T) {
	for _, address := range []string{"http://127.0.0.1:8080", "https://example.com/site", "http://[::1]:8000/"} {
		if _, err := parseNaiveFrontend("naive", address); err != nil {
			t.Fatal(address, err)
		}
	}
	for _, address := range []string{"file:///etc/passwd", "http:///empty", "https://user:secret@website.test", "https://website.test/?secret=1", "https://website.test/#fragment", "http://127.0.0.1:0", "http://127.0.0.1:65536"} {
		if _, err := parseNaiveFrontend("naive", address); err == nil {
			t.Fatal("accepted invalid frontend", address)
		}
	}
	in := Inbound{Type: "naive", TLS: certificate(t), Users: []User{{Username: "u", Password: "p"}}, NaiveFrontend: "http://127.0.0.1:8080"}
	for _, kind := range []string{"naive", "trusttunnel", "mixed"} {
		in.Type = kind
		data, _ := json.Marshal(Config{Inbounds: []Inbound{in}})
		_, err := Parse(data)
		if (err == nil) != (kind == "naive") {
			t.Fatal("frontend type validation", kind, err)
		}
	}
}

func TestNaiveFrontendHTTP3ConnectBoundary(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("malformed CONNECT reached website") }))
	defer backend.Close()
	r := naiveFrontendServer(t, backend.URL)
	out := testOutbound(t, r.config.Inbounds[0], r.Address("server"))
	out.QUIC = true
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	q, err := client.trustClients["proxy"].h3Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][2]string{{":scheme", "https"}, {":path", "/"}, {":protocol", "websocket"}} {
		s, err := q.OpenStream(ctx, false)
		if err != nil {
			t.Fatal(err)
		}
		s.SetDeadline(time.Now().Add(2 * time.Second))
		h := [][2]string{{":method", "CONNECT"}, {":authority", "127.0.0.1:9"}, extra, {"padding", "request"}}
		if err = h3WriteFrame(s, 1, h3Encode(h)); err != nil {
			t.Fatal(err)
		}
		s.CloseWrite()
		kind, wire, err := h3ReadFrame(s)
		if err != nil && strings.Contains(err.Error(), "peer reset stream") {
			s.Close()
			continue
		}
		if err != nil || kind != 1 {
			t.Fatal(kind, err)
		}
		reply, err := h3Decode(wire)
		s.Close()
		if err != nil || reply[":status"] != "400" || reply["padding"] != "" {
			t.Fatal("malformed CONNECT accepted or disclosed proxy", extra, reply, err)
		}
	}
}

func TestNaiveFrontendOfficialReference(t *testing.T) {
	if os.Getenv("LANBOAT_TEST_NAIVE") == "" {
		t.Fatal("LANBOAT_TEST_NAIVE required")
	}
	for _, quic := range []bool{false, true} {
		t.Run(fmt.Sprint(quic), func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Header.Get("Proxy-Authorization") != "" || req.Header.Get("Padding") != "" {
					t.Error("proxy credentials reached website")
				}
				_, _ = io.WriteString(w, "website alongside official client")
			}))
			defer backend.Close()
			f := newMutualTLSFixture(t)
			in := Inbound{Type: "naive", Tag: "server", Listen: "127.0.0.1", TLS: f.server(), Users: []User{{Username: "client", Password: "private"}}, NaiveFrontend: backend.URL}
			in.TLS.ClientAuthentication, in.TLS.ClientCertificate = "", nil
			r := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			_, port, _ := net.SplitHostPort(r.Address("server"))
			ca := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(ca, []byte(f.ca), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SSL_CERT_FILE", ca)
			local := portAddress("127.0.0.1", unusedPort(t))
			protocol, version := "https", 2
			if quic {
				protocol, version = "quic", 3
			}
			startTrustReference(t, "LANBOAT_TEST_NAIVE", "--listen=socks://"+local, "--proxy="+protocol+"://client:private@example.com:"+port, "--host-resolver-rules=MAP example.com 127.0.0.1", "--log")
			waitPort(t, local)
			out := testOutbound(t, Inbound{Type: "socks"}, local)
			out.Username, out.Password = "", ""
			assertTCP(t, newTestRuntime(t, Config{Outbounds: []Outbound{out}}))
			resp, err := naiveWebsiteClient(t, version).Get("https://" + r.Address("server") + "/")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || resp.StatusCode != 200 || string(body) != "website alongside official client" {
				t.Fatal("website and official proxy did not coexist", resp.Status, string(body), err)
			}
		})
	}
}
