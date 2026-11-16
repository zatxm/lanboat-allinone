package native

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func http3TestServer(t *testing.T, address string, options TLSOptions, handler http.Handler) (string, *quicEndpoint) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	packet, err := net.ListenPacket("udp", address)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	options.ALPN = []string{"h3"}
	config, err := options.config(true, "")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := listenQUIC(ctx, packet, config)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			q, err := endpoint.Accept(ctx)
			if err != nil {
				return
			}
			workers.Go(func() { serveHTTP3(q, handler) })
		}
	})
	t.Cleanup(func() { cancel(); endpoint.Close(); workers.Wait() })
	return "https://" + packet.LocalAddr().String(), endpoint
}

func http3ClientOptions(options TLSOptions) HTTPClientOptions {
	return HTTPClientOptions{Tag: "h3", Version: 3, DisableVersionFallback: true, TLS: options}
}

func http3Client(t *testing.T, r *Runtime, ref clientReference) *http.Client {
	t.Helper()
	client, transport, err := r.ruleHTTPClient(RuleSet{HTTPClient: ref})
	if err != nil {
		t.Fatal(err)
	}
	client.Timeout = 3 * time.Second
	t.Cleanup(transport.CloseIdleConnections)
	return client
}

func TestHTTP3RuleSetDownload(t *testing.T) {
	var body atomic.Value
	body.Store(`{"version":4,"rules":[{"domain":"before.test"}]}`)
	cert := certificate(t)
	url, _ := http3TestServer(t, "127.0.0.1:0", cert, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.ProtoMajor != 3 || req.Host != "rules.test" || req.Header.Get("X-Token") != "private" || req.Header.Get("Accept-Encoding") != "gzip" {
			t.Error("HTTP3 request lost protocol, host or headers", req)
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		writer := gzip.NewWriter(w)
		io.WriteString(writer, body.Load().(string))
		writer.Close()
	}))
	options := http3ClientOptions(TLSOptions{ServerName: "example.com", Certificate: cert.Certificate})
	options.Headers = map[string]headerValues{"Host": {"rules.test"}, "X-Token": {"private"}}
	for _, kind := range []string{"shared", "inline", "default"} {
		t.Run(kind, func(t *testing.T) {
			body.Store(`{"version":4,"rules":[{"domain":"before.test"}]}`)
			cache := filepath.Join(t.TempDir(), "rules.json")
			set := RuleSet{Type: "remote", Tag: "rules", URL: url, Format: "source", Path: cache, HTTPClient: "h3"}
			config := Config{HTTPClients: []HTTPClientOptions{options}, Route: Route{RuleSet: []RuleSet{set}, Rules: []Rule{{RuleSet: []string{"rules"}, Action: "reject"}}}}
			if kind == "inline" {
				encoded, _ := json.Marshal(options)
				config.HTTPClients = nil
				config.Route.RuleSet[0].HTTPClient = clientReference(encoded)
			} else if kind == "default" {
				config.Route.DefaultHTTPClient = "h3"
				config.Route.RuleSet[0].HTTPClient = ""
			}
			r := newTestRuntime(t, config)
			if _, err := r.Dial(context.Background(), "tcp", "before.test:443"); err != ErrRejected {
				t.Fatal("downloaded rules not applied", err)
			}
			body.Store(`{"version":4,"rules":[{"domain":"after.test"}]}`)
			if err := r.ReloadRuleSets(context.Background()); err != nil {
				t.Fatal(err)
			}
			previous, _ := os.ReadFile(cache)
			body.Store(`{"version":4,"rules":[{"invalid":true}]}`)
			if err := r.ReloadRuleSets(context.Background()); err == nil {
				t.Fatal("broken update accepted")
			}
			after, _ := os.ReadFile(cache)
			if !bytes.Equal(previous, after) || !r.ruleSets["rules"].matches(request{address: "after.test:443"}) || r.ruleSets["rules"].matches(request{address: "before.test:443"}) {
				t.Fatal("bad update replaced snapshot or cache")
			}
			if n := r.Stats().Connections; n != 0 {
				t.Fatal("download retained an idle socket", n)
			}
		})
	}
}

func TestHTTP3ClientFallback(t *testing.T) {
	for _, mode := range []string{"allowed", "disabled", "certificate", "pin", "response-error"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			tcp := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				if req.ProtoMajor != 2 {
					t.Error("fallback did not use HTTP2")
				}
				io.WriteString(w, "fallback")
			}))
			tcp.EnableHTTP2 = true
			tcp.StartTLS()
			defer tcp.Close()
			options := http3ClientOptions(TLSOptions{Insecure: true})
			options.DisableVersionFallback = mode == "disabled"
			if mode == "certificate" || mode == "pin" || mode == "response-error" {
				http3TestServer(t, tcp.Listener.Addr().String(), certificate(t), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if mode == "response-error" {
						w.WriteHeader(99)
					}
					io.WriteString(w, "bad")
				}))
				if mode == "certificate" {
					options.TLS.Insecure = false
				} else if mode == "pin" {
					options.TLS.CertificateSHA256 = []string{base64.StdEncoding.EncodeToString(make([]byte, 32))}
				}
			}
			client := http3Client(t, newTestRuntime(t, Config{HTTPClients: []HTTPClientOptions{options}}), "h3")
			response, err := client.Get(tcp.URL)
			if mode == "allowed" {
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				b, err := io.ReadAll(response.Body)
				if err != nil || string(b) != "fallback" || calls.Load() != 1 {
					t.Fatal(string(b), err, calls.Load())
				}
			} else if err == nil || calls.Load() != 0 {
				if response != nil {
					response.Body.Close()
				}
				t.Fatal("strict/certificate failure incorrectly fell back", err, calls.Load())
			}
		})
	}
}

func TestHTTP3ClientTLS(t *testing.T) {
	f := newMutualTLSFixture(t)
	for _, mode := range []string{"ca", "no-sni", "pin", "mtls", "ech"} {
		t.Run(mode, func(t *testing.T) {
			server := TLSOptions{Enabled: true, Certificate: []string{f.serverCert}, Key: []string{f.serverKey}}
			options := TLSOptions{ServerName: "example.com", Certificate: []string{f.ca}}
			if mode == "no-sni" {
				options.DisableSNI = true
			} else if mode == "pin" {
				cert, _ := server.config(true, "")
				hash := sha256.Sum256(cert.Certificates[0].Certificate[0])
				options.Certificate = nil
				options.CertificateSHA256 = []string{base64.StdEncoding.EncodeToString(hash[:])}
			} else if mode == "mtls" {
				server, options = f.server(), f.client()
			} else if mode == "ech" {
				config, key := testECHPair(t)
				server, options = testECHServer(t, f, key), testECHClient(f, config)
			}
			url, _ := http3TestServer(t, "127.0.0.1:0", server, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "secured") }))
			client := http3Client(t, newTestRuntime(t, Config{HTTPClients: []HTTPClientOptions{http3ClientOptions(options)}}), "h3")
			response, err := client.Get(url)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			b, err := io.ReadAll(response.Body)
			if err != nil || string(b) != "secured" || response.TLS == nil {
				t.Fatal(string(b), err)
			}
		})
	}
}

func TestHTTP3ClientBodyAndHeaders(t *testing.T) {
	for _, mode := range []string{"post", "cookies", "short", "long", "gzip", "status"} {
		t.Run(mode, func(t *testing.T) {
			payload := bytes.Repeat([]byte("payload"), 8000)
			url, _ := http3TestServer(t, "127.0.0.1:0", certificate(t), http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				switch mode {
				case "post":
					b, err := io.ReadAll(req.Body)
					if err != nil || !bytes.Equal(b, payload) {
						t.Error("POST body", len(b), err)
					}
					w.Write(b)
				case "cookies":
					w.Header().Add("Set-Cookie", "a=1")
					w.Header().Add("Set-Cookie", "b=2")
					io.WriteString(w, "cookies")
				case "short", "long":
					length := 3
					if mode == "short" {
						length = 10
					}
					w.Header().Set("Content-Length", fmt.Sprint(length))
					io.WriteString(w, "12345")
				case "gzip":
					w.Header().Set("Content-Encoding", "gzip")
					io.WriteString(w, "broken gzip")
				case "status":
					w.WriteHeader(503)
				}
			}))
			client := http3Client(t, newTestRuntime(t, Config{HTTPClients: []HTTPClientOptions{http3ClientOptions(TLSOptions{Insecure: true})}}), "h3")
			response, err := client.Post(url, "application/octet-stream", bytes.NewReader(payload))
			if mode == "gzip" {
				if err == nil {
					response.Body.Close()
					t.Fatal("broken gzip accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			b, err := io.ReadAll(response.Body)
			if mode == "short" || mode == "long" {
				if err == nil {
					t.Fatal("content length mismatch accepted")
				}
			} else if err != nil || mode == "post" && !bytes.Equal(b, payload) || mode == "cookies" && len(response.Cookies()) != 2 || mode == "status" && response.StatusCode != 503 {
				t.Fatal(len(b), response.Cookies(), err)
			}
		})
	}
}

func TestHTTP3ClientConfig(t *testing.T) {
	for _, setting := range []string{`"version":4`, `"version":-1`, `"version":3,"tls":{"fragment":true}`, `"version":3,"tls":{"record_fragment":true}`, `"version":3,"tls":{"max_version":"1.2"}`, `"version":3,"tls":{"utls":{"enabled":true,"fingerprint":"chrome"}}`} {
		if _, err := Parse([]byte(`{"http_clients":[{"tag":"h3",` + setting + `}]}`)); err == nil {
			t.Fatal("invalid HTTP3 client accepted", setting)
		}
	}
	for _, version := range []int{0, 1, 2, 3} {
		if _, err := Parse([]byte(fmt.Sprintf(`{"http_clients":[{"tag":"h3","version":%d}]}`, version))); err != nil {
			t.Fatal(version, err)
		}
	}
}

func TestHTTP3ClientRouting(t *testing.T) {
	for _, mode := range []string{"ipv6", "dns", "detour", "download-detour"} {
		t.Run(mode, func(t *testing.T) {
			address := "127.0.0.1:0"
			if mode == "ipv6" {
				address = "[::1]:0"
			}
			url, _ := http3TestServer(t, address, certificate(t), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "routed") }))
			options := http3ClientOptions(TLSOptions{Insecure: true})
			config := Config{HTTPClients: []HTTPClientOptions{options}, Outbounds: []Outbound{{Type: "block", Tag: "block"}}, Route: Route{Final: "block"}}
			set := RuleSet{HTTPClient: "h3"}
			var proxy *Runtime
			if mode == "dns" {
				url = strings.Replace(url, "127.0.0.1", "download.test", 1)
				config.DNS.Servers = []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"download.test": {"127.0.0.1"}}}}
			} else if mode == "detour" || mode == "download-detour" {
				in := testInbound(t, "socks")
				proxy = newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out := testOutbound(t, in, proxy.Address(in.Tag))
				out.Tag = "download"
				config.Outbounds = append(config.Outbounds, out)
				if mode == "detour" {
					config.HTTPClients[0].Detour = "download"
					set.DownloadDetour = "block"
				} else {
					set.DownloadDetour = "download"
				}
			}
			r := newTestRuntime(t, config)
			client, transport, err := r.ruleHTTPClient(set)
			if err != nil {
				t.Fatal(err)
			}
			defer transport.CloseIdleConnections()
			response, err := client.Get(url)
			if err != nil {
				t.Fatal(err)
			}
			b, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(b) != "routed" || proxy != nil && proxy.Stats().Uplink == 0 {
				t.Fatal(string(b), err)
			}
		})
	}
}

func TestHTTP3ClientRedirects(t *testing.T) {
	for _, mode := range []string{"same", "cross", "downgrade", "userinfo", "loop"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			targetURL, _ := http3TestServer(t, "127.0.0.1:0", certificate(t), http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				if req.Header.Get("X-Secret") != "" || req.Host == "alias.test" || req.Header.Get("User-Agent") != "Lanboat-test" {
					t.Error("cross-origin redirect leaked custom headers", req.Header, req.Host)
				}
				io.WriteString(w, "redirected")
			}))
			sourceURL, _ := http3TestServer(t, "127.0.0.1:0", certificate(t), http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path == "/next" {
					if req.Header.Get("X-Secret") != "private" || req.Host != "alias.test" {
						t.Error("same-origin redirect lost headers")
					}
					io.WriteString(w, "redirected")
					return
				}
				location := targetURL
				switch mode {
				case "same":
					location = "/next"
				case "downgrade":
					location = strings.Replace(targetURL, "https:", "http:", 1)
				case "userinfo":
					location = strings.Replace(targetURL, "https://", "https://user:password@", 1)
				case "loop":
					location = "/"
				}
				http.Redirect(w, req, location, 307)
			}))
			options := http3ClientOptions(TLSOptions{Insecure: true})
			r := newTestRuntime(t, Config{HTTPClients: []HTTPClientOptions{options}})
			client := http3Client(t, r, "h3")
			req, _ := http.NewRequest("GET", sourceURL, nil)
			req.Host = "alias.test"
			req.Header.Set("X-Secret", "private")
			req.Header.Set("User-Agent", "Lanboat-test")
			response, err := client.Do(req)
			if mode == "same" || mode == "cross" {
				if err != nil {
					t.Fatal(err)
				}
				b, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || string(b) != "redirected" {
					t.Fatal(string(b), err)
				}
			} else {
				if response != nil {
					response.Body.Close()
				}
				if err == nil || calls.Load() != 0 {
					t.Fatal("unsafe redirect accepted", err, calls.Load())
				}
			}
		})
	}
}

func TestHTTP3ClientCancellation(t *testing.T) {
	for _, mode := range []string{"headers", "body", "close", "runtime"} {
		t.Run(mode, func(t *testing.T) {
			started := make(chan struct{})
			url, _ := http3TestServer(t, "127.0.0.1:0", certificate(t), http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				close(started)
				if mode != "headers" {
					w.WriteHeader(200)
					w.(interface{ FlushError() error }).FlushError()
				}
				<-req.Context().Done()
			}))
			r := newTestRuntime(t, Config{HTTPClients: []HTTPClientOptions{http3ClientOptions(TLSOptions{Insecure: true})}})
			client := http3Client(t, r, "h3")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
			// Avoid gzip header reads, so pending DATA can be cancelled separately.
			req.Header.Set("Accept-Encoding", "identity")
			done := make(chan error, 1)
			var body io.ReadCloser
			ready := make(chan struct{})
			go func() {
				response, err := client.Do(req)
				if err != nil {
					done <- err
					return
				}
				body = response.Body
				close(ready)
				_, err = io.ReadAll(body)
				body.Close()
				done <- err
			}()
			<-started
			if mode != "headers" {
				<-ready
			}
			if mode == "close" {
				body.Close()
			} else if mode == "runtime" {
				r.Close()
			} else {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("HTTP3 cancellation retained a reader")
			}
			deadline := time.Now().Add(time.Second)
			for r.Stats().Connections != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if r.Stats().Connections != 0 {
				t.Fatal("HTTP3 cancellation retained socket")
			}
		})
	}
}

func TestHTTP3ClientUnreadCancellation(t *testing.T) {
	url, _ := http3TestServer(t, "127.0.0.1:0", certificate(t), http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
		w.(interface{ FlushError() error }).FlushError()
		<-req.Context().Done()
	}))
	r := newTestRuntime(t, Config{HTTPClients: []HTTPClientOptions{http3ClientOptions(TLSOptions{Insecure: true})}})
	client := http3Client(t, r, "h3")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	cancel()
	deadline := time.Now().Add(time.Second)
	for r.Stats().Connections != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if r.Stats().Connections != 0 {
		t.Fatal("cancelled unread response retained QUIC")
	}
}

func TestHTTP3ClientReference(t *testing.T) {
	reference := os.Getenv("LANBOAT_TEST_QUIC")
	if reference == "" {
		t.Fatal("LANBOAT_TEST_QUIC required for HTTP3 interoperability")
	}
	dir := t.TempDir()
	cert := certificate(t)
	cp, kp, source := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "rules.json")
	os.WriteFile(cp, []byte(strings.Join(cert.Certificate, "\n")), 0600)
	os.WriteFile(kp, []byte(strings.Join(cert.Key, "\n")), 0600)
	want := []byte(`{"version":4,"rules":[{"domain_suffix":"reference.test"}]}`)
	os.WriteFile(source, want, 0600)
	address := portAddress("127.0.0.1", unusedPort(t))
	cmd := exec.Command(reference, "http-server", address, cp, kp, source)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	cmd.Stderr = &log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait(); t.Log(log.String()) }()
	if line, err := bufio.NewReader(pipe).ReadString('\n'); err != nil || line != "READY\n" {
		t.Fatal(line, err)
	}
	options := http3ClientOptions(TLSOptions{ServerName: "example.com", Certificate: cert.Certificate})
	r := newTestRuntime(t, Config{HTTPClients: []HTTPClientOptions{options}})
	client := http3Client(t, r, "h3")
	for _, path := range []string{"rules", "redirect", "gzip", "post"} {
		t.Run(path, func(t *testing.T) {
			response, err := client.Post("https://"+address+"/"+path, "application/json", bytes.NewReader(want))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			b, err := io.ReadAll(response.Body)
			if err != nil || !bytes.Equal(b, want) || response.ProtoMajor != 3 || path != "post" && len(response.Cookies()) != 2 {
				t.Fatal(string(b), response.Header, err)
			}
		})
	}
	set := RuleSet{Type: "remote", Tag: "external", Format: "source", URL: "https://" + address + "/gzip", HTTPClient: "h3"}
	r.ruleSets[set.Tag] = &ruleCollection{}
	if err := r.loadRuleSet(context.Background(), set, true); err != nil || !r.ruleSets[set.Tag].matches(request{address: "www.reference.test:443"}) {
		t.Fatal("external HTTP3 rule-set download", err)
	}
}

func TestHTTP3BinaryRulesFailurePreservesCache(t *testing.T) {
	data, err := CompileRuleSet([]byte(`{"version":5,"rules":[{"domain_suffix":"binary.test"}]}`), "source")
	if err != nil {
		t.Fatal(err)
	}
	var mode atomic.Int32
	url, endpoint := http3TestServer(t, "127.0.0.1:0", certificate(t), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch mode.Load() {
		case 1:
			w.WriteHeader(503)
		case 2:
			w.Write(data[:len(data)/2])
		case 3:
			w.Header().Set("Content-Length", fmt.Sprint(len(data)+1))
			w.Write(data)
		default:
			w.Write(data)
		}
	}))
	cache := filepath.Join(t.TempDir(), "cached.srs")
	r := newTestRuntime(t, Config{HTTPClients: []HTTPClientOptions{http3ClientOptions(TLSOptions{Insecure: true})}, Route: Route{RuleSet: []RuleSet{{Type: "remote", Tag: "binary", Format: "binary", URL: url, Path: cache, HTTPClient: "h3"}}}})
	previous, _ := os.ReadFile(cache)
	for _, value := range []int32{1, 2, 3, 4} {
		mode.Store(value)
		if value == 4 {
			endpoint.Close()
		}
		if err := r.ReloadRuleSets(context.Background()); err == nil {
			t.Fatal("failed download accepted", value)
		}
		after, _ := os.ReadFile(cache)
		if !bytes.Equal(previous, after) || !r.ruleSets["binary"].matches(request{address: "www.binary.test:443"}) {
			t.Fatal("failed download damaged rules or cache", value)
		}
	}
}

func TestHTTP3HeaderValidation(t *testing.T) {
	valid := [][2]string{{":status", "200"}, {"set-cookie", "a=1"}, {"set-cookie", "b=2"}}
	headers := make(http.Header)
	if _, err := h3DecodeHeaders(h3Encode(valid), headers); err != nil || len(headers.Values("Set-Cookie")) != 2 {
		t.Fatal(headers, err)
	}
	if _, err := h3Decode(h3Encode(valid)); err == nil {
		t.Fatal("legacy tunnel decoder lost duplicate rejection")
	}
	for _, fields := range [][][2]string{
		{{":status", "200"}, {":status", "200"}},
		{{":status", "200"}, {"content-length", "1"}, {"content-length", "1"}},
		{{":status", "200"}, {"connection", "close"}},
		{{":status", "200"}, {"bad name", "value"}},
		{{":status", "200"}, {"x-test", "bad\x01value"}},
		{{"x-test", "first"}, {":status", "200"}},
	} {
		if _, err := h3DecodeHeaders(h3Encode(fields), make(http.Header)); err == nil {
			t.Fatal("invalid HTTP3 header accepted", fields)
		}
	}
}

func TestHTTP3ACMEReference(t *testing.T) {
	f := newACMEFixture(t, false)
	upstream, err := url.Parse(f.provider)
	if err != nil {
		t.Fatal(err)
	}
	base := *upstream
	base.Path = ""
	proxy := httputil.NewSingleHostReverseProxy(&base)
	options := f.client.TLS
	options.Enabled = true
	config, err := options.config(false, upstream.Hostname())
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: config}
	defer transport.CloseIdleConnections()
	proxy.Transport = transport
	private, err := x509.MarshalPKCS8PrivateKey(f.apiPair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS := TLSOptions{Enabled: true, Certificate: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.apiPair.Certificate[0]}))}, Key: []string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))}}
	var calls atomic.Int32
	http3TestServer(t, upstream.Host, serverTLS, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		if req.ProtoMajor != 3 {
			t.Error("ACME did not use HTTP3")
		}
		proxy.ServeHTTP(w, req)
	}))
	f.client.Version, f.client.DisableVersionFallback = 3, true
	_, provider := f.core(t, f.options(t))
	f.current(t, provider, "example.org")
	if calls.Load() < 5 {
		t.Fatal("ACME requests did not cross HTTP3", calls.Load())
	}
}

func FuzzHTTP3Headers(f *testing.F) {
	f.Add(h3Encode([][2]string{{":status", "200"}, {"content-length", "5"}}))
	f.Add(h3Encode([][2]string{{":status", "200"}, {"set-cookie", "a=1"}, {"set-cookie", "b=2"}}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		headers := make(http.Header)
		if _, err := h3DecodeHeaders(b, headers); err == nil {
			if len(headers.Values("Content-Length")) > 1 {
				t.Fatal("ambiguous content length")
			}
			for k, v := range headers {
				if err := validateHTTPHeader(k, v); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}
