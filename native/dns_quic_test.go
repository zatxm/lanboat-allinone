package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDNSQUICIndependent(t *testing.T) {
	for _, kind := range []string{"quic", "h3"} {
		t.Run(kind, func(t *testing.T) {
			in := Inbound{Type: "dns-" + kind, Tag: "dns", Listen: "127.0.0.1", TLS: certificate(t)}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"example.test": {"192.0.2.42", "2001:db8::42"}}}}}})
			h, p, _ := net.SplitHostPort(server.Address("dns"))
			port, _ := strconv.ParseUint(p, 10, 16)
			r, e := newResolver(DNSConfig{DisableCache: true, Servers: []DNSServer{{Type: kind, Tag: "dns", Server: h, ServerPort: uint16(port), TLS: TLSOptions{Insecure: true}}}})
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var wg sync.WaitGroup
			for range 16 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					q, _ := makeDNSQuery("example.test", 1)
					reply, e := r.exchange(ctx, q)
					if e != nil || len(reply) < 16 || !bytes.Equal(reply[:2], q[:2]) || !bytes.Equal(reply[len(reply)-4:], []byte{192, 0, 2, 42}) {
						t.Errorf("DNS response %x: %v", reply, e)
					}
				}()
			}
			wg.Wait()
			server.mu.Lock()
			l := server.quicListeners["dns"]
			l.mu.Lock()
			count := len(l.conns)
			l.mu.Unlock()
			server.mu.Unlock()
			if count != 1 {
				t.Fatalf("queries used %d connections", count)
			}
		})
	}
}
func TestDNSQUICInterop(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_QUIC")
	if ref == "" {
		t.Skip("LANBOAT_TEST_QUIC not set")
	}
	for _, kind := range []string{"quic", "h3"} {
		t.Run(kind+"/native-client", func(t *testing.T) {
			cert := certificate(t)
			dir := t.TempDir()
			cp, kp := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
			os.WriteFile(cp, []byte(strings.Join(cert.Certificate, "\n")), 0600)
			os.WriteFile(kp, []byte(strings.Join(cert.Key, "\n")), 0600)
			port := unusedPort(t)
			cmd := exec.Command(ref, "dns-server", kind, portAddress("127.0.0.1", port), cp, kp)
			stdout, e := cmd.StdoutPipe()
			if e != nil {
				t.Fatal(e)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			defer func() {
				cmd.Process.Kill()
				cmd.Wait()
				if t.Failed() {
					t.Log(stderr.String())
				}
			}()
			if !bufio.NewScanner(stdout).Scan() {
				t.Fatal("DNS oracle not ready", stderr.String())
			}
			r, e := newResolver(DNSConfig{DisableCache: true, Servers: []DNSServer{{Type: kind, Tag: "dns", Server: "127.0.0.1", ServerPort: port, TLS: TLSOptions{Insecure: true}}}})
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			for range 12 {
				q, _ := makeDNSQuery("example.test", 1)
				b, e := r.exchange(ctx, q)
				if e != nil || len(b) < 16 || !bytes.Equal(b[:2], q[:2]) || !bytes.Equal(b[len(b)-4:], []byte{192, 0, 2, 42}) {
					t.Fatalf("DNS response %x: %v", b, e)
				}
			}
		})
		t.Run(kind+"/native-server", func(t *testing.T) {
			s := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "dns-" + kind, Tag: "dns", Listen: "127.0.0.1", TLS: certificate(t)}}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"example.test": {"192.0.2.42"}}}}}})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			out, e := exec.CommandContext(ctx, ref, "dns-client", kind, s.Address("dns")).CombinedOutput()
			if e != nil || !strings.Contains(string(out), "PASS") {
				t.Fatalf("%s %v", out, e)
			}
		})
	}
}
func TestDNSQUICRejectMalformed(t *testing.T) {
	q, _ := makeDNSQuery("example.test", 1)
	q[0], q[1] = 0, 0
	valid := append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)
	for name, b := range map[string][]byte{"short": {0, 1, 0}, "noFIN": append(append([]byte(nil), valid...), 1), "ID": append([]byte(nil), valid...)} {
		t.Run(name, func(t *testing.T) {
			if name == "ID" {
				b[2] = 1
			}
			if _, e := readDoQMessage(bytes.NewReader(b)); e == nil {
				t.Fatal("invalid DoQ accepted")
			}
		})
	}
	var request bytes.Buffer
	h3WriteFrame(&request, 1, h3Encode([][2]string{{":status", "200"}, {"content-length", "1000"}, {"content-type", "application/dns-message"}}))
	h3WriteFrame(&request, 0, q)
	if _, _, e := readDNSH3Message(&request); e == nil {
		t.Fatal("bad content length accepted")
	}
}
func TestDNSQUICDetourFailureDoesNotLeak(t *testing.T) {
	for _, kind := range []string{"quic", "h3"} {
		t.Run(kind, func(t *testing.T) {
			r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "block", Tag: "deny"}}, DNS: DNSConfig{Servers: []DNSServer{{Type: kind, Tag: "dns", Server: "127.0.0.1", ServerPort: 1, Detour: "deny", TLS: TLSOptions{Insecure: true}}}}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			q, _ := makeDNSQuery("example.test", 1)
			if _, e := r.resolver.exchange(ctx, q); !errors.Is(e, ErrRejected) {
				t.Fatalf("detour was bypassed: %v", e)
			}
		})
	}
}

func TestDNSQUICBootstrapAndSOCKSDetour(t *testing.T) {
	for _, kind := range []string{"quic", "h3"} {
		t.Run(kind, func(t *testing.T) {
			dns := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "dns-" + kind, Tag: "dns", Listen: "127.0.0.1", TLS: certificate(t)}}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"example.test": {"192.0.2.42"}}}}}})
			in := testInbound(t, "socks")
			proxy := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, proxy.Address("server"))
			_, p, _ := net.SplitHostPort(dns.Address("dns"))
			port, _ := strconv.ParseUint(p, 10, 16)
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out, {Type: "block", Tag: "deny"}}, Route: Route{Final: "deny"}, DNS: DNSConfig{Final: "secure", Servers: []DNSServer{{Type: "hosts", Tag: "bootstrap", Predefined: map[string][]string{"dns.test": {"127.0.0.1"}}}, {Type: kind, Tag: "secure", Server: "dns.test", ServerPort: uint16(port), DomainResolver: "bootstrap", Detour: "proxy", TLS: TLSOptions{Insecure: true}}}}})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ips, e := client.resolver.lookup(ctx, "example.test")
			if e != nil || len(ips) != 1 || ips[0].String() != "192.0.2.42" {
				t.Fatal(ips, e)
			}
		})
	}
}
