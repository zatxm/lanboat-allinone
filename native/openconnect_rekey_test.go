package native

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestOpenConnectRekey(t *testing.T) {
	for _, channel := range []string{"cstp", "dtls", "dtls13"} {
		t.Run(channel, func(t *testing.T) {
			in := Inbound{Type: "openconnect", Tag: "server", Listen: "127.0.0.1", Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t)}
			if channel == "cstp" {
				in.RekeyTime = "2s"
				in.DisableDTLS = true
			} else {
				in.DTLSRekeyTime = "2s"
				if channel == "dtls13" {
					in.DTLSVersion = "1.3"
				}
			}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			host, port, _ := net.SplitHostPort(s.Address("server"))
			n, _ := shadowPort(port)
			c := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "openconnect", Tag: "proxy", Server: host, ServerPort: n, Username: "client", Password: "private", TLS: TLSOptions{Enabled: true, Insecure: true}, OpenConnectOptions: OpenConnectOptions{DisableDTLS: in.DisableDTLS, DTLSVersion: in.DTLSVersion}}}})
			client := c.ocClients["proxy"]
			tunnel, err := client.session(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			cookie := client.cookie
			var previous *ocDTLS
			if channel != "cstp" {
				previous = ocWaitDTLS(t, tunnel)
			}
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{1, 4096})
			if channel == "cstp" {
				select {
				case <-tunnel.finished:
				case <-time.After(4 * time.Second):
					t.Fatal("CSTP expiry ignored")
				}
				assertTCP(t, c)
				if client.tunnel.Load() == tunnel || client.cookie != cookie {
					t.Fatal("CSTP did not renew using cookie")
				}
			} else {
				deadline := time.Now().Add(6 * time.Second)
				for previous.ready.Load() && time.Now().Before(deadline) {
					time.Sleep(5 * time.Millisecond)
				}
				if previous.ready.Load() {
					t.Fatal("DTLS expiry ignored")
				}
				assertTCP(t, c)
				next := ocWaitDTLS(t, tunnel)
				if next == previous || client.tunnel.Load() != tunnel {
					t.Fatal("DTLS renewal recreated CSTP")
				}
				assertUDPSizes(t, c, []int{1, 4096})
				if next.sent.Load() == 0 || next.received.Load() == 0 {
					t.Fatal("renewal left traffic on CSTP")
				}
			}
		})
	}
}

func TestOpenConnectRekeyValidation(t *testing.T) {
	for _, value := range []string{"0", "0s", "-1s", "500ms", "1.5s", "169h", "invalid"} {
		if _, err := ocRekeyDuration(value); err == nil {
			t.Fatal("invalid rekey setting", value)
		}
	}
	for _, method := range []string{"new-tunnel", "ssl"} {
		for _, interval := range []string{"", "0", "-1", "1.5", "604801", "bad"} {
			if _, _, err := ocRekeyAdvice(http.Header{"X-Cstp-Rekey-Method": {method}, "X-Cstp-Rekey-Time": {interval}}, "CSTP"); err == nil {
				t.Fatal("invalid wire interval", interval)
			}
		}
	}
	if _, _, err := ocRekeyAdvice(http.Header{"X-Cstp-Rekey-Method": {"unknown"}}, "CSTP"); err == nil {
		t.Fatal("unknown method accepted")
	}
	in := Inbound{Type: "openconnect", Tag: "server", Listen: "127.0.0.1", Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t), OpenConnectOptions: OpenConnectOptions{RekeyTime: "1s", DTLSRekeyTime: "1s"}}
	b, _ := json.Marshal(Config{Inbounds: []Inbound{in}})
	if _, err := Parse(b); err != nil {
		t.Fatal(err)
	}
	in.DisableDTLS = true
	b, _ = json.Marshal(Config{Inbounds: []Inbound{in}})
	if _, err := Parse(b); err == nil {
		t.Fatal("disabled DTLS accepted rekey")
	}
	o := Outbound{Type: "openconnect", Tag: "proxy", Server: "127.0.0.1", ServerPort: 443, TLS: TLSOptions{Enabled: true}, OpenConnectOptions: OpenConnectOptions{RekeyTime: "1s"}}
	b, _ = json.Marshal(Config{Outbounds: []Outbound{o}})
	if _, err := Parse(b); err == nil {
		t.Fatal("server renewal policy accepted on outbound")
	}
}

func TestOpenConnectRekeySSLAdvice(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method != "CONNECT" {
					ocAuthReply(t, w, ocXML{Type: "complete", Token: "fixture-cookie"})
					return
				}
				conn, buffered, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				_, err = io.WriteString(conn, "HTTP/1.1 200 CONNECTED\r\nX-CSTP-Address: 10.44.0.2\r\nX-CSTP-Rekey-Method: ssl\r\nX-CSTP-Rekey-Time: 1\r\n\r\n")
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, buffered.Reader)
			}))
			server.TLS = &tls.Config{MinVersion: version, MaxVersion: version}
			server.StartTLS()
			t.Cleanup(server.Close)
			u, _ := url.Parse(server.URL)
			port, _ := shadowPort(u.Port())
			r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "openconnect", Tag: "proxy", Server: u.Hostname(), ServerPort: port, TLS: TLSOptions{Enabled: true, Insecure: true}, OpenConnectOptions: OpenConnectOptions{DisableDTLS: true}}}})
			tunnel, err := r.ocClients["proxy"].session(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if version == tls.VersionTLS12 {
				if tunnel.rekeyAfter != time.Second {
					t.Fatal("TLS1.2 ssl advice did not schedule a fresh tunnel")
				}
				select {
				case <-tunnel.finished:
				case <-time.After(2 * time.Second):
					t.Fatal("TLS1.2 ssl fallback did not close old channel")
				}
			} else if tunnel.rekeyAfter != 0 {
				t.Fatal("TLS1.3 KeyUpdate incorrectly scheduled a new tunnel")
			}
		})
	}
}
