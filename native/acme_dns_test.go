package native

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestACMEReferenceDNS(t *testing.T) {
	f := newACMEFixture(t, false)
	for _, provider := range []string{"cloudflare", "alidns", "acmedns"} {
		for _, delegation := range []string{"direct", "cname", "override"} {
			t.Run(provider+"/"+delegation, func(t *testing.T) {
				name := "_acme-challenge.example.org"
				if delegation != "direct" {
					name = "proof.delegated.example.org"
				}
				f.mu.Lock()
				clear(f.txt)
				clear(f.aliases)
				if delegation != "direct" {
					f.aliases["_acme-challenge.example.org"] = name
				}
				f.mu.Unlock()
				var created, deleted atomic.Int32
				client, out := f.dnsAPI(t, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					respond := func(v any) { json.NewEncoder(w).Encode(v) }
					add := func(value string) {
						f.mu.Lock()
						f.txt[name] = append(f.txt[name], value)
						f.mu.Unlock()
						created.Add(1)
					}
					remove := func() { f.mu.Lock(); delete(f.txt, name); f.mu.Unlock(); deleted.Add(1) }
					switch provider {
					case "cloudflare":
						if r.Method == "GET" && r.URL.Path == "/client/v4/zones" {
							if r.Header.Get("Authorization") != "Bearer zone-secret" {
								t.Error("zone token missing")
								w.WriteHeader(401)
								return
							}
							result := []map[string]string{}
							if r.URL.Query().Get("name") == "example.org" {
								result = append(result, map[string]string{"id": "zone-id", "name": "example.org"})
							}
							respond(map[string]any{"success": true, "result": result})
							return
						}
						if r.Header.Get("Authorization") != "Bearer record-secret" {
							t.Error("record token missing")
							w.WriteHeader(401)
							return
						}
						if r.Method == "POST" && r.URL.Path == "/client/v4/zones/zone-id/dns_records" {
							var v struct {
								Type, Name, Content string
								TTL                 int
							}
							json.NewDecoder(r.Body).Decode(&v)
							if v.Type != "TXT" || v.Name != name || v.TTL != 120 || len(v.Content) != 43 {
								t.Error("incorrect Cloudflare TXT request", v)
							}
							add(v.Content)
							respond(map[string]any{"success": true, "result": map[string]string{"id": "record-id"}})
							return
						}
						if r.Method == "DELETE" && r.URL.Path == "/client/v4/zones/zone-id/dns_records/record-id" {
							remove()
							respond(map[string]any{"success": true})
							return
						}
					case "alidns":
						if r.Method != "POST" || r.ParseForm() != nil {
							w.WriteHeader(400)
							return
						}
						values := r.PostForm
						signature := values.Get("Signature")
						values.Del("Signature")
						keys := make([]string, 0, len(values))
						for k := range values {
							keys = append(keys, k)
						}
						slices.Sort(keys)
						// Verify the public RPC signing format independently of the product signer.
						escape := func(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }
						var fields []string
						for _, k := range keys {
							fields = append(fields, escape(k)+"="+escape(values.Get(k)))
						}
						mac := hmac.New(sha1.New, []byte("ali-secret&"))
						mac.Write([]byte("POST&%2F&" + escape(strings.Join(fields, "&"))))
						if signature != base64.StdEncoding.EncodeToString(mac.Sum(nil)) || values.Get("AccessKeyId") != "ali-id" || values.Get("SecurityToken") != "sts-token" || values.Get("RegionId") != "cn-hangzhou" || values.Get("SignatureNonce") == "" {
							t.Error("AliDNS signing/authentication failed")
							w.WriteHeader(403)
							return
						}
						switch values.Get("Action") {
						case "DescribeDomainInfo":
							if values.Get("DomainName") == "example.org" {
								respond(map[string]string{"DomainName": "example.org"})
							} else {
								respond(map[string]string{"Code": "DomainNotFound"})
							}
							return
						case "AddDomainRecord":
							if values.Get("RR") != strings.TrimSuffix(name, ".example.org") || values.Get("DomainName") != "example.org" || values.Get("Type") != "TXT" || values.Get("TTL") != "120" {
								t.Error("incorrect AliDNS TXT request", values.Get("RR"))
							}
							add(values.Get("Value"))
							respond(map[string]string{"RecordId": "ali-record"})
							return
						case "DeleteDomainRecord":
							if values.Get("RecordId") != "ali-record" {
								t.Error("incorrect record cleanup")
							}
							remove()
							respond(map[string]string{"RecordId": "ali-record"})
							return
						}
					case "acmedns":
						if r.Method == "POST" && r.URL.Path == "/update" && r.Header.Get("X-Api-User") == "dns-user" && r.Header.Get("X-Api-Key") == "dns-password" {
							var v struct{ Subdomain, Txt string }
							json.NewDecoder(r.Body).Decode(&v)
							if v.Subdomain != "delegated-id" || len(v.Txt) != 43 {
								t.Error("incorrect ACME-DNS request")
							}
							add(v.Txt)
							respond(map[string]string{"txt": v.Txt})
							return
						}
					}
					t.Error("unexpected DNS API request", r.Method, r.URL.Path)
					w.WriteHeader(400)
				})
				dns := &ACMEDNSOptions{Provider: provider, Resolvers: []string{f.dns.LocalAddr().String()}, TTL: "2m", PropagationDelay: "1ms", PropagationTimeout: "2s"}
				if delegation == "override" {
					dns.OverrideDomain = name
				}
				switch provider {
				case "cloudflare":
					dns.APIToken, dns.ZoneToken = "record-secret", "zone-secret"
				case "alidns":
					dns.AccessKeyID, dns.AccessKeySecret, dns.RegionID, dns.SecurityToken = "ali-id", "ali-secret", "cn-hangzhou", "sts-token"
				case "acmedns":
					dns.Username, dns.Password, dns.Subdomain, dns.ServerURL = "dns-user", "dns-password", "delegated-id", "https://auth.example.org"
				}
				o := f.options(t)
				o.Domain = []string{"*.example.org", "example.org"}
				o.DNS01Challenge = dns
				r := newTestRuntime(t, Config{CertificateProviders: []CertificateProviderOptions{o}, HTTPClients: []HTTPClientOptions{client}, Outbounds: []Outbound{out}})
				f.current(t, r.certificateProviders[o.Tag], "www.example.org")
				if created.Load() != 2 || provider != "acmedns" && deleted.Load() != 2 {
					t.Fatal("DNS challenge/cleanup count", created.Load(), deleted.Load())
				}
				f.mu.Lock()
				left := len(f.txt[name])
				f.mu.Unlock()
				if provider != "acmedns" && left != 0 {
					t.Fatal("TXT record leaked")
				}
			})
		}
	}
}

func TestACMEDNSPropagationCleanup(t *testing.T) {
	f := newACMEFixture(t, false)
	var removed atomic.Bool
	client, out := f.dnsAPI(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			fmt.Fprint(w, `{"success":true,"result":[{"id":"zone","name":"example.org"}]}`)
		case "POST":
			fmt.Fprint(w, `{"success":true,"result":{"id":"own-record"}}`)
		case "DELETE":
			if !strings.HasSuffix(r.URL.Path, "/own-record") {
				t.Error("deleted another record")
			}
			removed.Store(true)
			fmt.Fprint(w, `{"success":true}`)
		}
	})
	o := f.options(t)
	o.DNS01Challenge = &ACMEDNSOptions{Provider: "cloudflare", APIToken: "record-secret", Resolvers: []string{f.dns.LocalAddr().String()}, PropagationTimeout: "20ms"}
	r := newTestRuntime(t, Config{CertificateProviders: []CertificateProviderOptions{o}, HTTPClients: []HTTPClientOptions{client}, Outbounds: []Outbound{out}})
	_, e := r.certificateProviders[o.Tag].current(context.Background(), "example.org")
	if e == nil || !strings.Contains(e.Error(), "propagation") || !removed.Load() {
		t.Fatal("missing TXT must fail and clean up", e, removed.Load())
	}
}

func TestACMEDNSShutdownCleanup(t *testing.T) {
	for _, parent := range []bool{false, true} {
		t.Run(fmt.Sprint(parent), func(t *testing.T) {
			f := newACMEFixture(t, false)
			created, deleted := make(chan struct{}), make(chan struct{})
			client, out := f.dnsAPI(t, func(w http.ResponseWriter, r *http.Request) {
				// Force cleanup to establish a new connection; an idle keepalive would
				// hide an incorrect runtime shutdown order.
				w.Header().Set("Connection", "close")
				switch r.Method {
				case "GET":
					fmt.Fprint(w, `{"success":true,"result":[{"id":"zone","name":"example.org"}]}`)
				case "POST":
					fmt.Fprint(w, `{"success":true,"result":{"id":"own-record"}}`)
					close(created)
				case "DELETE":
					if !strings.HasSuffix(r.URL.Path, "/own-record") {
						t.Error("deleted another record")
					}
					fmt.Fprint(w, `{"success":true}`)
					close(deleted)
				}
			})
			o := f.options(t)
			o.DNS01Challenge = &ACMEDNSOptions{Provider: "cloudflare", APIToken: "record-secret", Resolvers: []string{f.dns.LocalAddr().String()}, PropagationTimeout: "10s"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			config := Config{CertificateProviders: []CertificateProviderOptions{o}, HTTPClients: []HTTPClientOptions{client}, Outbounds: []Outbound{out}}
			raw, _ := json.Marshal(config)
			r, e := New(ctx, raw, zap.NewNop())
			if e != nil {
				t.Fatal(e)
			}
			if e = r.Start(); e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { r.Close() })
			done := make(chan error, 1)
			go func() { _, e := r.certificateProviders[o.Tag].current(context.Background(), "example.org"); done <- e }()
			select {
			case <-created:
			case <-time.After(3 * time.Second):
				t.Fatal("TXT creation not reached")
			}
			deadline := time.Now().Add(3 * time.Second)
			for f.txtQueries.Load() == 0 {
				if time.Now().After(deadline) {
					t.Fatal("created TXT response was not processed")
				}
				time.Sleep(time.Millisecond)
			}
			closed := make(chan error, 1)
			if parent {
				cancel()
			}
			go func() { closed <- r.Close() }()
			select {
			case e := <-closed:
				if e != nil {
					t.Fatal(e)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("shutdown/cleanup blocked")
			}
			select {
			case <-deleted:
			default:
				t.Fatal("shutdown skipped DNS cleanup")
			}
			if e := <-done; e == nil {
				t.Fatal("cancelled issuance accepted")
			}

		})
	}
}
