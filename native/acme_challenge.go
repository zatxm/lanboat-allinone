package native

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

type acmeChallenge struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Token  string `json:"token"`
	Status string `json:"status"`
}
type acmeAuthorization struct {
	Identifier acmeIdentifier  `json:"identifier"`
	Wildcard   bool            `json:"wildcard"`
	Status     string          `json:"status"`
	Challenges []acmeChallenge `json:"challenges"`
}

func (c *acmeClient) authorize(ctx context.Context, address string) error {
	data, header, _, e := c.post(ctx, address, nil)
	if e != nil {
		return e
	}
	var auth acmeAuthorization
	if json.Unmarshal(data, &auth) != nil {
		return errors.New("invalid ACME authorization")
	}
	name := auth.Identifier.Value
	if auth.Wildcard {
		name = "*." + name
	}
	if !slices.Contains(c.p.options.Domain, name) || (auth.Identifier.Type != "dns" && auth.Identifier.Type != "ip") || auth.Identifier.Type == "ip" && auth.Wildcard {
		return errors.New("ACME authorization identifier was not requested")
	}
	if auth.Status == "valid" {
		return nil
	}
	if auth.Status != "pending" {
		return errors.New("ACME authorization is not pending")
	}
	thumb := sha256.Sum256(c.jwk)
	choices := []string{"http-01", "tls-alpn-01"}
	if c.p.options.DNS01Challenge != nil || c.p.tailscaleEndpoint != "" {
		choices = []string{"dns-01"}
	}
	var failure error
	var cleanup func()
	for _, typ := range choices {
		if typ == "http-01" && c.p.options.DisableHTTPChallenge || typ == "tls-alpn-01" && c.p.options.DisableTLSALPNChallenge {
			continue
		}
		for _, challenge := range auth.Challenges {
			if challenge.Type != typ {
				continue
			}
			token, e := base64.RawURLEncoding.Strict().DecodeString(challenge.Token)
			if e != nil || len(token) < 16 || len(token) > 1024 {
				return errors.New("invalid ACME challenge token")
			}
			if e = c.validateURL(challenge.URL); e != nil {
				return e
			}
			value := challenge.Token + "." + acmeB64(thumb[:])
			if c.p.tailscaleEndpoint != "" {
				cleanup, e = c.presentTailscaleDNS(ctx, auth.Identifier.Value, value)
			} else if typ == "dns-01" {
				cleanup, e = c.presentDNS(ctx, auth.Identifier.Value, value)
			} else {
				cleanup, e = c.p.r.acme.present(c.p, typ, auth.Identifier.Value, challenge.Token, value)
			}
			if e != nil {
				failure = errors.Join(failure, e)
				continue
			}
			defer cleanup()
			if _, header, _, e = c.post(ctx, challenge.URL, []byte("{}")); e != nil {
				return e
			}
			for range 120 {
				if e = c.pause(ctx, header); e != nil {
					return e
				}
				data, header, _, e = c.post(ctx, address, nil)
				if e != nil {
					return e
				}
				if json.Unmarshal(data, &auth) != nil {
					return errors.New("invalid ACME authorization response")
				}
				if auth.Status == "valid" {
					return nil
				}
				if auth.Status != "pending" && auth.Status != "processing" {
					return errors.New("ACME challenge validation failed")
				}
			}
			return errors.New("ACME authorization retry limit exceeded")
		}
	}
	if failure != nil {
		return failure
	}
	return errors.New("ACME server offered no enabled supported challenge")
}

type acmeChallengeListener struct {
	listener net.Listener
	http     *http.Server
	refs     int
	done     chan struct{}
}
type acmeChallenges struct {
	r         *Runtime
	gate      chan struct{}
	mu        sync.Mutex
	http      map[string]string
	tls       map[string]*tls.Certificate
	listeners map[string]*acmeChallengeListener
}

func (r *Runtime) initACME() {
	if r.acme == nil {
		r.acme = &acmeChallenges{r: r, gate: make(chan struct{}, 1), http: map[string]string{}, tls: map[string]*tls.Certificate{}, listeners: map[string]*acmeChallengeListener{}}
	}
}
func (h *acmeChallenges) present(p *managedCertificate, kind, name, token, value string) (func(), error) {
	port := p.options.AlternativeHTTPPort
	if port == 0 {
		port = 80
	}
	key := name + "\x00" + token
	var cert *tls.Certificate
	var e error
	if kind == "tls-alpn-01" {
		port = p.options.AlternativeTLSPort
		if port == 0 {
			port = 443
		}
		cert, e = acmeChallengeCertificate(name, value)
		if e != nil {
			return nil, e
		}
		if ip, err := netip.ParseAddr(name); err == nil {
			// RFC8738 uses reverse-IP SNI, with an IP SAN in the proof.
			name = tsDNSReverse(ip)
		}
	}
	service := kind + ":" + strconv.Itoa(int(port))
	h.mu.Lock()
	if kind == "http-01" {
		h.http[key] = value
	} else {
		h.tls[name] = cert
	}
	remove := func() {
		if kind == "http-01" {
			delete(h.http, key)
		} else {
			delete(h.tls, name)
		}
	}
	listener := h.listeners[service]
	if listener == nil {
		listener = &acmeChallengeListener{done: make(chan struct{})}
		raw, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(int(port))))
		if err != nil {
			if !h.sharedPort(p, kind, port) {
				remove()
				h.mu.Unlock()
				return nil, fmt.Errorf("ACME challenge listener: %w", err)
			}
			close(listener.done)
		} else {
			listener.listener = raw
			if kind == "http-01" {
				listener.http = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if !h.serveHTTP(w, r) {
						http.NotFound(w, r)
					}
				}), ErrorLog: zap.NewStdLog(h.r.logger), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 8192}
				go func() { defer close(listener.done); listener.http.Serve(raw) }()
			} else {
				listener.http = &http.Server{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: h.tlsConfig}, ErrorLog: zap.NewStdLog(h.r.logger), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 8192}
				go func() { defer close(listener.done); listener.http.Serve(tls.NewListener(raw, listener.http.TLSConfig)) }()
			}
		}
		h.listeners[service] = listener
	}
	listener.refs++
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		remove()
		listener.refs--
		last := listener.refs == 0
		if last {
			delete(h.listeners, service)
		}
		h.mu.Unlock()
		if last {
			if listener.http != nil {
				listener.http.Close()
			}
			<-listener.done
		}
	}, nil
}
func (h *acmeChallenges) sharedPort(p *managedCertificate, kind string, port uint16) bool {
	for _, in := range h.r.config.Inbounds {
		in = in.pluginTransport()
		if in.ListenPort != port {
			continue
		}
		if kind == "http-01" && !in.TLS.Enabled && (in.Type == "http" || in.Type == "mixed") {
			return true
		}
		if kind == "tls-alpn-01" && in.TLS.Enabled && h.r.certificateProviders[string(in.TLS.CertificateProvider)] == p {
			return true
		}
	}
	return false
}
func (h *acmeChallenges) serveHTTP(w http.ResponseWriter, r *http.Request) bool {
	value, ok := h.httpValue(r)
	if !ok {
		return false
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(value))
	return true
}
func (h *acmeChallenges) httpValue(r *http.Request) (string, bool) {
	const prefix = "/.well-known/acme-challenge/"
	if r.Method != "GET" || !strings.HasPrefix(r.URL.Path, prefix) || r.URL.RawQuery != "" {
		return "", false
	}
	host := r.Host
	if name, _, e := net.SplitHostPort(host); e == nil {
		host = name
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	h.mu.Lock()
	value, ok := h.http[host+"\x00"+strings.TrimPrefix(r.URL.Path, prefix)]
	h.mu.Unlock()
	return value, ok
}
func (h *acmeChallenges) tlsConfig(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	if len(hello.SupportedProtos) != 1 || hello.SupportedProtos[0] != "acme-tls/1" {
		return nil, errors.New("ACME challenge listener requires acme-tls/1")
	}
	h.mu.Lock()
	cert := h.tls[strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))]
	h.mu.Unlock()
	if cert == nil {
		return nil, errors.New("no active ACME TLS challenge for this identifier")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"acme-tls/1"}, Certificates: []tls.Certificate{*cert}}, nil
}
func (p *managedCertificate) wrapACMETLS(base *tls.Config) *tls.Config {
	c := base.Clone()
	load := base.GetConfigForClient
	c.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == "acme-tls/1" {
			return p.r.acme.tlsConfig(hello)
		}
		if load != nil {
			return load(hello)
		}
		return nil, nil
	}
	return c
}
func acmeChallengeCertificate(name, value string) (*tls.Certificate, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	digest := sha256.Sum256([]byte(value))
	extension, _ := asn1.Marshal(digest[:])
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, e
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}, Critical: true, Value: extension}}}
	if ip, e := netip.ParseAddr(name); e == nil {
		leaf.IPAddresses = []net.IP{net.IP(ip.AsSlice())}
	} else {
		leaf.DNSNames = []string{name}
	}
	der, e := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if e != nil {
		return nil, e
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
