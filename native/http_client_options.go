package native

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type ExperimentalOptions struct {
	ClashAPI  *ControllerOptions `json:"clash_api,omitempty"`
	CacheFile CacheFileOptions   `json:"cache_file,omitempty"`
}
type CacheFileOptions struct {
	Enabled       bool   `json:"enabled,omitempty"`
	Path          string `json:"path,omitempty"`
	CacheID       string `json:"cache_id,omitempty"`
	StoreFakeIP   bool   `json:"store_fakeip,omitempty"`
	StoreDNS      bool   `json:"store_dns,omitempty"`
	BufferSize    string `json:"buffer_size,omitempty"`
	FlushInterval string `json:"flush_interval,omitempty"`
}
type HTTPClientOptions struct {
	DialOptions
	Tag                    string                  `json:"tag,omitempty"`
	Engine                 string                  `json:"engine,omitempty"`
	Version                int                     `json:"version,omitempty"`
	DisableVersionFallback bool                    `json:"disable_version_fallback,omitempty"`
	Headers                map[string]headerValues `json:"headers,omitempty"`
	TLS                    TLSOptions              `json:"tls,omitempty"`
	Detour                 string                  `json:"detour,omitempty"`
}
type clientReference string

func (o HTTPClientOptions) validate() error {
	if err := o.DialOptions.validate(); err != nil {
		return err
	}
	if o.TLS.realityEnabled() {
		return errors.New("HTTP downloader Reality is configured through a proxy detour")
	}
	if o.Engine != "" && o.Engine != "go" && o.Engine != "apple" {
		return errors.New("HTTP client engine must be go or apple")
	}
	if o.Engine == "apple" {
		if o.Version != 0 || o.DisableVersionFallback {
			return errors.New("Apple HTTP engine does not support version overrides")
		}
		raw, _ := json.Marshal(o.TLS)
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &fields)
		allowed := map[string]bool{"enabled": true, "server_name": true, "insecure": true, "min_version": true, "max_version": true, "certificate": true, "certificate_path": true, "certificate_sha256": true, "certificate_public_key_sha256": true}
		for name := range fields {
			if !allowed[name] {
				return fmt.Errorf("Apple HTTP engine does not support tls.%s", name)
			}
		}
	}
	if o.Version < 0 || o.Version > 3 {
		return errors.New("HTTP client version must be1,2 or3")
	}
	if o.Version == 3 {
		if err := o.TLS.validateQUICVersion(); err != nil {
			return err
		}
	}
	for k, values := range o.Headers {
		if len(values) == 0 || k == "" {
			return errors.New("empty HTTP header values")
		}
		if err := validateHTTPHeader(k, values); err != nil {
			return err
		}
	}
	return nil
}

func validateHTTPHeader(name string, values []string) error {
	if name == "" {
		return errors.New("empty HTTP header name")
	}
	for _, c := range name {
		if c <= 32 || c >= 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={}", c) {
			return errors.New("invalid HTTP header name")
		}
	}
	for _, v := range values {
		for _, c := range v {
			if c < 32 && c != '\t' || c == 127 {
				return errors.New("invalid HTTP header value")
			}
		}
	}
	return nil
}

func (r *clientReference) UnmarshalJSON(raw []byte) error {
	var tag string
	if json.Unmarshal(raw, &tag) == nil {
		*r = clientReference(tag)
		return nil
	}
	var o HTTPClientOptions
	if e := decodeOptions(raw, &o); e != nil {
		return e
	}
	*r = clientReference(raw)
	return nil
}
func (r clientReference) MarshalJSON() ([]byte, error) {
	if len(r) > 0 && r[0] == '{' {
		return []byte(r), nil
	}
	return json.Marshal(string(r))
}
func (r *Runtime) httpClientOptions(ref clientReference) (HTTPClientOptions, error) {
	if len(ref) > 0 && ref[0] == '{' {
		var o HTTPClientOptions
		e := decodeOptions([]byte(ref), &o)
		o.namespace = r.namespaces[o.NetNS]
		return o, e
	}
	tag := string(ref)
	if tag == "" {
		tag = r.config.Route.DefaultHTTPClient
		if tag == "" && len(r.config.HTTPClients) > 0 {
			return r.config.HTTPClients[0], nil
		}
	}
	if tag == "" {
		return HTTPClientOptions{}, nil
	}
	for _, o := range r.config.HTTPClients {
		if o.Tag == tag {
			return o, nil
		}
	}
	return HTTPClientOptions{}, fmt.Errorf("unknown HTTP client %q", tag)
}

type httpClientTransport interface {
	http.RoundTripper
	CloseIdleConnections()
}

func (r *Runtime) ruleHTTPClient(s RuleSet) (*http.Client, httpClientTransport, error) {
	o, e := r.httpClientOptions(s.HTTPClient)
	if e != nil {
		return nil, nil, e
	}
	if e := o.validate(); e != nil {
		return nil, nil, e
	}
	tlsOptions := o.TLS
	tlsOptions.Enabled = true
	config, e := tlsOptions.config(false, "")
	if e != nil {
		return nil, nil, e
	}
	if o.Version == 1 {
		config.NextProtos = []string{"http/1.1"}
	}
	transport := &http.Transport{TLSClientConfig: config, ForceAttemptHTTP2: o.Version != 1, MaxIdleConns: 1, IdleConnTimeout: time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		tag := o.Detour
		if tag == "" {
			tag = s.DownloadDetour
		}
		if tag != "" {
			return r.dialOutbound(ctx, tag, network, address)
		}
		if len(s.HTTPClient) == 0 && len(r.config.HTTPClients) == 0 && r.config.Route.DefaultHTTPClient == "" {
			return r.dialOutbound(ctx, r.config.Route.Final, network, address)
		}
		return r.directWithOptions(ctx, o.DialOptions, network, address)
	}}
	if tlsOptions.KernelTX || tlsOptions.KernelRX || tlsOptions.RecordFragment || tlsOptions.Fragment || tlsOptions.DisableSNI || tlsOptions.ECH != nil && tlsOptions.ECH.Enabled {
		transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			hostname, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			options, err := tlsOptions.config(false, hostname)
			if err != nil {
				return nil, err
			}
			options, err = prepareClientTLS(ctx, options, tlsOptions, r.resolver)
			if err != nil {
				return nil, err
			}
			options.NextProtos = transport.TLSClientConfig.NextProtos
			raw, err := transport.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			secured := clientTLS(raw, options, tlsOptions)
			if err := secured.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return secured, nil
		}
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return errors.New("unsafe rule_set redirect")
		}
		if req.URL.User != nil {
			return errors.New("credentials in rule_set redirect are forbidden")
		}
		if req.URL.Host != via[0].URL.Host || req.URL.Scheme != via[0].URL.Scheme {
			for key := range req.Header {
				if !strings.EqualFold(key, "User-Agent") && !strings.EqualFold(key, "Accept") && !strings.EqualFold(key, "Accept-Encoding") {
					delete(req.Header, key)
				}
			}
			req.Host = ""
		}
		return nil
	}}
	if o.Engine == "apple" {
		apple, err := newAppleHTTPTransport(r, o, s)
		if err != nil {
			return nil, nil, err
		}
		client.Transport = apple
		return client, apple, nil
	}
	if o.Version == 3 {
		h3 := &http3Transport{runtime: r, options: o, fallback: transport}
		client.Transport = h3
		return client, h3, nil
	}
	return client, transport, nil
}
