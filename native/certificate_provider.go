package native

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

type CertificateProviderOptions struct {
	ACMEOptions
	Type              string          `json:"type"`
	Tag               string          `json:"tag,omitempty"`
	Endpoint          string          `json:"endpoint,omitempty"`
	Domain            []string        `json:"domain"`
	DataDirectory     string          `json:"data_directory,omitempty"`
	APIToken          string          `json:"api_token,omitempty"`
	OriginCAKey       string          `json:"origin_ca_key,omitempty"`
	RequestType       string          `json:"request_type,omitempty"`
	RequestedValidity int             `json:"requested_validity,omitempty"`
	HTTPClient        clientReference `json:"http_client,omitempty"`
}

type certificateReference string

func (r *certificateReference) UnmarshalJSON(raw []byte) error {
	var tag string
	if json.Unmarshal(raw, &tag) == nil {
		if strings.HasPrefix(tag, "{") {
			return errors.New("certificate provider tags cannot start with an opening brace")
		}
		*r = certificateReference(tag)
		return nil
	}
	var o CertificateProviderOptions
	if err := decodeOptions(raw, &o); err != nil {
		return err
	}
	if o.Tag != "" {
		return errors.New("inline certificate providers cannot have a tag")
	}
	if err := o.normalize(); err != nil {
		return err
	}
	*r = certificateReference(raw)
	return nil
}

func (r certificateReference) MarshalJSON() ([]byte, error) {
	if r.inline() {
		return []byte(r), nil
	}
	return json.Marshal(string(r))
}

func (r certificateReference) inline() bool { return len(r) > 0 && r[0] == '{' }

func (o *CertificateProviderOptions) normalize() error {
	if o.Type == "tailscale" {
		if o.Endpoint == "" {
			return errors.New("Tailscale certificate provider requires endpoint")
		}
		if !o.ACMEOptions.empty() || len(o.Domain) != 0 || o.DataDirectory != "" || o.HTTPClient != "" || o.APIToken != "" || o.OriginCAKey != "" || o.RequestType != "" || o.RequestedValidity != 0 {
			return errors.New("Tailscale certificates use the endpoint identity and state;other provider options conflict")
		}
		return nil
	}
	if o.Endpoint != "" {
		return errors.New("certificate provider endpoint requires type tailscale")
	}
	if o.Type == "acme" {
		return o.normalizeACME()
	}
	if o.Type != "cloudflare-origin-ca" {
		return fmt.Errorf("unimplemented certificate provider type %q", o.Type)
	}
	if !o.ACMEOptions.empty() {
		return errors.New("ACME options require acme certificate provider")
	}
	if (o.APIToken == "") == (o.OriginCAKey == "") {
		return errors.New("Cloudflare certificate provider requires exactly one of api_token and origin_ca_key")
	}
	if strings.ContainsAny(o.APIToken+o.OriginCAKey, "\r\n\x00") {
		return errors.New("invalid Cloudflare certificate credential")
	}
	if len(o.Domain) == 0 || len(o.Domain) > 100 {
		return errors.New("Cloudflare certificate provider requires1-100 domains")
	}
	o.Domain = slices.Clone(o.Domain)
	for i, name := range o.Domain {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		host := strings.TrimPrefix(name, "*.")
		if len(name) > 253 || !strings.Contains(host, ".") || !echDomain(host) {
			return errors.New("certificate domains must be DNS A-labels or single-level wildcard DNS names")
		}
		o.Domain[i] = name
	}
	slices.Sort(o.Domain)
	o.Domain = slices.Compact(o.Domain)
	if o.RequestType == "" {
		o.RequestType = "origin-rsa"
	}
	if o.RequestType != "origin-rsa" && o.RequestType != "origin-ecc" {
		return errors.New("Cloudflare request_type must be origin-rsa or origin-ecc")
	}
	if o.RequestedValidity == 0 {
		o.RequestedValidity = 5475
	}
	if !slices.Contains([]int{7, 30, 90, 365, 730, 1095, 5475}, o.RequestedValidity) {
		return errors.New("invalid Cloudflare requested_validity")
	}
	return nil
}

func (o TLSOptions) validateCertificateProvider(server bool) error {
	if o.CertificateProvider == "" {
		return nil
	}
	if !server || !o.Enabled || o.realityEnabled() {
		return errors.New("certificate_provider requires inbound TLS without Reality")
	}
	if len(o.Certificate)+len(o.Key) != 0 || o.CertificatePath != "" || o.KeyPath != "" || o.PKCS12 != "" || o.PKCS12Path != "" {
		return errors.New("certificate_provider conflicts with a static TLS identity")
	}
	if o.CertificateProvider.inline() {
		var options CertificateProviderOptions
		if err := decodeOptions([]byte(o.CertificateProvider), &options); err != nil {
			return err
		}
		return options.normalize()
	}
	return nil
}

func (c Config) validateCertificateProviders() error {
	providers := make(map[string]bool)
	r := &Runtime{config: c}
	validate := func(o CertificateProviderOptions) error {
		if err := o.normalize(); err != nil {
			return err
		}
		if o.Type == "tailscale" {
			if !slices.ContainsFunc(c.Outbounds, func(endpoint Outbound) bool { return endpoint.Tag == o.Endpoint && endpoint.Type == "tailscale" }) {
				return errors.New("Tailscale certificate provider requires a Tailscale endpoint tag")
			}
			return nil
		}
		http, err := r.httpClientOptions(o.HTTPClient)
		if err != nil {
			return err
		}
		if err := http.validate(); err != nil {
			return err
		}
		if http.Detour != "" && !slices.ContainsFunc(c.Outbounds, func(out Outbound) bool { return out.Tag == http.Detour }) {
			return errors.New("unknown certificate provider HTTP client detour")
		}
		http.TLS.Enabled = true
		_, err = http.TLS.config(false, "")
		return err
	}
	for _, options := range c.CertificateProviders {
		if options.Tag == "" || strings.HasPrefix(options.Tag, "{") || providers[options.Tag] {
			return errors.New("certificate provider tags must be unique and nonempty")
		}
		providers[options.Tag] = true
		if err := validate(options); err != nil {
			return err
		}
	}
	for _, in := range c.Inbounds {
		options := in.pluginTransport().TLS
		if err := options.validateCertificateProvider(true); err != nil {
			return err
		}
		ref := options.CertificateProvider
		if ref.inline() {
			var options CertificateProviderOptions
			if err := decodeOptions([]byte(ref), &options); err != nil {
				return err
			}
			if err := validate(options); err != nil {
				return err
			}
		} else if ref != "" && !providers[string(ref)] {
			return fmt.Errorf("unknown certificate_provider %q", ref)
		}
	}
	return nil
}

func (r *Runtime) certificateProvider(ref certificateReference) (*managedCertificate, error) {
	if p := r.certificateProviders[string(ref)]; p != nil {
		return p, nil
	}
	var options CertificateProviderOptions
	if err := decodeOptions([]byte(ref), &options); err != nil {
		return nil, err
	}
	if err := options.normalize(); err != nil {
		return nil, err
	}
	if p := r.existingTailscaleCertificate(options); p != nil {
		r.certificateProviders[string(ref)] = p
		return p, nil
	}
	p := &managedCertificate{r: r, options: options, now: time.Now}
	if options.Type == "acme" || options.Type == "tailscale" {
		r.initACME()
	}
	r.certificateProviders[string(ref)] = p
	return p, nil
}
