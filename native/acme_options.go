package native

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

type ACMEOptions struct {
	DefaultServerName       string               `json:"default_server_name,omitempty"`
	Email                   string               `json:"email,omitempty"`
	Provider                string               `json:"provider,omitempty"`
	AccountKey              string               `json:"account_key,omitempty"`
	DisableHTTPChallenge    bool                 `json:"disable_http_challenge,omitempty"`
	DisableTLSALPNChallenge bool                 `json:"disable_tls_alpn_challenge,omitempty"`
	AlternativeHTTPPort     uint16               `json:"alternative_http_port,omitempty"`
	AlternativeTLSPort      uint16               `json:"alternative_tls_port,omitempty"`
	ExternalAccount         *ACMEExternalAccount `json:"external_account,omitempty"`
	DNS01Challenge          *ACMEDNSOptions      `json:"dns01_challenge,omitempty"`
	KeyType                 string               `json:"key_type,omitempty"`
	Profile                 string               `json:"profile,omitempty"`
}
type ACMEExternalAccount struct {
	KeyID  string `json:"key_id"`
	MACKey string `json:"mac_key"`
}
type ACMEDNSOptions struct {
	TTL                string   `json:"ttl,omitempty"`
	PropagationDelay   string   `json:"propagation_delay,omitempty"`
	PropagationTimeout string   `json:"propagation_timeout,omitempty"`
	Resolvers          []string `json:"resolvers,omitempty"`
	OverrideDomain     string   `json:"override_domain,omitempty"`
	Provider           string   `json:"provider"`
	APIToken           string   `json:"api_token,omitempty"`
	ZoneToken          string   `json:"zone_token,omitempty"`
	AccessKeyID        string   `json:"access_key_id,omitempty"`
	AccessKeySecret    string   `json:"access_key_secret,omitempty"`
	RegionID           string   `json:"region_id,omitempty"`
	SecurityToken      string   `json:"security_token,omitempty"`
	Username           string   `json:"username,omitempty"`
	Password           string   `json:"password,omitempty"`
	Subdomain          string   `json:"subdomain,omitempty"`
	ServerURL          string   `json:"server_url,omitempty"`
}

func (o ACMEOptions) empty() bool {
	return o.DefaultServerName == "" && o.Email == "" && o.Provider == "" && o.AccountKey == "" && !o.DisableHTTPChallenge && !o.DisableTLSALPNChallenge && o.AlternativeHTTPPort == 0 && o.AlternativeTLSPort == 0 && o.ExternalAccount == nil && o.DNS01Challenge == nil && o.KeyType == "" && o.Profile == ""
}

func acmeURL(address string) (*url.URL, error) {
	u, err := url.Parse(address)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("invalid ACME HTTPS URL")
	}
	ip, _ := netip.ParseAddr(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && (ip.IsLoopback() || u.Hostname() == "localhost")) {
		return nil, errors.New("ACME URLs require HTTPS outside loopback")
	}
	return u, nil
}
func (o *CertificateProviderOptions) normalizeACME() error {
	if o.APIToken != "" || o.OriginCAKey != "" || o.RequestType != "" || o.RequestedValidity != 0 {
		return errors.New("Cloudflare Origin CA options conflict with acme")
	}
	if len(o.Domain) == 0 || len(o.Domain) > 100 {
		return errors.New("ACME requires1-100 identifiers")
	}
	o.Domain = slices.Clone(o.Domain)
	hasIP := false
	for i, name := range o.Domain {
		if ip, err := netip.ParseAddr(name); err == nil {
			if ip.Zone() != "" {
				return errors.New("ACME IP identifiers cannot contain a zone")
			}
			o.Domain[i] = ip.Unmap().String()
			hasIP = true
			continue
		}
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		host := strings.TrimPrefix(name, "*.")
		if len(name) > 253 || !strings.Contains(host, ".") || !echDomain(host) {
			return errors.New("invalid ACME DNS identifier;use A-labels")
		}
		if strings.HasPrefix(name, "*.") && o.DNS01Challenge == nil {
			return errors.New("ACME wildcard identifiers require DNS01 challenge")
		}
		o.Domain[i] = name
	}
	slices.Sort(o.Domain)
	o.Domain = slices.Compact(o.Domain)
	if o.DefaultServerName != "" {
		if ip, err := netip.ParseAddr(o.DefaultServerName); err == nil {
			o.DefaultServerName = ip.Unmap().String()
		} else {
			o.DefaultServerName = strings.ToLower(strings.TrimSuffix(o.DefaultServerName, "."))
		}
		if !slices.ContainsFunc(o.Domain, func(n string) bool { return certificateNameMatches(n, o.DefaultServerName) }) {
			return errors.New("default_server_name must be managed by the ACME provider")
		}
	}
	if o.Email != "" {
		a, err := mail.ParseAddress(o.Email)
		if err != nil || a.Name != "" || a.Address != o.Email {
			return errors.New("invalid ACME email")
		}
	}
	switch o.Provider {
	case "", "letsencrypt":
		o.Provider = "https://acme-v02.api.letsencrypt.org/directory"
		if hasIP && o.Profile == "" {
			o.Profile = "shortlived"
		}
	case "zerossl":
		o.Provider = "https://acme.zerossl.com/v2/DV90"
		if o.ExternalAccount == nil && o.Email == "" && o.AccountKey == "" {
			return errors.New("ZeroSSL requires email,external_account or account_key")
		}
	}
	if _, err := acmeURL(o.Provider); err != nil {
		return err
	}
	if o.KeyType == "" {
		o.KeyType = "p256"
	}
	if !slices.Contains([]string{"p256", "p384", "ed25519", "rsa2048", "rsa4096"}, o.KeyType) {
		return errors.New("invalid ACME key_type")
	}
	if o.AccountKey != "" {
		if _, err := acmePrivateKey(o.AccountKey); err != nil {
			return err
		}
	}
	if o.ExternalAccount != nil {
		k, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimRight(o.ExternalAccount.MACKey, "="))
		if err != nil || len(k) < 32 || o.ExternalAccount.KeyID == "" {
			return errors.New("invalid ACME external account binding")
		}
	}
	if o.DNS01Challenge == nil && o.DisableHTTPChallenge && o.DisableTLSALPNChallenge {
		return errors.New("ACME requires at least one enabled challenge")
	}
	if o.DNS01Challenge != nil {
		if hasIP {
			return errors.New("ACME IP identifiers cannot use DNS01")
		}
		return o.DNS01Challenge.validate()
	}
	return nil
}
func (o ACMEDNSOptions) validate() error {
	switch o.Provider {
	case "cloudflare":
		if o.AccessKeyID != "" || o.AccessKeySecret != "" || o.RegionID != "" || o.SecurityToken != "" || o.Username != "" || o.Password != "" || o.Subdomain != "" || o.ServerURL != "" {
			return errors.New("conflicting Cloudflare DNS01 options")
		}
		if o.APIToken == "" {
			return errors.New("Cloudflare DNS01 requires api_token")
		}
	case "alidns":
		if o.APIToken != "" || o.ZoneToken != "" || o.Username != "" || o.Password != "" || o.Subdomain != "" || o.ServerURL != "" {
			return errors.New("conflicting AliDNS DNS01 options")
		}
		if o.AccessKeyID == "" || o.AccessKeySecret == "" {
			return errors.New("AliDNS requires access_key_id and access_key_secret")
		}
	case "acmedns":
		if o.APIToken != "" || o.ZoneToken != "" || o.AccessKeyID != "" || o.AccessKeySecret != "" || o.RegionID != "" || o.SecurityToken != "" {
			return errors.New("conflicting ACME-DNS options")
		}
		if o.Username == "" || o.Password == "" || o.Subdomain == "" {
			return errors.New("ACME-DNS requires username,password and subdomain")
		}
		if _, err := acmeURL(o.ServerURL); err != nil {
			return err
		}
	default:
		return errors.New("unimplemented DNS01 provider")
	}
	if strings.ContainsAny(o.APIToken+o.ZoneToken+o.AccessKeyID+o.SecurityToken+o.Username+o.Password, "\r\n\x00") {
		return errors.New("invalid DNS01 credential")
	}
	if o.OverrideDomain != "" && !validACMERecord(o.OverrideDomain) {
		return errors.New("invalid DNS01 override_domain")
	}
	for _, v := range []struct {
		value string
		max   time.Duration
	}{{o.TTL, 24 * time.Hour}, {o.PropagationDelay, 10 * time.Minute}} {
		if v.value != "" {
			d, e := time.ParseDuration(v.value)
			if e != nil || d < 0 || d > v.max || v.value == o.TTL && d < time.Second {
				return errors.New("invalid DNS01 duration")
			}
		}
	}
	if o.PropagationTimeout != "" && o.PropagationTimeout != "-1" {
		d, e := time.ParseDuration(o.PropagationTimeout)
		if e != nil || d <= 0 || d > 10*time.Minute {
			return errors.New("invalid DNS01 propagation_timeout")
		}
	}
	if len(o.Resolvers) > 16 {
		return errors.New("too many DNS01 resolvers")
	}
	for _, s := range o.Resolvers {
		if _, _, e := net.SplitHostPort(s); e != nil {
			if _, e = netip.ParseAddr(s); e != nil {
				return errors.New("DNS01 resolvers must be IP addresses with optional ports")
			}
		} else {
			h, port, _ := net.SplitHostPort(s)
			p, pe := strconv.ParseUint(port, 10, 16)
			if _, e := netip.ParseAddr(h); e != nil || pe != nil || p == 0 {
				return errors.New("DNS01 resolver requires an IP address and port1-65535")
			}
		}
	}
	return nil
}
func acmePrivateKey(text string) (crypto.Signer, error) {
	b, rest := pem.Decode([]byte(text))
	if b == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid ACME private key PEM")
	}
	var k any
	var err error
	switch b.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(b.Bytes)
	default:
		err = errors.New("unsupported key PEM")
	}
	if err != nil {
		return nil, errors.New("invalid ACME private key")
	}
	switch key := k.(type) {
	case *rsa.PrivateKey:
		if key.N.BitLen() < 2048 {
			return nil, errors.New("ACME RSA key must contain at least2048 bits")
		}
	case *ecdsa.PrivateKey:
	case ed25519.PrivateKey:
	default:
		return nil, errors.New("unsupported ACME account key")
	}
	return k.(crypto.Signer), nil
}
func acmeGenerateKey(kind string) (crypto.Signer, error) {
	switch kind {
	case "p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ed25519":
		_, k, e := ed25519.GenerateKey(rand.Reader)
		return k, e
	case "rsa4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	default:
		return rsa.GenerateKey(rand.Reader, 2048)
	}
}
