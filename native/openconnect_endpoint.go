package native

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type ocEndpointTLS struct {
	TLSOptions
	CertificateAuthority     []string `json:"certificate_authority,omitempty"`
	CertificateAuthorityPath string   `json:"certificate_authority_path,omitempty"`
	PeerFingerprint          []string `json:"peer_fingerprint,omitempty"`
	SystemTrustDisabled      bool     `json:"system_trust_disabled,omitempty"`
	pins                     []ocEndpointPin
}

type ocEndpointPin struct{ kind, prefix string }

type ocFormEntry struct {
	FormID        string `json:"form_id,omitempty"`
	SubmissionKey string `json:"submission_key,omitempty"`
	Name          string `json:"name,omitempty"`
	Value         string `json:"value,omitempty"`
	Promote       bool   `json:"promote,omitempty"`
}

type ocEndpointOptions struct {
	DialOptions
	OpenConnectOptions
	masqueNATOptions
	Type                           string            `json:"type"`
	Tag                            string            `json:"tag,omitempty"`
	Server                         string            `json:"server"`
	Flavor                         string            `json:"flavor,omitempty"`
	Username                       string            `json:"username,omitempty"`
	Password                       string            `json:"password,omitempty"`
	AuthGroup                      string            `json:"auth_group,omitempty"`
	Cookie                         string            `json:"cookie,omitempty"`
	UserAgent                      string            `json:"user_agent,omitempty"`
	ReportedOS                     string            `json:"reported_os,omitempty"`
	Version                        string            `json:"version,omitempty"`
	LocalHostname                  string            `json:"local_hostname,omitempty"`
	NoUDP                          bool              `json:"no_udp,omitempty"`
	IPv6Disabled                   bool              `json:"ipv6_disabled,omitempty"`
	HTTPKeepaliveDisabled          bool              `json:"http_keepalive_disabled,omitempty"`
	XMLPostDisabled                bool              `json:"xml_post_disabled,omitempty"`
	ExternalAuthDisabled           bool              `json:"external_auth_disabled,omitempty"`
	PasswordAuthenticationDisabled bool              `json:"password_authentication_disabled,omitempty"`
	OnDemand                       bool              `json:"on_demand,omitempty"`
	MTU                            int               `json:"mtu,omitempty"`
	BaseMTU                        int               `json:"base_mtu,omitempty"`
	DPDInterval                    string            `json:"dpd_interval,omitempty"`
	FormEntries                    []ocFormEntry     `json:"form_entries,omitempty"`
	TLS                            ocEndpointTLS     `json:"tls,omitempty"`
	Detour                         string            `json:"detour,omitempty"`
	DomainResolver                 resolverReference `json:"domain_resolver,omitempty"`
	path                           string
	dpd                            time.Duration
}

func (e *ocEndpointOptions) outbound() (Outbound, error) {
	if e.Flavor != "" && e.Flavor != "anyconnect" {
		return Outbound{}, errors.New("OpenConnect endpoint supports the anyconnect flavor")
	}
	text := e.Server
	if !strings.Contains(text, "://") {
		text = "https://" + text
	}
	u, err := url.Parse(text)
	if err != nil || len(e.Server) > 8192 || u.Scheme != "https" || u.Hostname() == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.ContainsAny(e.Server, "#\x00\r\n\t ") {
		return Outbound{}, errors.New("OpenConnect server must be an HTTPS URL without user information, query or fragment")
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err != nil {
		if !masqueDomain(strings.TrimSuffix(host, "."), false) {
			return Outbound{}, errors.New("invalid OpenConnect server host")
		}
	} else if ip.IsUnspecified() || ip.IsMulticast() || ip.Is4In6() || ip.Zone() != "" {
		return Outbound{}, errors.New("invalid OpenConnect server address")
	}
	port := uint64(443)
	if u.Port() != "" {
		port, err = strconv.ParseUint(u.Port(), 10, 16)
		if err != nil || port == 0 {
			return Outbound{}, errors.New("invalid OpenConnect server port")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return Outbound{}, errors.New("empty OpenConnect server port")
	}
	e.path = u.EscapedPath()
	if e.path == "" {
		e.path = "/"
	}
	if e.Cookie != "" && !ocValidCookie(e.Cookie) {
		return Outbound{}, errors.New("invalid OpenConnect session cookie")
	}
	for _, v := range []string{e.UserAgent, e.ReportedOS, e.Version, e.LocalHostname} {
		if len(v) > 255 || strings.ContainsAny(v, "\x00\r\n") {
			return Outbound{}, errors.New("invalid OpenConnect client identity")
		}
	}
	if e.Group != "" && e.AuthGroup != "" && e.Group != e.AuthGroup {
		return Outbound{}, errors.New("OpenConnect group conflicts with auth_group")
	}
	if e.AuthGroup != "" {
		e.Group = e.AuthGroup
	}
	e.DisableDTLS = e.DisableDTLS || e.NoUDP
	e.DisableExternalAuth = e.DisableExternalAuth || e.ExternalAuthDisabled
	if e.BaseMTU < 0 || e.BaseMTU > 65535 {
		return Outbound{}, errors.New("OpenConnect base_mtu must be0-65535")
	}
	if e.BaseMTU != 0 {
		e.BaseMTU = max(1280, e.BaseMTU)
	}
	if e.DPDInterval != "" {
		e.dpd, err = optionDuration(e.DPDInterval, 0)
		if err != nil || e.dpd > 24*time.Hour {
			return Outbound{}, errors.New("invalid OpenConnect dpd_interval")
		}
		if e.dpd > 0 {
			e.dpd = max(e.dpd, 2*time.Second)
		}
	}
	if len(e.FormEntries) > 128 {
		return Outbound{}, errors.New("too many OpenConnect form_entries")
	}
	for _, f := range e.FormEntries {
		name := f.SubmissionKey
		if name == "" {
			name = f.Name
			if f.FormID == "" || len(f.FormID) > 128 || strings.ContainsRune(f.FormID, 0) {
				return Outbound{}, errors.New("OpenConnect form entry requires form_id and name, or submission_key")
			}
		}
		if !ocFieldName(name) || len(f.Value) > 8192 || strings.ContainsRune(f.Value, 0) || f.Promote && f.Value != "" {
			return Outbound{}, errors.New("invalid OpenConnect form entry")
		}
	}
	if _, err := e.masqueNATOptions.settings(); err != nil {
		return Outbound{}, err
	}
	t := &e.TLS
	if len(t.CertificateSHA256)+len(t.CertificatePublicKeySHA256) != 0 && (t.SystemTrustDisabled || len(t.PeerFingerprint)+len(t.CertificateAuthority) != 0 || t.CertificateAuthorityPath != "") {
		return Outbound{}, errors.New("native TLS pins conflict with OpenConnect trust fields")
	}
	if len(t.CertificateAuthority) != 0 && t.CertificateAuthorityPath != "" || (len(t.CertificateAuthority) != 0 || t.CertificateAuthorityPath != "") && (len(t.Certificate) != 0 || t.CertificatePath != "") {
		return Outbound{}, errors.New("conflicting OpenConnect certificate authority fields")
	}
	if len(t.CertificateAuthority) != 0 {
		t.Certificate = t.CertificateAuthority
	}
	if t.CertificateAuthorityPath != "" {
		t.CertificatePath = t.CertificateAuthorityPath
	}
	if t.SystemTrustDisabled && len(t.Certificate) == 0 && t.CertificatePath == "" && len(t.PeerFingerprint) == 0 && !t.Insecure {
		return Outbound{}, errors.New("OpenConnect system_trust_disabled requires a trust source")
	}
	if len(t.PeerFingerprint) > 64 || len(t.PeerFingerprint) != 0 && len(t.CertificateSHA256)+len(t.CertificatePublicKeySHA256) != 0 {
		return Outbound{}, errors.New("invalid or conflicting OpenConnect peer fingerprints")
	}
	t.pins = nil
	for _, raw := range t.PeerFingerprint {
		pin := ocEndpointPin{prefix: raw}
		if kind, prefix, ok := strings.Cut(raw, ":"); ok {
			pin.kind, pin.prefix = kind, prefix
		}
		limit, alphabet := 40, "0123456789abcdef"
		switch pin.kind {
		case "", "sha1":
		case "sha256":
			limit = 64
		case "pin-sha256":
			limit, alphabet = 44, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
		default:
			return Outbound{}, errors.New("unknown OpenConnect peer fingerprint type")
		}
		if pin.kind != "pin-sha256" {
			pin.prefix = strings.ToLower(pin.prefix)
		}
		if len(pin.prefix) < 4 || len(pin.prefix) > limit || strings.ContainsFunc(pin.prefix, func(r rune) bool { return !strings.ContainsRune(alphabet, r) }) || strings.Contains(pin.prefix, "=") && (len(pin.prefix) != 44 || strings.Count(pin.prefix, "=") != 1 || pin.prefix[43] != '=') {
			return Outbound{}, errors.New("invalid OpenConnect peer fingerprint")
		}
		t.pins = append(t.pins, pin)
	}
	t.Enabled = true
	return Outbound{Type: "openconnect", Tag: e.Tag, Server: host, ServerPort: uint16(port), Username: e.Username, Password: e.Password, MTU: e.MTU, TLS: t.TLSOptions, DialOptions: e.DialOptions, Detour: e.Detour, DomainResolver: e.DomainResolver, OpenConnectOptions: e.OpenConnectOptions, ocEndpoint: e}, nil
}

func (e *ocEndpointOptions) field(form, name string) (string, bool, bool) {
	var value string
	var found, promote bool
	for _, f := range e.FormEntries {
		if f.SubmissionKey == name || f.SubmissionKey == "" && f.FormID == form && f.Name == name {
			value, found, promote = f.Value, true, f.Promote
		}
	}
	return value, found, promote
}

func (e *ocEndpointOptions) configureTLS(c *tls.Config) error {
	o := e.TLS
	if len(o.pins) == 0 && !o.SystemTrustDisabled && len(o.CertificateAuthority) == 0 && o.CertificateAuthorityPath == "" {
		return nil
	}
	roots := x509.NewCertPool()
	if !o.SystemTrustDisabled {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			return err
		}
	}
	cert := []byte(strings.Join(o.Certificate, "\n"))
	if o.CertificatePath != "" {
		var err error
		cert, err = os.ReadFile(o.CertificatePath)
		if err != nil {
			return err
		}
	}
	if len(cert) != 0 && !roots.AppendCertsFromPEM(cert) {
		return errors.New("invalid OpenConnect certificate authority")
	}
	c.InsecureSkipVerify = true
	c.VerifyConnection = func(s tls.ConnectionState) error {
		if len(s.PeerCertificates) == 0 {
			return errors.New("OpenConnect TLS peer supplied no certificate")
		}
		leaf := s.PeerCertificates[0]
		for _, pin := range o.pins {
			var actual string
			switch pin.kind {
			case "":
				h := sha1.Sum(leaf.Raw)
				actual = hex.EncodeToString(h[:])
			case "sha1":
				h := sha1.Sum(leaf.RawSubjectPublicKeyInfo)
				actual = hex.EncodeToString(h[:])
			case "sha256":
				h := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
				actual = hex.EncodeToString(h[:])
			case "pin-sha256":
				h := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
				actual = base64.StdEncoding.EncodeToString(h[:])
			}
			if strings.HasPrefix(actual, pin.prefix) {
				return nil
			}
		}
		if len(o.pins) != 0 {
			return errors.New("OpenConnect TLS peer fingerprint mismatch")
		}
		if o.Insecure {
			return nil
		}
		return verifyTLSChain(s, roots, c.ServerName, false)
	}
	return nil
}

// DisconnectOpenConnect releases an on-demand endpoint; Dial or authentication reconnects it.
func (r *Runtime) DisconnectOpenConnect(tag string) error {
	c := r.ocClients[tag]
	if c == nil || c.o.ocEndpoint == nil || !c.o.ocEndpoint.OnDemand || r.ctx.Err() != nil {
		return fmt.Errorf("disconnect requires an on_demand OpenConnect endpoint: %q", tag)
	}
	c.reset()
	return nil
}

func (c *ocClient) userAgent() string {
	if e := c.o.ocEndpoint; e != nil && e.UserAgent != "" {
		return e.UserAgent
	}
	return "Open AnyConnect VPN Agent Lanboat/1.0"
}

func (c *ocClient) endpointTransport(ctx context.Context, o Outbound, network string) (net.Conn, error) {
	if o.ocEndpoint == nil || o.Detour == "" || o.DomainResolver == "" {
		return c.r.endpoint(ctx, o, network)
	}
	call, cancel := o.DomainResolver.apply(ctx)
	defer cancel()
	call = context.WithValue(call, dnsBootstrapKey{}, o.DomainResolver.tag())
	ips, err := c.r.directIPs(call, o.Server)
	if err != nil {
		return nil, err
	}
	var last error = errors.New("OpenConnect peer has no resolved address")
	for _, ip := range ips[:min(len(ips), 16)] {
		o.Server = ip.String()
		conn, err := c.r.endpoint(call, o, network)
		if err == nil {
			return conn, nil
		}
		last = err
		if call.Err() != nil {
			return nil, call.Err()
		}
	}
	return nil, last
}

func (c *ocClient) configureEndpointIP(p *ipEndpoint) {
	if e := c.o.ocEndpoint; e != nil {
		p.inbound = e.Tag
		p.nat = c.nat
		settings, _ := e.masqueNATOptions.settings()
		p.udpIdleTimeout = settings.timeout
	}
}

func (c *ocClient) endpointOrigin() *url.URL {
	u := &url.URL{Scheme: "https", Host: portAddress(c.o.Server, c.o.ServerPort), Path: "/"}
	if e := c.o.ocEndpoint; e != nil {
		path, _ := url.PathUnescape(e.path)
		u.Path, u.RawPath = path, e.path
	}
	return u
}

func (c *ocClient) endpointIdentity(message *ocXML) {
	if e := c.o.ocEndpoint; e != nil {
		if e.Version != "" && message.Agent != nil {
			message.Agent.Value = e.Version
		}
		if e.ReportedOS != "" {
			message.Device = e.ReportedOS
		}
	}
}
