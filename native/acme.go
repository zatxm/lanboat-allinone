package native

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type acmeAccountState struct {
	Version  int    `json:"version"`
	Provider string `json:"provider"`
	Email    string `json:"email"`
	Key      string `json:"key"`
	URL      string `json:"url"`
}
type acmeCertificateState struct {
	Version     int      `json:"version"`
	Domains     []string `json:"domains"`
	Provider    string   `json:"provider"`
	KeyType     string   `json:"key_type"`
	Profile     string   `json:"profile"`
	Certificate string   `json:"certificate"`
	PrivateKey  string   `json:"private_key"`
}

func (p *managedCertificate) acmePath(kind string) (string, error) {
	dir := p.options.DataDirectory
	if dir == "" {
		home, e := os.UserHomeDir()
		if e != nil {
			return "", e
		}
		dir = filepath.Join(home, ".lanboat-allinone", "certificates")
	}
	var id []byte
	if kind == "account" {
		thumb := ""
		if p.options.AccountKey != "" {
			key, e := acmePrivateKey(p.options.AccountKey)
			if e != nil {
				return "", e
			}
			jwk, _, _, e := acmeJWK(key)
			if e != nil {
				return "", e
			}
			thumb = acmeB64(jwk)
		}
		id = acmeJSON([]any{p.options.Provider, p.options.Email, thumb})
	} else {
		id = acmeJSON([]any{p.options.Domain, p.options.Provider, p.options.KeyType, p.options.Profile})
	}
	return filepath.Join(dir, fmt.Sprintf("acme-%s-%x.json", kind, sha256.Sum256(id))), nil
}
func readCertificateJSON(path string, v any) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, originCAMaxResponse+1))
	if e != nil || len(b) > originCAMaxResponse {
		return errors.New("invalid certificate state size")
	}
	if decodeOptions(b, v) != nil {
		return errors.New("invalid certificate state JSON")
	}
	return nil
}
func saveCertificateJSON(path string, v any) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if len(b) > originCAMaxResponse {
		return errors.New("certificate state exceeds1MiB")
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".certificate-*.tmp")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func (p *managedCertificate) parseACME(s acmeCertificateState) (*tls.Certificate, error) {
	if s.Version != 1 || !slices.Equal(s.Domains, p.options.Domain) || s.Provider != p.options.Provider || s.KeyType != p.options.KeyType || s.Profile != p.options.Profile {
		return nil, errors.New("ACME certificate cache does not match request parameters")
	}
	pair, e := tls.X509KeyPair([]byte(s.Certificate), []byte(s.PrivateKey))
	if e != nil {
		return nil, errors.New("invalid ACME certificate/key pair")
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, e
	}
	pair.Leaf = leaf
	if leaf.IsCA || !leaf.NotAfter.After(leaf.NotBefore) {
		return nil, errors.New("invalid ACME leaf certificate")
	}
	if len(leaf.ExtKeyUsage) > 0 && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil, errors.New("ACME certificate does not permit server authentication")
	}
	for _, n := range p.options.Domain {
		if ip, e := netip.ParseAddr(n); e == nil {
			if !slices.ContainsFunc(leaf.IPAddresses, func(a net.IP) bool { return a.Equal(net.IP(ip.AsSlice())) }) {
				return nil, errors.New("ACME certificate is missing requested IP")
			}
		} else if !slices.ContainsFunc(leaf.DNSNames, func(v string) bool { return strings.EqualFold(n, v) }) {
			return nil, errors.New("ACME certificate is missing requested DNS name")
		}
	}
	kind := ""
	switch k := pair.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		if k.Curve.Params().BitSize == 256 {
			kind = "p256"
		} else if k.Curve.Params().BitSize == 384 {
			kind = "p384"
		}
	case *rsa.PrivateKey:
		kind = fmt.Sprintf("rsa%d", k.N.BitLen())
	case ed25519.PrivateKey:
		kind = "ed25519"
	}
	if kind != p.options.KeyType {
		return nil, errors.New("ACME private key type does not match configuration")
	}
	return &pair, nil
}
func (p *managedCertificate) loadACME() error {
	path, e := p.acmePath("certificate")
	if e != nil {
		return e
	}
	var s acmeCertificateState
	if e = readCertificateJSON(path, &s); errors.Is(e, os.ErrNotExist) {
		return nil
	} else if e != nil {
		return e
	}
	p.cert, e = p.parseACME(s)
	return e
}
func (p *managedCertificate) acmeAccount() (crypto.Signer, bool, error) {
	path, e := p.acmePath("account")
	if e != nil {
		return nil, false, e
	}
	var s acmeAccountState
	e = readCertificateJSON(path, &s)
	if e == nil {
		if s.Version != 1 || s.Provider != p.options.Provider || s.Email != p.options.Email {
			return nil, false, errors.New("ACME account cache does not match CA/email")
		}
		key, e := acmePrivateKey(s.Key)
		if e != nil {
			return nil, false, e
		}
		if p.options.AccountKey != "" {
			configured, e := acmePrivateKey(p.options.AccountKey)
			if e != nil {
				return nil, false, e
			}
			a, _, _, _ := acmeJWK(key)
			b, _, _, _ := acmeJWK(configured)
			if string(a) != string(b) {
				return nil, false, errors.New("ACME account cache does not match configured account key")
			}
		}
		return key, true, nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return nil, false, e
	}
	if p.options.AccountKey != "" {
		key, e := acmePrivateKey(p.options.AccountKey)
		return key, true, e
	}
	key, e := acmeGenerateKey("p256")
	return key, false, e
}
func (c *acmeClient) register(ctx context.Context, existing bool) error {
	if existing {
		_, h, _, e := c.post(ctx, c.directory.NewAccount, acmeJSON(map[string]bool{"onlyReturnExisting": true}))
		if e == nil {
			c.kid = h.Get("Location")
			return c.validateURL(c.kid)
		}
		var problem *acmeError
		if !errors.As(e, &problem) || problem.typ != "urn:ietf:params:acme:error:accountDoesNotExist" {
			return e
		}
	}
	binding := c.p.options.ExternalAccount
	if binding == nil && c.p.options.Provider == "https://acme.zerossl.com/v2/DV90" && c.p.options.Email != "" {
		var e error
		binding, e = c.zeroSSLBinding(ctx)
		if e != nil {
			return e
		}
	}
	if c.directory.Meta.ExternalAccountRequired && binding == nil {
		return errors.New("ACME server requires external_account binding")
	}
	eab, e := c.eab(binding)
	if e != nil {
		return e
	}
	payload := struct {
		Terms   bool     `json:"termsOfServiceAgreed"`
		Contact []string `json:"contact,omitempty"`
		Binding *acmeJWS `json:"externalAccountBinding,omitempty"`
	}{Terms: true, Binding: eab}
	if c.p.options.Email != "" {
		payload.Contact = []string{"mailto:" + c.p.options.Email}
	}
	_, h, _, e := c.post(ctx, c.directory.NewAccount, acmeJSON(payload))
	if e != nil {
		return e
	}
	c.kid = h.Get("Location")
	return c.validateURL(c.kid)
}
func (c *acmeClient) zeroSSLBinding(ctx context.Context) (*ACMEExternalAccount, error) {
	endpoint := "https://api.zerossl.com/acme/eab-credentials-email"
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(url.Values{"email": {c.p.options.Email}}.Encode()))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, e := c.http.Do(req)
	if e != nil {
		return nil, errors.New("ZeroSSL EAB request failed")
	}
	data, e := acmeResponse(resp)
	if e != nil {
		return nil, e
	}
	var v struct {
		Success bool   `json:"success"`
		Kid     string `json:"eab_kid"`
		Key     string `json:"eab_hmac_key"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(data, &v) != nil || !v.Success || v.Kid == "" || v.Key == "" {
		return nil, errors.New("ZeroSSL EAB request rejected;configure external_account explicitly")
	}
	return &ACMEExternalAccount{v.Kid, v.Key}, nil
}

type acmeIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
type acmeOrder struct {
	Status         string           `json:"status"`
	Identifiers    []acmeIdentifier `json:"identifiers"`
	Authorizations []string         `json:"authorizations"`
	Finalize       string           `json:"finalize"`
	Certificate    string           `json:"certificate"`
}

func (p *managedCertificate) issueACME(ctx context.Context) (*tls.Certificate, error) {
	select {
	case p.r.acme.gate <- struct{}{}:
		defer func() { <-p.r.acme.gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	key, existing, e := p.acmeAccount()
	if e != nil {
		return nil, e
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	accountPath, _ := p.acmePath("account")
	stateKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	// Save the identity before registration: a lost response must not lose the
	// key for an account the CA may already have created.
	if e = saveCertificateJSON(accountPath, acmeAccountState{1, p.options.Provider, p.options.Email, stateKey, ""}); e != nil {
		return nil, e
	}
	client, transport, e := p.r.ruleHTTPClient(RuleSet{HTTPClient: p.options.HTTPClient})
	if e != nil {
		return nil, e
	}
	defer transport.CloseIdleConnections()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	base, _ := acmeURL(p.options.Provider)
	c := &acmeClient{p: p, http: client, base: base, key: key}
	c.jwk, c.alg, c.hash, e = acmeJWK(key)
	if e != nil {
		return nil, e
	}
	data, _, _, e := c.request(ctx, "GET", p.options.Provider, "", nil)
	if e != nil {
		return nil, e
	}
	if json.Unmarshal(data, &c.directory) != nil {
		return nil, errors.New("invalid ACME directory")
	}
	for _, address := range []string{c.directory.NewAccount, c.directory.NewNonce, c.directory.NewOrder} {
		if e = c.validateURL(address); e != nil {
			return nil, e
		}
	}
	if p.options.Profile != "" {
		if _, ok := c.directory.Meta.Profiles[p.options.Profile]; !ok {
			return nil, errors.New("ACME requested profile is not advertised by CA")
		}
	}
	if e = c.register(ctx, existing); e != nil {
		return nil, e
	}
	if e = saveCertificateJSON(accountPath, acmeAccountState{1, p.options.Provider, p.options.Email, stateKey, c.kid}); e != nil {
		return nil, e
	}
	ids := make([]acmeIdentifier, 0, len(p.options.Domain))
	for _, name := range p.options.Domain {
		typ := "dns"
		if _, e := netip.ParseAddr(name); e == nil {
			typ = "ip"
		}
		ids = append(ids, acmeIdentifier{typ, name})
	}
	payload := struct {
		Identifiers []acmeIdentifier `json:"identifiers"`
		Profile     string           `json:"profile,omitempty"`
	}{ids, p.options.Profile}
	data, h, _, e := c.post(ctx, c.directory.NewOrder, acmeJSON(payload))
	if e != nil {
		return nil, e
	}
	orderURL := h.Get("Location")
	if e = c.validateURL(orderURL); e != nil {
		return nil, e
	}
	var order acmeOrder
	if json.Unmarshal(data, &order) != nil {
		return nil, errors.New("invalid ACME order")
	}
	returned := slices.Clone(order.Identifiers)
	slices.SortFunc(returned, func(a, b acmeIdentifier) int { return strings.Compare(a.Value, b.Value) })
	if !slices.Equal(returned, ids) || len(order.Authorizations) > 100 || order.Status != "pending" && order.Status != "ready" {
		return nil, errors.New("ACME new order does not match the requested identifiers or state")
	}
	for _, auth := range order.Authorizations {
		if e = c.authorize(ctx, auth); e != nil {
			return nil, e
		}
	}
	for attempt := 0; order.Status != "ready" && order.Status != "valid"; attempt++ {
		if attempt >= 120 || order.Status != "pending" {
			return nil, errors.New("ACME order did not become ready")
		}
		if e = c.pause(ctx, h); e != nil {
			return nil, e
		}
		data, h, _, e = c.post(ctx, orderURL, nil)
		if e != nil {
			return nil, e
		}
		if json.Unmarshal(data, &order) != nil {
			return nil, errors.New("invalid ACME order response")
		}
	}
	certKey, e := acmeGenerateKey(p.options.KeyType)
	if e != nil {
		return nil, e
	}
	csr := &x509.CertificateRequest{Subject: pkix.Name{}}
	for _, id := range ids {
		if id.Type == "ip" {
			csr.IPAddresses = append(csr.IPAddresses, net.ParseIP(id.Value))
		} else {
			csr.DNSNames = append(csr.DNSNames, id.Value)
		}
	}
	if len(p.options.Domain[0]) <= 64 {
		csr.Subject.CommonName = p.options.Domain[0]
	}
	request, e := x509.CreateCertificateRequest(rand.Reader, csr, certKey)
	if e != nil {
		return nil, e
	}
	if order.Status == "ready" {
		data, h, _, e = c.post(ctx, order.Finalize, acmeJSON(map[string]string{"csr": acmeB64(request)}))
		if e != nil {
			return nil, e
		}
		if json.Unmarshal(data, &order) != nil {
			return nil, errors.New("invalid ACME finalize response")
		}
	}
	for attempt := 0; order.Status != "valid"; attempt++ {
		if attempt >= 120 || order.Status != "processing" && order.Status != "ready" && order.Status != "pending" {
			return nil, errors.New("ACME order issuance failed")
		}
		if e = c.pause(ctx, h); e != nil {
			return nil, e
		}
		data, h, _, e = c.post(ctx, orderURL, nil)
		if e != nil {
			return nil, e
		}
		if json.Unmarshal(data, &order) != nil {
			return nil, errors.New("invalid ACME processing response")
		}
	}
	data, _, _, e = c.post(ctx, order.Certificate, nil)
	if e != nil {
		return nil, e
	}
	private, e = x509.MarshalPKCS8PrivateKey(certKey)
	if e != nil {
		return nil, e
	}
	state := acmeCertificateState{1, p.options.Domain, p.options.Provider, p.options.KeyType, p.options.Profile, string(data), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))}
	pair, e := p.parseACME(state)
	if e != nil {
		return nil, e
	}
	if p.now().Before(pair.Leaf.NotBefore) || !p.now().Before(pair.Leaf.NotAfter) {
		return nil, errors.New("ACME issued certificate is not currently valid")
	}
	path, _ := p.acmePath("certificate")
	if e = saveCertificateJSON(path, state); e != nil {
		return nil, e
	}
	return pair, nil
}
func (c *acmeClient) pause(ctx context.Context, h http.Header) error {
	return acmePause(ctx, min(5*time.Minute, max(10*time.Millisecond, acmeRetryAfter(h, c.p.now(), time.Second).Sub(c.p.now()))))
}
func acmePause(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
