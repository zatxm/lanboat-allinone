package native

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	"net/http"
	"os"
	"path/filepath"
	"slices"
)

const originCAURL = "https://api.cloudflare.com/client/v4/certificates"
const originCAMaxResponse = 1 << 20

type originCAState struct {
	Version     int      `json:"version"`
	Domains     []string `json:"domains"`
	RequestType string   `json:"request_type"`
	Validity    int      `json:"requested_validity"`
	ID          string   `json:"id"`
	Certificate string   `json:"certificate"`
	PrivateKey  string   `json:"private_key"`
}

func (p *managedCertificate) originCAPath() (string, error) {
	dir := p.options.DataDirectory
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".lanboat-allinone", "certificates")
	}
	id, _ := json.Marshal([]any{p.options.Domain, p.options.RequestType, p.options.RequestedValidity})
	return filepath.Join(dir, fmt.Sprintf("cloudflare-%x.json", sha256.Sum256(id))), nil
}

func (p *managedCertificate) parseState(s originCAState) (*tls.Certificate, error) {
	if s.Version != 1 || !slices.Equal(s.Domains, p.options.Domain) || s.RequestType != p.options.RequestType || s.Validity != p.options.RequestedValidity {
		return nil, errors.New("Cloudflare certificate cache does not match configured domains and request parameters")
	}
	cert, err := tls.X509KeyPair([]byte(s.Certificate), []byte(s.PrivateKey))
	if err != nil {
		return nil, errors.New("invalid Cloudflare certificate/key pair")
	}
	leaf := cert.Leaf
	if leaf.IsCA || !leaf.NotAfter.After(leaf.NotBefore) {
		return nil, errors.New("invalid Cloudflare leaf certificate")
	}
	for _, name := range p.options.Domain {
		if !slices.Contains(leaf.DNSNames, name) {
			return nil, errors.New("Cloudflare certificate is missing a requested DNS name")
		}
	}
	if len(leaf.ExtKeyUsage) > 0 && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil, errors.New("Cloudflare certificate does not permit server authentication")
	}
	switch key := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if p.options.RequestType != "origin-rsa" || key.N.BitLen() < 2048 {
			return nil, errors.New("unexpected Cloudflare RSA private key")
		}
	case *ecdsa.PrivateKey:
		if p.options.RequestType != "origin-ecc" || key.Curve != elliptic.P256() {
			return nil, errors.New("unexpected Cloudflare ECC private key")
		}
	default:
		return nil, errors.New("unexpected Cloudflare private key algorithm")
	}
	return &cert, nil
}

func (p *managedCertificate) loadOriginCA() error {
	path, err := p.statePath()
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, originCAMaxResponse+1))
	if err != nil || len(data) > originCAMaxResponse {
		return errors.New("cannot read Cloudflare certificate cache")
	}
	var s originCAState
	if err := decodeOptions(data, &s); err != nil {
		return errors.New("invalid Cloudflare certificate cache")
	}
	p.cert, err = p.parseState(s)
	return err
}

func (p *managedCertificate) save(s originCAState) error {
	path, err := p.statePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if len(data) > originCAMaxResponse {
		return errors.New("Cloudflare certificate cache exceeds1MiB")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".cloudflare-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func (p *managedCertificate) issueOriginCA(ctx context.Context) (*tls.Certificate, error) {
	var key crypto.Signer
	var err error
	if p.options.RequestType == "origin-rsa" {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: p.options.Domain[0]}, DNSNames: p.options.Domain}, key)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(struct {
		CSR      string   `json:"csr"`
		Hosts    []string `json:"hostnames"`
		Type     string   `json:"request_type"`
		Validity int      `json:"requested_validity"`
	}{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), p.options.Domain, p.options.RequestType, p.options.RequestedValidity})
	if err != nil {
		return nil, err
	}
	client, transport, err := p.r.ruleHTTPClient(RuleSet{HTTPClient: p.options.HTTPClient})
	if err != nil {
		return nil, err
	}
	defer transport.CloseIdleConnections()
	// The provider credentials must never follow redirects, including307/308.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, originCAURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpOptions, _ := p.r.httpClientOptions(p.options.HTTPClient)
	for k, values := range httpOptions.Headers {
		for _, value := range values {
			req.Header.Add(k, value)
		}
	}
	req.Header.Del("X-Auth-User-Service-Key")
	req.Header.Del("Authorization")
	req.Header.Set("Content-Type", "application/json")
	if p.options.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+p.options.APIToken)
	} else {
		req.Header.Set("X-Auth-User-Service-Key", p.options.OriginCAKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("Cloudflare certificate API request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Cloudflare certificate API returned HTTP%d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, originCAMaxResponse+1))
	if err != nil || len(data) > originCAMaxResponse {
		return nil, errors.New("invalid Cloudflare certificate API response size")
	}
	var result struct {
		Success bool `json:"success"`
		Result  struct {
			ID          string `json:"id"`
			Certificate string `json:"certificate"`
		} `json:"result"`
	}
	if json.Unmarshal(data, &result) != nil || !result.Success || result.Result.Certificate == "" {
		return nil, errors.New("Cloudflare certificate API rejected issuance or returned an invalid response")
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	s := originCAState{Version: 1, Domains: p.options.Domain, RequestType: p.options.RequestType, Validity: p.options.RequestedValidity, ID: result.Result.ID, Certificate: result.Result.Certificate, PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))}
	cert, err := p.parseState(s)
	if err != nil {
		return nil, err
	}
	now := p.now()
	if now.Before(cert.Leaf.NotBefore) || !now.Before(cert.Leaf.NotAfter) {
		return nil, errors.New("Cloudflare issued certificate is not currently valid")
	}
	if err := p.save(s); err != nil {
		return nil, fmt.Errorf("persist Cloudflare certificate: %w", err)
	}
	return cert, nil
}
