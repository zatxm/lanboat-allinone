package native

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"slices"
)

// Called only during runtime construction. Shared and inline references to the
// same endpoint use one issuer, avoiding duplicate orders and CA rate limits.
func (r *Runtime) existingTailscaleCertificate(options CertificateProviderOptions) *managedCertificate {
	if options.Type == "tailscale" {
		for _, provider := range r.certificateProviders {
			if provider.options.Type == "tailscale" && provider.options.Endpoint == options.Endpoint {
				return provider
			}
		}
	}
	return nil
}

func (p *managedCertificate) wrapTailscaleTLS(base *tls.Config) *tls.Config {
	c := base.Clone()
	load := c.GetConfigForClient
	c.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		// GetCertificate is skipped on ticket resumption. Authorization, expiry
		// and renewal must also be checked before accepting a resumed session.
		if _, err := p.current(hello.Context(), hello.ServerName); err != nil {
			return nil, err
		}
		current := base
		if load != nil {
			var err error
			current, err = load(hello)
			if err != nil {
				return nil, err
			}
			if current == nil {
				current = base
			}
		}
		if hello.ServerName == "" {
			// An empty SNI follows the endpoint name, which can change. Do not
			// let a ticket for its old default identity survive a node rename.
			current = current.Clone()
			current.GetConfigForClient = nil
			current.SessionTicketsDisabled = true
			return current, nil
		}
		if load == nil {
			return nil, nil
		}
		return current, nil
	}
	return c
}

// Certificate authority comes from the authenticated map, never from a peer or
// an arbitrary ClientHello. Recheck it even when a certificate is cached.
func (c *tailscaleClient) certificateDomain(ctx context.Context, name string) (string, []string, error) {
	if err := c.wait(ctx); err != nil {
		return "", nil, err
	}
	c.mu.Lock()
	domains := slices.Clone(c.dnsConfig.CertDomains)
	self := canonicalDomain(c.self.Name)
	c.mu.Unlock()
	for i, domain := range domains {
		domains[i] = canonicalDomain(domain)
	}
	name = canonicalDomain(name)
	if name == "" {
		if slices.Contains(domains, self) {
			name = self
		} else if len(domains) == 1 {
			name = domains[0]
		}
	}
	if name == "" || !slices.Contains(domains, name) {
		return "", nil, errors.New("Tailscale certificate name is not authorized;enable MagicDNS and HTTPS for this endpoint")
	}
	return name, domains, nil
}

func (p *managedCertificate) tailscaleCertificate(ctx context.Context, name string) (*managedCertificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return nil, netClosedCertificateProvider
	}
	c := p.r.tailscaleClient(p.options.Endpoint)
	if c == nil {
		return nil, errors.New("Tailscale certificate endpoint is unavailable")
	}
	name, domains, err := c.certificateDomain(ctx, name)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, netClosedCertificateProvider
	}
	if child := p.children[name]; child != nil {
		return child, nil
	}
	if p.children == nil {
		p.children = make(map[string]*managedCertificate)
	}
	// Retired names cannot grow the cache indefinitely after repeated renames.
	for domain, child := range p.children {
		if !slices.Contains(domains, domain) {
			child.close()
			delete(p.children, domain)
		}
	}
	options := CertificateProviderOptions{
		Type: "acme", Tag: p.options.Tag, Domain: []string{name},
		DataDirectory: filepath.Join(c.stateDir, "certificates"),
		ACMEOptions:   ACMEOptions{Provider: "letsencrypt", KeyType: "p256"},
	}
	if err = options.normalize(); err != nil {
		return nil, err
	}
	child := &managedCertificate{r: p.r, options: options, now: p.now, tailscaleEndpoint: p.options.Endpoint}
	p.children[name] = child
	return child, nil
}

func (c *acmeClient) presentTailscaleDNS(ctx context.Context, domain, authorization string) (func(), error) {
	endpoint := c.p.r.tailscaleClient(c.p.tailscaleEndpoint)
	if endpoint == nil {
		return nil, errors.New("Tailscale certificate endpoint is unavailable")
	}
	if _, _, err := endpoint.certificateDomain(ctx, domain); err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(authorization))
	body := struct {
		Version int
		NodeKey string
		Name    string
		Type    string
		Value   string
	}{tailscaleCapability, tsKeyName(endpoint.nodeKey, "nodekey"), "_acme-challenge." + domain, "TXT", acmeB64(digest[:])}
	response, err := endpoint.controlRequest(ctx, "/machine/set-dns", body)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	var result map[string]json.RawMessage
	if err != nil || len(raw) > 64<<10 || json.Unmarshal(raw, &result) != nil || result == nil {
		return nil, errors.New("invalid Tailscale SetDNS response")
	}
	// SetDNS has no deletion operation. The control plane expires its TXT proof.
	return func() {}, nil
}
