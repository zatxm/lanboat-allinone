package native

import (
	"context"
	"crypto/tls"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

type managedCertificate struct {
	r                 *Runtime
	options           CertificateProviderOptions
	now               func() time.Time
	mu                sync.Mutex
	workers           sync.WaitGroup
	closed            bool
	loaded            bool
	cert              *tls.Certificate
	next              time.Time
	err               error
	pending           chan struct{}
	cancel            context.CancelFunc
	children          map[string]*managedCertificate
	tailscaleEndpoint string
}

func (p *managedCertificate) statePath() (string, error) {
	if p.options.Type == "acme" {
		return p.acmePath("certificate")
	}
	return p.originCAPath()
}
func (p *managedCertificate) load() error {
	if p.options.Type == "acme" {
		return p.loadACME()
	}
	return p.loadOriginCA()
}
func (p *managedCertificate) issue(ctx context.Context) (*tls.Certificate, error) {
	if p.options.Type == "acme" {
		return p.issueACME(ctx)
	}
	return p.issueOriginCA(ctx)
}
func (p *managedCertificate) current(ctx context.Context, name string) (*tls.Certificate, error) {
	if p.options.Type == "tailscale" {
		child, err := p.tailscaleCertificate(ctx, name)
		if err != nil {
			return nil, err
		}
		return child.current(ctx, child.options.Domain[0])
	}
	if name == "" {
		name = p.options.DefaultServerName
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		if p.closed || p.r.ctx.Err() != nil {
			p.mu.Unlock()
			return nil, netClosedCertificateProvider
		}
		if !p.loaded {
			if err := p.load(); err != nil {
				p.mu.Unlock()
				return nil, err
			}
			p.loaded = true
		}
		if name != "" {
			name = strings.ToLower(strings.TrimSuffix(name, "."))
			if !echDomain(name) && !p.acmeIPName(name) {
				p.mu.Unlock()
				return nil, errors.New("invalid TLS server name for certificate provider")
			}
			matched := slices.ContainsFunc(p.options.Domain, func(pattern string) bool { return certificateNameMatches(pattern, name) })
			if !matched {
				p.mu.Unlock()
				return nil, errors.New("TLS server name is not managed by the certificate provider")
			}
		}
		now := p.now()
		valid := p.cert != nil && !now.Before(p.cert.Leaf.NotBefore) && now.Before(p.cert.Leaf.NotAfter)
		due := !valid
		if valid {
			window := min(30*24*time.Hour, p.cert.Leaf.NotAfter.Sub(p.cert.Leaf.NotBefore)/3)
			due = !now.Before(p.cert.Leaf.NotAfter.Add(-window))
		}
		if due && p.pending == nil && !now.Before(p.next) {
			p.pending = make(chan struct{})
			limit := 30 * time.Second
			if p.options.Type == "acme" {
				limit = 15 * time.Minute
			}
			issue, cancel := context.WithTimeout(p.r.ctx, limit)
			p.cancel = cancel
			p.workers.Add(1)
			go p.refresh(issue, cancel)
		}
		if valid {
			cert := p.cert
			p.mu.Unlock()
			return cert, nil
		}
		pending, err := p.pending, p.err
		p.mu.Unlock()
		if pending == nil {
			if err == nil {
				err = errors.New("no currently valid managed certificate; retry is deferred")
			}
			return nil, err
		}
		select {
		case <-pending:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.r.ctx.Done():
			return nil, netClosedCertificateProvider
		}
	}
}

func (p *managedCertificate) acmeIPName(name string) bool {
	if p.options.Type != "acme" {
		return false
	}
	_, err := netip.ParseAddr(name)
	return err == nil
}

func certificateNameMatches(pattern, name string) bool {
	prefix := strings.TrimSuffix(name, strings.TrimPrefix(pattern, "*"))
	return name == pattern || strings.HasPrefix(pattern, "*.") && strings.HasSuffix(name, pattern[1:]) && prefix != "" && !strings.Contains(prefix, ".")
}

var netClosedCertificateProvider = errors.New("certificate provider is closed")

func (p *managedCertificate) refresh(ctx context.Context, cancel context.CancelFunc) {
	defer p.workers.Done()
	defer cancel()
	cert, err := p.issue(ctx)
	p.mu.Lock()
	p.err = err
	if err == nil {
		p.cert, p.next = cert, p.now().Add(min(time.Hour, max(time.Second, cert.Leaf.NotAfter.Sub(p.now())/3)))
	} else {
		p.next = p.now().Add(time.Minute)
		var delayed *acmeError
		if errors.As(err, &delayed) && delayed.retry.After(p.next) {
			p.next = delayed.retry
		}
	}
	close(p.pending)
	p.pending = nil
	p.cancel = nil
	closed := p.closed
	p.mu.Unlock()
	if err != nil && !closed && p.r.ctx.Err() == nil {
		p.r.logger.Warn("certificate renewal failed", zap.String("provider", p.options.Tag), zap.Error(err))
	}
}

func (p *managedCertificate) close() {
	p.mu.Lock()
	p.closed = true
	if p.cancel != nil {
		p.cancel()
	}
	children := p.children
	p.mu.Unlock()
	for _, child := range children {
		child.close()
	}
	p.workers.Wait()
}
