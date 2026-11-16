package native

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"
)

type masqueStatusError int

func (s masqueStatusError) Error() string { return fmt.Sprintf("MASQUE request rejected: HTTP%d", s) }

func masqueTLSConfig(config *tls.Config) *tls.Config {
	config = cloneTLSConfig(config)
	if verify := config.VerifyConnection; verify != nil {
		config.VerifyConnection = func(state tls.ConnectionState) error {
			if err := verify(state); err != nil {
				return &tls.CertificateVerificationError{UnverifiedCertificates: state.PeerCertificates, Err: err}
			}
			return nil
		}
	}
	return config
}

func validateMasqueHeaders(headers map[string]headerValues) error {
	seen, size := map[string]bool{}, 0
	for name, values := range headers {
		key := strings.ToLower(name)
		if seen[key] {
			return errors.New("duplicate MASQUE header")
		}
		seen[key] = true
		if err := transportHeaderName(name, false); err != nil {
			return err
		}
		switch key {
		case masqueContextsHeader, "host", "authorization", "proxy-authorization", "capsule-protocol", "connection", "upgrade", "content-length", "transfer-encoding", "te", "trailer", "proxy-connection", "keep-alive", masqueProtocolHeader:
			return errors.New("MASQUE owns header " + name)
		}
		for _, value := range values {
			size += len(name) + len(value)
			if strings.ContainsAny(value, "\r\n\x00") {
				return errors.New("invalid MASQUE header value")
			}
		}
	}
	if len(headers) > 128 || size > 16384 {
		return errors.New("MASQUE headers exceed limit")
	}
	return nil
}

func masqueCanFallback(err error) bool {
	var status masqueStatusError
	if errors.As(err, &status) {
		return status == 421 || status == 501 || status == 505
	}
	var verification *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	return !errors.As(err, &verification) && !errors.As(err, &unknown) && !errors.As(err, &invalid) && !errors.As(err, &hostname)
}

// The caller holds c.mu. A session's negotiated version is immutable, so live
// streams never start using a different framing when another dial falls back.
func (c *masqueClient) openSession(ctx context.Context, protocol, path, authority string) (*masqueFlow, error) {
	version := c.outbound.HTTPVersion
	if version == 0 {
		version = 3
	}
	if c.session != nil {
		version = c.session.version
	}
	last := 1
	if c.outbound.DisableVersionFallback {
		last = version
	}
	deadline := time.Now().Add(handshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	var failures []error
	for ; version >= last; version-- {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		budget := time.Until(deadline) / time.Duration(version-last+1)
		if budget <= 0 {
			return nil, context.DeadlineExceeded
		}
		attempt, cancel := context.WithTimeout(ctx, budget)
		m, err := c.ensure(attempt, version)
		var flow *masqueFlow
		if err == nil {
			flow, err = c.open(attempt, m, protocol, path, authority)
		}
		cancel()
		if err == nil {
			return flow, nil
		}
		failures = append(failures, fmt.Errorf("HTTP%d: %w", version, err))
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !masqueCanFallback(err) || version == last {
			break
		}
		if m != nil {
			m.close()
			m.workers.Wait()
		}
		c.session = nil
		c.ip.Store(nil)
	}
	return nil, errors.Join(failures...)
}
