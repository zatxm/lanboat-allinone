package native

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
)

func (o TLSOptions) configureProtocol(c *tls.Config, server bool) error {
	if err := o.validateBrowser(server); err != nil {
		return err
	}
	if o.KernelTX || o.KernelRX {
		if runtime.GOOS != "linux" {
			return errors.New("kernel TLS requires Linux")
		}
		if o.MaxVersion != "" && o.MaxVersion != "1.3" {
			return errors.New("kernel TLS requires TLS1.3")
		}
		c.MinVersion = tls.VersionTLS13
	}
	if o.Engine != "" && (o.Engine != "go" || server) {
		return errors.New("TLS engine supports only the outbound go engine")
	}
	if o.DisableSNI && server {
		return errors.New("disable_sni is an outbound TLS option")
	}
	versions := map[string]uint16{"1.0": tls.VersionTLS10, "1.1": tls.VersionTLS11, "1.2": tls.VersionTLS12, "1.3": tls.VersionTLS13}
	for _, v := range []struct {
		name string
		out  *uint16
	}{{o.MinVersion, &c.MinVersion}, {o.MaxVersion, &c.MaxVersion}} {
		if v.name != "" {
			id, ok := versions[v.name]
			if !ok {
				return fmt.Errorf("unknown TLS version %q", v.name)
			}
			*v.out = id
		}
	}
	if o.KernelTX || o.KernelRX {
		c.MinVersion = max(c.MinVersion, tls.VersionTLS13)
	}
	if c.MaxVersion != 0 && c.MinVersion > c.MaxVersion {
		return errors.New("TLS min_version exceeds max_version")
	}
	for _, name := range o.CipherSuites {
		found := false
		for _, suite := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
			if suite.Name == name {
				c.CipherSuites = append(c.CipherSuites, suite.ID)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unknown TLS cipher suite %q", name)
		}
	}
	curves := map[string]tls.CurveID{"P256": tls.CurveP256, "P384": tls.CurveP384, "P521": tls.CurveP521, "X25519": tls.X25519, "X25519MLKEM768": tls.X25519MLKEM768}
	for _, name := range o.CurvePreferences {
		id, ok := curves[name]
		if !ok {
			return fmt.Errorf("unknown TLS curve %q", name)
		}
		c.CurvePreferences = append(c.CurvePreferences, id)
	}
	for _, name := range o.ALPN {
		if len(name) == 0 || len(name) > 255 {
			return errors.New("TLS ALPN identifiers must contain1-255 bytes")
		}
	}
	return nil
}

func (o TLSOptions) validateQUICVersion() error {
	if o.browserEnabled() {
		return errors.New("browser ClientHello profiles require a TCP TLS stream")
	}
	if o.KernelTX || o.KernelRX {
		return errors.New("kernel TLS requires a TCP stream, not QUIC")
	}
	if o.RecordFragment || o.Fragment || o.FragmentFallbackDelay != "" {
		return errors.New("TLS fragmentation requires a TCP stream, not QUIC")
	}
	if o.MaxVersion != "" && o.MaxVersion != "1.3" {
		return errors.New("QUIC requires TLS1.3")
	}
	return nil
}

type tlsPins struct{ certificate, publicKey [][32]byte }

func parseTLSPins(certs, keys []string) (tlsPins, error) {
	p := tlsPins{}
	for i, values := range [][]string{certs, keys} {
		for _, value := range values {
			if len(value) != 44 {
				return p, errors.New("TLS SHA256 pins must be32-byte digests encoded in base64")
			}
			b, err := base64.StdEncoding.Strict().DecodeString(value)
			if err != nil || len(b) != 32 {
				return p, errors.New("TLS SHA256 pins must be32-byte digests encoded in base64")
			}
			if i == 0 {
				p.certificate = append(p.certificate, [32]byte(b))
			} else {
				p.publicKey = append(p.publicKey, [32]byte(b))
			}
		}
	}
	return p, nil
}

func (p tlsPins) enabled() bool { return len(p.certificate)+len(p.publicKey) != 0 }

func (p tlsPins) verify(s tls.ConnectionState) error {
	if len(s.PeerCertificates) == 0 {
		return errors.New("TLS peer certificate is missing")
	}
	// Pin the authenticated leaf, never an unverified appended chain member.
	leaf := s.PeerCertificates[0]
	cert, key := sha256.Sum256(leaf.Raw), sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	match := 0
	for _, pin := range p.certificate {
		match |= subtle.ConstantTimeCompare(cert[:], pin[:])
	}
	for _, pin := range p.publicKey {
		match |= subtle.ConstantTimeCompare(key[:], pin[:])
	}
	if match == 0 {
		return errors.New("TLS certificate pin mismatch")
	}
	return nil
}

func verifyTLSChain(s tls.ConnectionState, roots *x509.CertPool, hostname string, client bool) error {
	if len(s.PeerCertificates) == 0 {
		return errors.New("TLS peer certificate is missing")
	}
	options := x509.VerifyOptions{Roots: roots, DNSName: hostname, Intermediates: x509.NewCertPool()}
	if client {
		options.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	for _, cert := range s.PeerCertificates[1:] {
		options.Intermediates.AddCert(cert)
	}
	_, err := s.PeerCertificates[0].Verify(options)
	return err
}

func (o TLSOptions) configurePins(c *tls.Config, server bool) error {
	certs, keys := o.CertificateSHA256, o.CertificatePublicKeySHA256
	if server {
		if len(certs)+len(keys) != 0 {
			return errors.New("certificate_sha256 and certificate_public_key_sha256 are outbound TLS options")
		}
		certs, keys = o.ClientCertificateSHA256, o.ClientCertificatePublicKeySHA256
	} else if len(o.ClientCertificateSHA256)+len(o.ClientCertificatePublicKeySHA256) != 0 {
		return errors.New("client_certificate SHA256 pins are inbound TLS options")
	}
	pins, err := parseTLSPins(certs, keys)
	if err != nil {
		return err
	}
	if pins.enabled() {
		if server {
			if len(o.ClientCertificate)+len(o.ClientCertificatePath) != 0 {
				return errors.New("client certificate pins conflict with client CA certificates")
			}
			if c.ClientAuth == tls.VerifyClientCertIfGiven || c.ClientAuth == tls.RequireAndVerifyClientCert {
				required := c.ClientAuth == tls.RequireAndVerifyClientCert
				c.ClientAuth = tls.RequestClientCert
				if required {
					c.ClientAuth = tls.RequireAnyClientCert
				}
				c.VerifyConnection = func(s tls.ConnectionState) error {
					if !required && len(s.PeerCertificates) == 0 {
						return nil
					}
					return pins.verify(s)
				}
			}
		} else {
			if len(o.Certificate) != 0 || o.CertificatePath != "" {
				return errors.New("TLS certificate pins conflict with CA certificates")
			}
			c.InsecureSkipVerify = true // Explicit pins replace PKI verification.
			c.VerifyConnection = pins.verify
		}
	}
	if o.DisableSNI {
		hostname := c.ServerName
		c.ServerName = ""
		if !o.Insecure && !pins.enabled() {
			c.InsecureSkipVerify = true
			c.VerifyConnection = func(s tls.ConnectionState) error { return verifyTLSChain(s, c.RootCAs, hostname, false) }
		}
	}
	return nil
}
