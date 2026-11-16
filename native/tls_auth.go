package native

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
)

// configureClientAuth uses the same modern client_certificate fields for the
// outbound identity and the inbound trust store, according to their roles.
func (o TLSOptions) configureClientAuth(c *tls.Config, server bool) error {
	cert := []byte(strings.Join(o.ClientCertificate, "\n"))
	for _, path := range o.ClientCertificatePath {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		cert = append(append(cert, '\n'), b...)
	}
	if server {
		if len(o.ClientKey) != 0 || o.ClientKeyPath != "" {
			return errors.New("client_key is an outbound TLS option")
		}
		modes := map[string]tls.ClientAuthType{
			"": tls.NoClientCert, "no": tls.NoClientCert,
			"request": tls.RequestClientCert, "require-any": tls.RequireAnyClientCert,
			"verify-if-given": tls.VerifyClientCertIfGiven, "require-and-verify": tls.RequireAndVerifyClientCert,
		}
		mode, ok := modes[o.ClientAuthentication]
		if !ok {
			return fmt.Errorf("unknown TLS client_authentication %q", o.ClientAuthentication)
		}
		c.ClientAuth = mode
		if mode == tls.VerifyClientCertIfGiven || mode == tls.RequireAndVerifyClientCert {
			if len(cert) == 0 && len(o.ClientCertificateSHA256)+len(o.ClientCertificatePublicKeySHA256) == 0 {
				return errors.New("verified client authentication requires client CA certificates or certificate pins")
			}
		}
		if len(cert) > 0 {
			c.ClientCAs = x509.NewCertPool()
			if !c.ClientCAs.AppendCertsFromPEM(cert) {
				return errors.New("invalid TLS client trust certificate")
			}
			if len(o.ClientCertificatePath) != 0 && (mode == tls.VerifyClientCertIfGiven || mode == tls.RequireAndVerifyClientCert) {
				roots := c.ClientCAs
				c.VerifyConnection = func(s tls.ConnectionState) error {
					if !s.DidResume || mode == tls.VerifyClientCertIfGiven && len(s.PeerCertificates) == 0 {
						return nil
					}
					return verifyTLSChain(s, roots, "", true)
				}
			}
		}
		return nil
	}
	if o.ClientAuthentication != "" {
		return errors.New("client_authentication is an inbound TLS option")
	}
	key := []byte(strings.Join(o.ClientKey, "\n"))
	if o.ClientKeyPath != "" {
		var err error
		key, err = os.ReadFile(o.ClientKeyPath)
		if err != nil {
			return err
		}
	}
	if len(cert) == 0 && len(key) == 0 {
		return nil
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return fmt.Errorf("TLS client certificate/key: %w", err)
	}
	c.Certificates = []tls.Certificate{pair}
	return nil
}
