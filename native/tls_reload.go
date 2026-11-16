package native

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
)

type tlsFileCache struct {
	mu       sync.Mutex
	options  TLSOptions
	server   bool
	hostname string
	paths    []string
	stamps   []os.FileInfo
	config   *tls.Config
}

func tlsFileStamps(paths []string) ([]os.FileInfo, error) {
	stamps := make([]os.FileInfo, len(paths))
	for i, path := range paths {
		var err error
		stamps[i], err = os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("TLS credential file: %w", err)
		}
	}
	return stamps, nil
}

func sameTLSFiles(a, b []os.FileInfo) bool {
	return slices.EqualFunc(a, b, func(a, b os.FileInfo) bool {
		return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
	})
}

func (f *tlsFileCache) current() (*tls.Config, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	before, err := tlsFileStamps(f.paths)
	if err != nil {
		return nil, err
	}
	if f.config != nil && sameTLSFiles(f.stamps, before) {
		return f.config, nil
	}
	c, err := f.options.staticConfig(f.server, f.hostname)
	if err != nil {
		return nil, err
	}
	after, err := tlsFileStamps(f.paths)
	if err != nil {
		return nil, err
	}
	if !sameTLSFiles(before, after) {
		return nil, errors.New("TLS credential files changed while loading")
	}
	f.config, f.stamps = c, after
	return c, nil
}

func (o TLSOptions) config(server bool, hostname string) (result *tls.Config, err error) {
	defer func() {
		if err == nil && server && result != nil && o.provider != nil && o.provider.options.Type == "acme" {
			result = o.provider.wrapACMETLS(result)
		} else if err == nil && server && result != nil && o.provider != nil && o.provider.options.Type == "tailscale" {
			result = o.provider.wrapTailscaleTLS(result)
		}
	}()
	var paths []string
	for _, path := range append([]string{o.CertificatePath, o.KeyPath, o.ClientKeyPath, o.PKCS12Path}, o.ClientCertificatePath...) {
		if path != "" && !slices.Contains(paths, path) {
			paths = append(paths, path)
		}
	}
	if o.ECH != nil && o.ECH.Enabled {
		for _, path := range []string{o.ECH.KeyPath, o.ECH.ConfigPath} {
			if path != "" && !slices.Contains(paths, path) {
				paths = append(paths, path)
			}
		}
	}
	if !o.Enabled || len(paths) == 0 {
		return o.staticConfig(server, hostname)
	}
	cache := &tlsFileCache{options: o, server: server, hostname: hostname, paths: paths}
	snapshot, err := cache.current()
	if err != nil {
		return nil, err
	}
	c := snapshot.Clone()
	if server {
		c.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return cache.current() }
		if o.ECH != nil && o.ECH.Enabled {
			c.GetEncryptedClientHelloKeys = func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
				snapshot, err := cache.current()
				if err != nil {
					return nil, err
				}
				return snapshot.EncryptedClientHelloKeys, nil
			}
		}
		return c, nil
	}
	c.InsecureSkipVerify = true // Verification below uses the latest trust snapshot.
	c.VerifyConnection = func(s tls.ConnectionState) error {
		snapshot, err := cache.current()
		if err != nil {
			return err
		}
		if snapshot.VerifyConnection != nil {
			return snapshot.VerifyConnection(s)
		}
		if snapshot.InsecureSkipVerify {
			return nil
		}
		hostname := snapshot.ServerName
		if hostname == "" {
			hostname = s.ServerName
		}
		return verifyTLSChain(s, snapshot.RootCAs, hostname, false)
	}
	if len(snapshot.Certificates) != 0 {
		c.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			snapshot, err := cache.current()
			if err != nil {
				return nil, err
			}
			cert := &snapshot.Certificates[0]
			if info.SupportsCertificate(cert) != nil {
				return &tls.Certificate{}, nil
			}
			return cert, nil
		}
	}
	return c, nil
}

// Protocol adapters can change ALPN and TLS versions on clones. Preserve those
// settings when replacing only the credentials with a freshly loaded snapshot.
func cloneTLSConfig(base *tls.Config) *tls.Config {
	c := base.Clone()
	if load := base.GetConfigForClient; load != nil {
		c.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			snapshot, err := load(hello)
			if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == "acme-tls/1" {
				return snapshot, err
			}
			if err != nil || snapshot == nil {
				return nil, err
			}
			current := c.Clone()
			current.GetConfigForClient = nil
			current.Certificates, current.ClientCAs = snapshot.Certificates, snapshot.ClientCAs
			current.GetCertificate = snapshot.GetCertificate
			current.SessionTicketsDisabled = c.SessionTicketsDisabled || snapshot.SessionTicketsDisabled
			current.EncryptedClientHelloKeys = snapshot.EncryptedClientHelloKeys
			current.VerifyConnection = snapshot.VerifyConnection
			return current, nil
		}
	}
	return c
}
