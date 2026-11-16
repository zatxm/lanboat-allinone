package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

// Each login owns a GSS context; providers verify the service and mutual token.
type OpenConnectNegotiateSession interface {
	Next(context.Context, []byte) (token []byte, complete bool, err error)
	Close() error
}

type OpenConnectNegotiateRequest struct {
	Endpoint       string
	URL            string
	Service        string
	ChannelBinding []byte // RFC5929 tls-server-end-point, without the GSS prefix.
}

type OpenConnectNegotiateHandler func(context.Context, OpenConnectNegotiateRequest) (OpenConnectNegotiateSession, error)
type ocNegotiateKey struct{}

func WithOpenConnectNegotiate(ctx context.Context, handler OpenConnectNegotiateHandler) context.Context {
	return context.WithValue(ctx, ocNegotiateKey{}, handler)
}

func (r *Runtime) SetOpenConnectNegotiateHandler(handler OpenConnectNegotiateHandler) {
	if handler == nil {
		r.ocNegotiateHandler.Store(nil)
	} else {
		r.ocNegotiateHandler.Store(&handler)
	}
}

type ocNegotiate struct {
	handler       OpenConnectNegotiateHandler
	session       OpenConnectNegotiateSession
	authorization string
	complete      bool
	verified      bool
	rounds        int
	binding       []byte
}

func (c *ocClient) negotiate(ctx context.Context) *ocNegotiate {
	h, explicit := ctx.Value(ocNegotiateKey{}).(OpenConnectNegotiateHandler)
	if !explicit {
		if p := c.r.ocNegotiateHandler.Load(); p != nil {
			h = *p
		}
	}
	return &ocNegotiate{handler: h}
}

func (n *ocNegotiate) close() {
	if n.session != nil {
		_ = n.session.Close()
		n.session = nil
	}
	n.authorization = ""
}

func ocNegotiateToken(header http.Header) ([]byte, bool, error) {
	var token []byte
	found := false
	for _, line := range header.Values("WWW-Authenticate") {
		for _, part := range strings.Split(line, ",") {
			fields := strings.Fields(part)
			if len(fields) == 0 || !strings.EqualFold(fields[0], "Negotiate") {
				continue
			}
			if found || len(fields) > 2 {
				return nil, false, errors.New("invalid OpenConnect Negotiate challenge")
			}
			found = true
			if len(fields) == 2 {
				var err error
				if len(fields[1]) > 43692 {
					return nil, false, errors.New("OpenConnect Negotiate token exceeds32KiB")
				}
				token, err = base64.StdEncoding.Strict().DecodeString(fields[1])
				if err != nil || len(token) > 32768 {
					return nil, false, errors.New("invalid OpenConnect Negotiate token")
				}
			}
		}
	}
	return token, found, nil
}

func ocChannelBinding(state *tls.ConnectionState) ([]byte, error) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil, errors.New("OpenConnect Negotiate requires a TLS peer certificate")
	}
	cert := state.PeerCertificates[0]
	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		h := sha512.Sum384(cert.Raw)
		return h[:], nil
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		h := sha512.Sum512(cert.Raw)
		return h[:], nil
	default:
		h := sha256.Sum256(cert.Raw)
		return h[:], nil
	}
}

func (n *ocNegotiate) challenge(ctx context.Context, c *ocClient, current string, header http.Header, state *tls.ConnectionState) error {
	token, found, err := ocNegotiateToken(header)
	if err != nil {
		return err
	}
	if !found || n.verified || n.rounds >= 16 {
		return errors.New("OpenConnect Negotiate authentication failed")
	}
	binding, err := ocChannelBinding(state)
	if err != nil {
		return err
	}
	if n.session != nil && !bytes.Equal(binding, n.binding) {
		return errors.New("OpenConnect Negotiate TLS channel binding changed")
	}
	if n.session == nil {
		n.binding = binding
		host := c.o.TLS.ServerName
		if host == "" {
			host = c.o.Server
		}
		n.session, err = n.handler(ctx, OpenConnectNegotiateRequest{Endpoint: c.o.Tag, URL: current, Service: "HTTP/" + strings.ToLower(strings.TrimSuffix(host, ".")), ChannelBinding: binding})
		if err != nil {
			return err
		}
		if n.session == nil {
			return errors.New("OpenConnect Negotiate provider returned no context")
		}
	}
	response, complete, err := n.session.Next(ctx, token)
	if err != nil {
		return err
	}
	if len(response) == 0 || len(response) > 32768 {
		return errors.New("invalid OpenConnect Negotiate response size")
	}
	n.authorization = "Negotiate " + base64.StdEncoding.EncodeToString(response)
	n.complete = complete
	n.rounds++
	return nil
}

func (n *ocNegotiate) finish(ctx context.Context, header http.Header, state *tls.ConnectionState) error {
	if n.session == nil || n.verified {
		return nil
	}
	binding, err := ocChannelBinding(state)
	if err != nil {
		return err
	}
	if !bytes.Equal(binding, n.binding) {
		return errors.New("OpenConnect Negotiate TLS channel binding changed")
	}
	token, found, err := ocNegotiateToken(header)
	if err != nil {
		return err
	}
	if found {
		if len(token) == 0 {
			return errors.New("OpenConnect Negotiate final token is empty")
		}
		response, complete, err := n.session.Next(ctx, token)
		if err != nil {
			return err
		}
		if len(response) != 0 || !complete {
			return errors.New("OpenConnect Negotiate final token did not authenticate the server")
		}
		n.complete = true
	}
	if !n.complete {
		return errors.New("OpenConnect Negotiate mutual authentication incomplete")
	}
	n.verified = true
	return nil
}
