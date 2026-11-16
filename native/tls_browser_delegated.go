package native

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"slices"
	"strings"
	"time"
)

func browserDelegatedKey(body []byte, leaf *x509.Certificate, profile string, now time.Time) (any, tls.SignatureScheme, error) {
	p := stCursor{data: body}
	p.vector(1)
	list := stCursor{data: p.vector(3)}
	list.vector(3)
	values, err := stExtensions(list.vector(2))
	if err != nil || p.end() != nil || list.err != nil {
		return nil, 0, errors.New("invalid delegated certificate framing")
	}
	dc, ok := values[34]
	if !ok {
		return leaf.PublicKey, 0, nil
	}
	if !strings.HasPrefix(profile, "firefox") && profile != "random" {
		return nil, 0, errors.New("unsolicited delegated credential")
	}
	r := stCursor{data: dc}
	expiry := leaf.NotBefore.Add(time.Duration(r.number(4)) * time.Second)
	scheme := tls.SignatureScheme(r.number(2))
	public := r.vector(3)
	algorithm := tls.SignatureScheme(r.number(2))
	credential := dc[:len(dc)-len(r.data)]
	signature := r.vector(2)
	if r.end() != nil || !slices.Contains([]tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512}, scheme) || !slices.Contains(browserSignatures(profile), uint16(algorithm)) {
		return nil, 0, errors.New("invalid delegated credential signature selection")
	}
	if now.Before(leaf.NotBefore) || !now.Before(expiry) || expiry.After(now.Add(7*24*time.Hour)) || !expiry.Before(leaf.NotAfter) || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, 0, errors.New("invalid delegated credential lifetime or key usage")
	}
	allowed := false
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 44}) && !ext.Critical && bytes.Equal(ext.Value, []byte{5, 0}) {
			allowed = true
		}
	}
	if !allowed {
		return nil, 0, errors.New("certificate does not authorize delegation")
	}
	key, err := x509.ParsePKIXPublicKey(public)
	if err != nil || !stSignatureKey(key, scheme) {
		return nil, 0, errors.New("invalid delegated credential public key")
	}
	input := bytes.Repeat([]byte{' '}, 64)
	input = append(input, "TLS, server delegated credentials\x00"...)
	input = append(input, leaf.Raw...)
	input = append(input, credential...)
	if err := browserTLS12Verify(leaf.PublicKey, algorithm, input, signature); err != nil {
		return nil, 0, err
	}
	return key, scheme, nil
}
