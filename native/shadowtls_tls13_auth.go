package native

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"hash"
	"slices"
)

func stCertificates(body []byte, browser ...bool) ([]*x509.Certificate, error) {
	p := stCursor{data: body}
	if len(p.vector(1)) != 0 {
		return nil, errors.New("unexpected TLS server certificate context")
	}
	list := stCursor{data: p.vector(3)}
	if e := p.end(); e != nil {
		return nil, e
	}
	var certs []*x509.Certificate
	for len(list.data) > 0 && list.err == nil {
		der := list.vector(3)
		ext := list.vector(2)
		if list.err != nil {
			return nil, list.err
		}
		if len(certs) >= 32 {
			return nil, errors.New("TLS certificate chain exceeds32certificates")
		}
		cert, e := x509.ParseCertificate(der)
		if e != nil {
			return nil, e
		}
		certs = append(certs, cert)
		if len(ext) != 0 {
			values, e := stExtensions(ext)
			if e != nil {
				return nil, e
			}
			for id, data := range values {
				if len(browser) == 0 || !browser[0] || len(certs) != 1 {
					return nil, errors.New("unsolicited TLS certificate extension")
				}
				p := stCursor{data: data}
				switch id {
				case 34:
					if len(data) == 0 {
						return nil, errors.New("empty delegated credential")
					}
				case 5:
					if p.number(1) != 1 || len(p.vector(3)) == 0 || p.end() != nil {
						return nil, errors.New("invalid TLS OCSP response")
					}
				case 18:
					list := stCursor{data: p.vector(2)}
					if p.end() != nil || len(list.data) == 0 {
						return nil, errors.New("invalid TLS SCT list")
					}
					for len(list.data) > 0 && list.err == nil {
						if len(list.vector(2)) == 0 {
							return nil, errors.New("empty TLS SCT")
						}
					}
					if list.end() != nil {
						return nil, errors.New("invalid TLS SCT list")
					}
				default:
					return nil, errors.New("unsolicited TLS certificate extension")
				}
			}
		}
	}
	if e := list.end(); e != nil {
		return nil, e
	}
	if len(certs) == 0 {
		return nil, errors.New("TLS server certificate required")
	}
	return certs, nil
}
func stCertificateRequest(body []byte) ([]byte, *tls.CertificateRequestInfo, error) {
	p := stCursor{data: body}
	context := bytes.Clone(p.vector(1))
	ext := p.vector(2)
	if e := p.end(); e != nil {
		return nil, nil, e
	}
	if len(context) != 0 {
		return nil, nil, errors.New("unexpected TLS initial client certificate context")
	}
	values, e := stExtensions(ext)
	if e != nil {
		return nil, nil, e
	}
	r := &tls.CertificateRequestInfo{Version: tls.VersionTLS13}
	schemes := stCursor{data: values[13]}
	list := stCursor{data: schemes.vector(2)}
	if schemes.end() != nil || len(list.data) == 0 || len(list.data)%2 != 0 {
		return nil, nil, errors.New("invalid TLS signature algorithms")
	}
	for len(list.data) > 0 && list.err == nil {
		r.SignatureSchemes = append(r.SignatureSchemes, tls.SignatureScheme(list.number(2)))
	}
	if data, ok := values[47]; ok {
		p := stCursor{data: data}
		ca := stCursor{data: p.vector(2)}
		if p.end() != nil {
			return nil, nil, errors.New("invalid TLS certificate authorities")
		}
		for len(ca.data) > 0 && ca.err == nil {
			r.AcceptableCAs = append(r.AcceptableCAs, bytes.Clone(ca.vector(2)))
		}
		if ca.end() != nil {
			return nil, nil, errors.New("invalid TLS certificate authorities")
		}
	}
	return context, r, nil
}
func stSignatureHash(s tls.SignatureScheme) (crypto.Hash, error) {
	switch s {
	case tls.PSSWithSHA256, tls.ECDSAWithP256AndSHA256:
		return crypto.SHA256, nil
	case tls.PSSWithSHA384, tls.ECDSAWithP384AndSHA384:
		return crypto.SHA384, nil
	case tls.PSSWithSHA512, tls.ECDSAWithP521AndSHA512:
		return crypto.SHA512, nil
	case tls.Ed25519, tls.MLDSA44, tls.MLDSA65, tls.MLDSA87:
		return crypto.Hash(0), nil
	}
	return 0, errors.New("unsupported TLS1.3 CertificateVerify signature")
}
func stSignatureInput(server bool, transcript hash.Hash) []byte {
	label := "TLS 1.3, client CertificateVerify"
	if server {
		label = "TLS 1.3, server CertificateVerify"
	}
	b := bytes.Repeat([]byte{' '}, 64)
	b = append(b, label...)
	b = append(b, 0)
	return append(b, transcript.Sum(nil)...)
}
func stSignatureKey(key any, scheme tls.SignatureScheme) bool {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= 1024 && k.N.BitLen() <= 8192 && (scheme == tls.PSSWithSHA256 || scheme == tls.PSSWithSHA384 || scheme == tls.PSSWithSHA512)
	case *ecdsa.PublicKey:
		bits := k.Curve.Params().BitSize
		return bits == 256 && scheme == tls.ECDSAWithP256AndSHA256 || bits == 384 && scheme == tls.ECDSAWithP384AndSHA384 || bits == 521 && scheme == tls.ECDSAWithP521AndSHA512
	case ed25519.PublicKey:
		return scheme == tls.Ed25519
	case *mldsa.PublicKey:
		return k.Parameters() == mldsa.MLDSA44() && scheme == tls.MLDSA44 || k.Parameters() == mldsa.MLDSA65() && scheme == tls.MLDSA65 || k.Parameters() == mldsa.MLDSA87() && scheme == tls.MLDSA87
	}
	return false
}
func stVerifyCertificateSignature(body []byte, key any, transcript hash.Hash) error {
	p := stCursor{data: body}
	scheme := tls.SignatureScheme(p.number(2))
	sig := p.vector(2)
	if e := p.end(); e != nil {
		return e
	}
	if (!slices.Contains(stSignatures, scheme) && scheme != tls.MLDSA44 && scheme != tls.MLDSA65 && scheme != tls.MLDSA87) || !stSignatureKey(key, scheme) {
		return errors.New("invalid TLS CertificateVerify key/signature selection")
	}
	h, e := stSignatureHash(scheme)
	if e != nil {
		return e
	}
	data := stSignatureInput(true, transcript)
	if h != 0 {
		hash := h.New()
		hash.Write(data)
		data = hash.Sum(nil)
	}
	switch k := key.(type) {
	case *rsa.PublicKey:
		e = rsa.VerifyPSS(k, h, data, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h})
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, data, sig) {
			e = errors.New("invalid TLS ECDSA signature")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(k, data, sig) {
			e = errors.New("invalid TLS Ed25519 signature")
		}
	case *mldsa.PublicKey:
		e = mldsa.Verify(k, data, sig, nil)
	}
	return e
}
func stSendClientCertificate(cfg *tls.Config, req *tls.CertificateRequestInfo, context []byte, transcript hash.Hash, send func(byte, []byte) error) error {
	var certificate *tls.Certificate
	var e error
	if cfg.GetClientCertificate != nil {
		certificate, e = cfg.GetClientCertificate(req)
		if e != nil {
			return e
		}
	} else {
		for i := range cfg.Certificates {
			if req.SupportsCertificate(&cfg.Certificates[i]) == nil {
				certificate = &cfg.Certificates[i]
				break
			}
		}
	}
	body := stVector(context, 1)
	var list []byte
	if certificate != nil {
		for _, der := range certificate.Certificate {
			list = append(list, stVector(der, 3)...)
			list = append(list, 0, 0)
		}
	}
	if len(list) > 1<<20 {
		return errors.New("TLS client certificate chain exceeds1MiB")
	}
	body = append(body, stVector(list, 3)...)
	if e = send(11, body); e != nil {
		return e
	}
	if len(list) == 0 {
		return nil
	}
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return errors.New("TLS client private key is not a signer")
	}
	for _, scheme := range req.SignatureSchemes {
		if !stSignatureKey(signer.Public(), scheme) || len(certificate.SupportedSignatureAlgorithms) > 0 && !slices.Contains(certificate.SupportedSignatureAlgorithms, scheme) {
			continue
		}
		h, e := stSignatureHash(scheme)
		if e != nil {
			continue
		}
		data := stSignatureInput(false, transcript)
		var opts crypto.SignerOpts = h
		if h != 0 {
			digest := h.New()
			digest.Write(data)
			data = digest.Sum(nil)
		}
		if _, ok := signer.Public().(*rsa.PublicKey); ok {
			opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
		}
		signature, e := signer.Sign(rand.Reader, data, opts)
		if e != nil {
			return e
		}
		out := binary.BigEndian.AppendUint16(nil, uint16(scheme))
		out = append(out, stVector(signature, 2)...)
		return send(15, out)
	}
	return errors.New("no compatible TLS client signature algorithm")
}
