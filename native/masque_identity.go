package native

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"time"
)

func masqueKeyDER(s string) ([]byte, error) {
	if b, _ := pem.Decode([]byte(s)); b != nil {
		return b.Bytes, nil
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
}
func prepareMasqueIdentity(o *Outbound) error {
	if o.Type != "masque" {
		if o.MasquePublicKey != "" {
			return errors.New("public_key requires MASQUE")
		}
		return nil
	}
	if len(o.PrivateKey) > 0 {
		if len(o.TLS.ClientCertificate) > 0 || len(o.TLS.ClientCertificatePath) > 0 || o.TLS.PKCS12 != "" || o.TLS.PKCS12Path != "" {
			return errors.New("MASQUE private_key conflicts with TLS client identity")
		}
		der, e := masqueKeyDER(strings.Join(o.PrivateKey, "\n"))
		if e != nil {
			return e
		}
		key, e := x509.ParsePKCS8PrivateKey(der)
		if e != nil {
			key, e = x509.ParseECPrivateKey(der)
		}
		if e != nil {
			return e
		}
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("MASQUE private_key must be ECDSA")
		}
		serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if e != nil {
			return e
		}
		template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Lanboat MASQUE"}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
		certificate, e := x509.CreateCertificate(rand.Reader, template, template, &ec.PublicKey, ec)
		if e != nil {
			return e
		}
		pkcs8, e := x509.MarshalPKCS8PrivateKey(ec)
		if e != nil {
			return e
		}
		o.TLS.ClientCertificate = []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}))}
		o.PrivateKey = nil
		o.TLS.ClientKey = []string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))}
	}
	if o.MasquePublicKey != "" {
		if len(o.TLS.Certificate) > 0 || o.TLS.CertificatePath != "" || len(o.TLS.CertificateSHA256) > 0 || len(o.TLS.CertificatePublicKeySHA256) > 0 {
			return errors.New("MASQUE public_key conflicts with TLS server trust")
		}
		der, e := masqueKeyDER(o.MasquePublicKey)
		if e != nil {
			return e
		}
		pub, e := x509.ParsePKIXPublicKey(der)
		if e != nil {
			x, y := elliptic.Unmarshal(elliptic.P256(), der)
			if x == nil {
				return errors.New("invalid MASQUE ECDSA public_key")
			}
			pub = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		}
		spki, e := x509.MarshalPKIXPublicKey(pub)
		if e != nil {
			return e
		}
		sum := sha256.Sum256(spki)
		o.TLS.CertificatePublicKeySHA256 = []string{base64.StdEncoding.EncodeToString(sum[:])}
		o.MasquePublicKey = ""
	}
	return nil
}
