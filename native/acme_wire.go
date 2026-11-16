package native

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type acmeError struct {
	typ    string
	status int
	retry  time.Time
}

func (e *acmeError) Error() string {
	return fmt.Sprintf("ACME request failed: HTTP%d %s", e.status, e.typ)
}
func acmeB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func acmeJSON(v any) []byte   { b, _ := json.Marshal(v); return b }

func acmeJWK(key crypto.Signer) (json.RawMessage, string, crypto.Hash, error) {
	switch pub := key.Public().(type) {
	case *ecdsa.PublicKey:
		size := (pub.Curve.Params().BitSize + 7) / 8
		alg := "ES256"
		hash := crypto.SHA256
		if size == 48 {
			alg, hash = "ES384", crypto.SHA384
		} else if size == 66 {
			alg, hash = "ES512", crypto.SHA512
		}
		return acmeJSON(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{pub.Curve.Params().Name, "EC", acmeB64(pub.X.FillBytes(make([]byte, size))), acmeB64(pub.Y.FillBytes(make([]byte, size)))}), alg, hash, nil
	case *rsa.PublicKey:
		return acmeJSON(struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}{acmeB64(big.NewInt(int64(pub.E)).Bytes()), "RSA", acmeB64(pub.N.Bytes())}), "RS256", crypto.SHA256, nil
	case ed25519.PublicKey:
		return acmeJSON(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
		}{"Ed25519", "OKP", acmeB64(pub)}), "EdDSA", crypto.Hash(0), nil
	}
	return nil, "", 0, errors.New("unsupported ACME JWK")
}
func acmeSignature(key crypto.Signer, hash crypto.Hash, message []byte) ([]byte, error) {
	var digest []byte
	switch hash {
	case crypto.SHA256:
		d := sha256.Sum256(message)
		digest = d[:]
	case crypto.SHA384:
		d := sha512.Sum384(message)
		digest = d[:]
	case crypto.SHA512:
		d := sha512.Sum512(message)
		digest = d[:]
	default:
		digest = message
	}
	if k, ok := key.(*ecdsa.PrivateKey); ok {
		r, s, e := ecdsa.Sign(rand.Reader, k, digest)
		if e != nil {
			return nil, e
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		return out, nil
	}
	return key.Sign(rand.Reader, digest, hash)
}

type acmeJWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type acmeClient struct {
	p          *managedCertificate
	http       *http.Client
	base       *url.URL
	key        crypto.Signer
	jwk        json.RawMessage
	alg        string
	hash       crypto.Hash
	kid, nonce string
	directory  struct {
		NewNonce   string `json:"newNonce"`
		NewAccount string `json:"newAccount"`
		NewOrder   string `json:"newOrder"`
		Meta       struct {
			ExternalAccountRequired bool              `json:"externalAccountRequired"`
			Profiles                map[string]string `json:"profiles"`
		} `json:"meta"`
	}
}

func (c *acmeClient) validateURL(address string) error {
	u, e := acmeURL(address)
	if e != nil {
		return e
	}
	if u.Scheme != c.base.Scheme || !strings.EqualFold(u.Host, c.base.Host) {
		return errors.New("ACME resource URL changed authority")
	}
	return nil
}
func acmeResponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, originCAMaxResponse+1))
	if e != nil || len(b) > originCAMaxResponse {
		return nil, errors.New("invalid ACME response size")
	}
	return b, nil
}
func (c *acmeClient) request(ctx context.Context, method, address, contentType string, body []byte) ([]byte, http.Header, int, error) {
	if e := c.validateURL(address); e != nil {
		return nil, nil, 0, e
	}
	req, e := http.NewRequestWithContext(ctx, method, address, bytes.NewReader(body))
	if e != nil {
		return nil, nil, 0, e
	}
	options, _ := c.p.r.httpClientOptions(c.p.options.HTTPClient)
	for k, values := range options.Headers {
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, e := c.http.Do(req)
	if e != nil {
		return nil, nil, 0, errors.New("ACME HTTP request failed")
	}
	data, e := acmeResponse(resp)
	if nonce := resp.Header.Get("Replay-Nonce"); nonce != "" {
		c.nonce = nonce
	}
	if e != nil {
		return nil, resp.Header, resp.StatusCode, e
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var problem struct {
			Type string `json:"type"`
		}
		json.Unmarshal(data, &problem)
		code := strings.TrimPrefix(problem.Type, "urn:ietf:params:acme:error:")
		if code == problem.Type || len(code) == 0 || len(code) > 64 || strings.ContainsFunc(code, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') }) {
			problem.Type = "invalidResponse"
		}
		return nil, resp.Header, resp.StatusCode, &acmeError{typ: problem.Type, status: resp.StatusCode, retry: acmeRetryAfter(resp.Header, c.p.now(), 0)}
	}
	return data, resp.Header, resp.StatusCode, nil
}
func acmeRetryAfter(h http.Header, now time.Time, fallback time.Duration) time.Time {
	if seconds, e := strconv.ParseInt(h.Get("Retry-After"), 10, 64); e == nil && seconds >= 0 && seconds <= 86400 {
		return now.Add(time.Duration(seconds) * time.Second)
	}
	if when, e := http.ParseTime(h.Get("Retry-After")); e == nil && when.After(now) && when.Before(now.Add(24*time.Hour)) {
		return when
	}
	return now.Add(fallback)
}
func (c *acmeClient) post(ctx context.Context, address string, payload []byte) ([]byte, http.Header, int, error) {
	for range 5 {
		if c.nonce == "" {
			if _, _, _, e := c.request(ctx, "HEAD", c.directory.NewNonce, "", nil); e != nil {
				return nil, nil, 0, e
			}
		}
		if c.nonce == "" {
			return nil, nil, 0, errors.New("ACME server did not provide a replay nonce")
		}
		protected := struct {
			Alg   string          `json:"alg"`
			JWK   json.RawMessage `json:"jwk,omitempty"`
			Kid   string          `json:"kid,omitempty"`
			Nonce string          `json:"nonce"`
			URL   string          `json:"url"`
		}{Alg: c.alg, Kid: c.kid, Nonce: c.nonce, URL: address}
		if c.kid == "" {
			protected.JWK = c.jwk
		}
		c.nonce = ""
		encoded := acmeB64(acmeJSON(protected))
		value := acmeB64(payload)
		signature, e := acmeSignature(c.key, c.hash, []byte(encoded+"."+value))
		if e != nil {
			return nil, nil, 0, e
		}
		b, h, status, e := c.request(ctx, "POST", address, "application/jose+json", acmeJSON(acmeJWS{encoded, value, acmeB64(signature)}))
		var problem *acmeError
		if errors.As(e, &problem) && problem.typ == "urn:ietf:params:acme:error:badNonce" {
			continue
		}
		return b, h, status, e
	}
	return nil, nil, 0, errors.New("ACME replay nonce retry limit exceeded")
}
func (c *acmeClient) eab(o *ACMEExternalAccount) (*acmeJWS, error) {
	if o == nil {
		return nil, nil
	}
	macKey, e := base64.RawURLEncoding.Strict().DecodeString(strings.TrimRight(o.MACKey, "="))
	if e != nil {
		return nil, e
	}
	protected := acmeB64(acmeJSON(struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		URL string `json:"url"`
	}{"HS256", o.KeyID, c.directory.NewAccount}))
	payload := acmeB64(c.jwk)
	mac := hmac.New(sha256.New, macKey)
	mac.Write([]byte(protected + "." + payload))
	return &acmeJWS{protected, payload, acmeB64(mac.Sum(nil))}, nil
}
