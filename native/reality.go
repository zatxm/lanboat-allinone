package native

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

type RealityOptions struct {
	Enabled           bool                `json:"enabled,omitempty"`
	Handshake         *ShadowTLSHandshake `json:"handshake,omitempty"`
	PrivateKey        string              `json:"private_key,omitempty"`
	PublicKey         string              `json:"public_key,omitempty"`
	ShortID           []string            `json:"short_id,omitempty"`
	MaxTimeDifference string              `json:"max_time_difference,omitempty"`
	MLDSA65Seed       string              `json:"mldsa65_seed,omitempty"`
	MLDSA65Verify     string              `json:"mldsa65_verify,omitempty"`
}

func (o RealityOptions) shortIDs() []string {
	if len(o.ShortID) == 0 {
		return []string{""}
	}
	return o.ShortID
}
func (o RealityOptions) timeDifference() (time.Duration, error) {
	if o.MaxTimeDifference == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(o.MaxTimeDifference)
	if err != nil || d < 0 {
		return 0, errors.New("Reality max_time_difference must be a nonnegative duration")
	}
	return d, nil
}

func (o RealityOptions) MarshalJSON() ([]byte, error) {
	type plain RealityOptions
	if o.PublicKey == "" || len(o.ShortID) != 1 {
		return json.Marshal(plain(o))
	}
	return json.Marshal(struct {
		plain
		ShortID string `json:"short_id"`
	}{plain(o), o.ShortID[0]})
}

func realityKey(value string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(b) != 32 {
		return nil, errors.New("Reality key must be32bytes in unpadded base64url")
	}
	return b, nil
}

func realityShortID(value string) ([8]byte, error) {
	var id [8]byte
	b, err := hex.DecodeString(value)
	if err != nil || len(b) > 8 {
		return id, errors.New("Reality short_id must contain0-16 hexadecimal digits in whole bytes")
	}
	copy(id[:], b)
	return id, nil
}

func realityAEAD(key *ecdh.PrivateKey, public, random []byte) (cipher.AEAD, []byte, error) {
	peer, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		return nil, nil, err
	}
	shared, err := key.ECDH(peer)
	if err != nil {
		return nil, nil, err
	}
	auth, err := hkdf.Key(sha256.New, shared, random[:20], "REALITY", 32)
	clear(shared)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(auth)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	return aead, auth, err
}

func (o *RealityOptions) clientHello(h *stClientHello, hello []byte) ([]byte, error) {
	public, err := realityKey(o.PublicKey)
	if err != nil {
		return nil, err
	}
	if len(hello) < 71 || h.key == nil || h.key.Curve() != ecdh.X25519() {
		return nil, errors.New("Reality requires an X25519 ClientHello")
	}
	if len(o.shortIDs()) != 1 {
		return nil, errors.New("Reality requires one client short ID")
	}
	id, err := realityShortID(o.shortIDs()[0])
	if err != nil {
		return nil, err
	}
	private := h.key
	if h.fallback != nil {
		private = h.fallback
	}
	aead, auth, err := realityAEAD(private, public, h.random)
	if err != nil {
		return nil, err
	}
	clear(h.session)
	clear(hello[39:71])
	plain := make([]byte, 16)
	copy(plain, []byte{1, 8, 1})
	binary.BigEndian.PutUint32(plain[4:], uint32(time.Now().Unix()))
	copy(plain[8:], id[:])
	h.session = aead.Seal(h.session[:0], h.random[20:], plain, hello)
	copy(hello[39:71], h.session)
	h.config = cloneTLSConfig(h.config)
	h.config.InsecureSkipVerify = true
	verify := h.config.VerifyConnection
	h.config.VerifyConnection = func(state tls.ConnectionState) error {
		defer clear(auth)
		if len(state.PeerCertificates) == 0 {
			return errors.New("Reality peer certificate missing")
		}
		leaf := state.PeerCertificates[0]
		public, ok := leaf.PublicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("Reality peer certificate must use Ed25519")
		}
		mac := hmac.New(sha512.New, auth)
		mac.Write(public)
		if !hmac.Equal(mac.Sum(nil), leaf.Signature) {
			return errors.New("Reality peer authentication failed")
		}
		if o.MLDSA65Verify != "" {
			public, err := realityMLDSAPublic(o.MLDSA65Verify)
			if err != nil {
				return err
			}
			mac.Write(hello)
			mac.Write(h.serverHello)
			if len(leaf.Extensions) == 0 || !leaf.Extensions[0].Id.Equal(realityMLDSAOID) || mldsa.Verify(public, mac.Sum(nil), leaf.Extensions[0].Value, nil) != nil {
				return errors.New("Reality ML-DSA-65 authentication failed")
			}
		}
		if verify != nil {
			return verify(state)
		}
		return nil
	}
	return hello, nil
}

func (o TLSOptions) realityEnabled() bool { return o.Reality != nil && o.Reality.Enabled }

func (o TLSOptions) realityConfig(server bool, hostname string) (*tls.Config, error) {
	x := o.Reality
	if !o.Enabled || x == nil || !x.Enabled {
		return nil, errors.New("Reality requires enabled TLS")
	}
	if o.ServerName == "" {
		o.ServerName = hostname
	}
	if (!server || o.ServerName != "") && !echDomain(o.ServerName) || o.DisableSNI || o.Insecure {
		return nil, errors.New("Reality requires a DNS server_name and authenticated TLS")
	}
	if o.ECH != nil || len(o.Certificate)+len(o.Key)+len(o.ClientCertificate)+len(o.ClientKey)+len(o.CertificateSHA256)+len(o.CertificatePublicKeySHA256)+len(o.ClientCertificateSHA256)+len(o.ClientCertificatePublicKeySHA256) != 0 || o.CertificatePath != "" || o.KeyPath != "" || len(o.ClientCertificatePath) != 0 || o.ClientKeyPath != "" || o.PKCS12 != "" || o.PKCS12Path != "" || o.PKCS12Password != "" || o.ClientAuthentication != "" {
		return nil, errors.New("Reality cannot combine ordinary TLS identities,CA/pins,ECH or client authentication")
	}
	if o.MinVersion != "" && o.MinVersion != "1.3" || o.MaxVersion != "" && o.MaxVersion != "1.3" || len(o.CipherSuites) != 0 || len(o.CurvePreferences) != 0 {
		return nil, errors.New("Reality uses TLS1.3 with hybrid X25519/ML-KEM and fixed TLS1.3 cipher negotiation")
	}
	if !server && len(x.shortIDs()) != 1 || len(x.shortIDs()) > 128 {
		return nil, errors.New("Reality requires one client short_id or1-128 server short IDs")
	}
	seen := map[[8]byte]bool{}
	for _, s := range x.shortIDs() {
		id, err := realityShortID(s)
		if err != nil {
			return nil, err
		}
		if seen[id] {
			return nil, errors.New("duplicate Reality short_id")
		}
		seen[id] = true
	}
	if server {
		if x.PublicKey != "" || x.MLDSA65Verify != "" || x.Handshake == nil {
			return nil, errors.New("Reality server requires handshake and private_key")
		}
		private, err := realityKey(x.PrivateKey)
		if err != nil {
			return nil, err
		}
		defer clear(private)
		if x.MLDSA65Seed != "" {
			seed, _ := realityKey(x.MLDSA65Seed)
			if bytes.Equal(seed, private) {
				clear(seed)
				return nil, errors.New("Reality identity and ML-DSA-65 seeds must differ")
			}
			clear(seed)
			if _, err := realityMLDSAPrivate(x.MLDSA65Seed); err != nil {
				return nil, err
			}
		}
		if !shadowHost(x.Handshake.Server) || x.Handshake.ServerPort == 0 {
			return nil, errors.New("Reality handshake requires server and server_port")
		}
		if x.MaxTimeDifference != "" {
			if _, err := x.timeDifference(); err != nil {
				return nil, err
			}
		}
	} else {
		if x.PrivateKey != "" || x.Handshake != nil || x.MaxTimeDifference != "" || x.MLDSA65Seed != "" {
			return nil, errors.New("Reality client contains server-only fields")
		}
		if _, err := realityKey(x.PublicKey); err != nil {
			return nil, err
		}
		if x.MLDSA65Verify != "" {
			if _, err := realityMLDSAPublic(x.MLDSA65Verify); err != nil {
				return nil, err
			}
		}
	}
	c := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ServerName: o.ServerName, NextProtos: o.ALPN, SessionTicketsDisabled: true, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}}
	if err := o.configureProtocol(c, server); err != nil {
		return nil, err
	}
	return c, nil
}

func realityHelloData(hello []byte) ([]byte, []byte, error) {
	if len(hello) < 71 || hello[0] != 1 || hello[38] != 32 || int(hello[1])<<16|int(hello[2])<<8|int(hello[3]) != len(hello)-4 {
		return nil, nil, errors.New("invalid Reality ClientHello")
	}
	p := stCursor{data: hello[71:]}
	p.vector(2)
	if !bytes.Equal(p.vector(1), []byte{0}) {
		return nil, nil, errors.New("invalid Reality compression")
	}
	extensions := p.vector(2)
	if p.end() != nil {
		return nil, nil, errors.New("invalid Reality extensions")
	}
	ext, err := stExtensions(extensions)
	if err != nil {
		return nil, nil, err
	}
	versions := stCursor{data: ext[43]}
	offered := versions.vector(1)
	hasTLS13 := false
	for i := 0; i+1 < len(offered); i += 2 {
		hasTLS13 = hasTLS13 || offered[i] == 3 && offered[i+1] == 4
	}
	if versions.end() != nil || len(offered)%2 != 0 || !hasTLS13 {
		return nil, nil, errors.New("Reality requires TLS1.3")
	}
	q := stCursor{data: ext[51]}
	shares := stCursor{data: q.vector(2)}
	if q.end() != nil {
		return nil, nil, errors.New("invalid Reality key shares")
	}
	var hybrid, classic []byte
	for len(shares.data) > 0 && shares.err == nil {
		group := tls.CurveID(shares.number(2))
		key := shares.vector(2)
		switch group {
		case tls.X25519MLKEM768:
			if len(key) != 1184+32 || hybrid != nil {
				return nil, nil, errors.New("invalid Reality hybrid key share")
			}
			hybrid = key[1184:]
		case tls.X25519:
			if len(key) != 32 || classic != nil {
				return nil, nil, errors.New("invalid Reality X25519 key share")
			}
			classic = key
		}
	}
	if shares.end() != nil || hybrid == nil && classic == nil {
		return nil, nil, errors.New("Reality X25519 key share missing")
	}
	if classic != nil {
		return hello[6:38], classic, nil
	}
	return hello[6:38], hybrid, nil
}

func (x *RealityOptions) authenticate(hello []byte, now time.Time) ([]byte, error) {
	random, public, err := realityHelloData(hello)
	if err != nil {
		return nil, err
	}
	secret, err := realityKey(x.PrivateKey)
	if err != nil {
		return nil, err
	}
	key, err := ecdh.X25519().NewPrivateKey(secret)
	clear(secret)
	if err != nil {
		return nil, err
	}
	aead, auth, err := realityAEAD(key, public, random)
	if err != nil {
		return nil, err
	}
	ad := bytes.Clone(hello)
	clear(ad[39:71])
	plain, err := aead.Open(nil, random[20:], hello[39:71], ad)
	if err != nil {
		return nil, errors.New("Reality authentication failed")
	}
	match := false
	for _, s := range x.shortIDs() {
		id, _ := realityShortID(s)
		match = hmac.Equal(id[:], plain[8:16]) || match
	}
	if !match {
		return nil, errors.New("Reality short ID mismatch")
	}
	if limit, _ := x.timeDifference(); limit > 0 {
		delta := now.Sub(time.Unix(int64(binary.BigEndian.Uint32(plain[4:8])), 0))
		if delta > limit || delta < -limit {
			return nil, errors.New("Reality authentication timestamp expired")
		}
	}
	return auth, nil
}

// GenerateRealityKeyPair returns fresh X25519 credentials to the explicit caller.
func GenerateRealityKeyPair() (private, public string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes()), base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}
