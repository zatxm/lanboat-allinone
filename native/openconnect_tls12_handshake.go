package native

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"slices"
	"time"
)

var ocTLS12Signatures = []tls.SignatureScheme{
	tls.PSSWithSHA256, tls.ECDSAWithP256AndSHA256, tls.Ed25519, tls.PSSWithSHA384, tls.PSSWithSHA512,
	tls.PKCS1WithSHA256, tls.PKCS1WithSHA384, tls.PKCS1WithSHA512, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512,
}

func ocTLS12SignatureHash(s tls.SignatureScheme) (crypto.Hash, error) {
	switch s {
	case tls.PKCS1WithSHA256:
		return crypto.SHA256, nil
	case tls.PKCS1WithSHA384:
		return crypto.SHA384, nil
	case tls.PKCS1WithSHA512:
		return crypto.SHA512, nil
	}
	return stSignatureHash(s)
}
func ocTLS12SignatureKey(key any, s tls.SignatureScheme) bool {
	if !slices.Contains(ocTLS12Signatures, s) {
		return false
	}
	switch k := key.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= 1024 && k.N.BitLen() <= 8192 && (s == tls.PSSWithSHA256 || s == tls.PSSWithSHA384 || s == tls.PSSWithSHA512 || s == tls.PKCS1WithSHA256 || s == tls.PKCS1WithSHA384 || s == tls.PKCS1WithSHA512)
	case *ecdsa.PublicKey:
		return s == tls.ECDSAWithP256AndSHA256 || s == tls.ECDSAWithP384AndSHA384 || s == tls.ECDSAWithP521AndSHA512
	case ed25519.PublicKey:
		return s == tls.Ed25519
	}
	return false
}
func ocTLS12Digest(s tls.SignatureScheme, input []byte) (crypto.Hash, []byte, error) {
	h, e := ocTLS12SignatureHash(s)
	if e != nil {
		return h, nil, e
	}
	if h == 0 {
		return h, input, nil
	}
	d := h.New()
	d.Write(input)
	return h, d.Sum(nil), nil
}
func ocTLS12Verify(key any, s tls.SignatureScheme, input, sig []byte) error {
	if !ocTLS12SignatureKey(key, s) {
		return errors.New("invalid CSTP TLS signature scheme")
	}
	h, d, e := ocTLS12Digest(s, input)
	if e != nil {
		return e
	}
	switch k := key.(type) {
	case *rsa.PublicKey:
		if s == tls.PKCS1WithSHA256 || s == tls.PKCS1WithSHA384 || s == tls.PKCS1WithSHA512 {
			return rsa.VerifyPKCS1v15(k, h, d, sig)
		}
		return rsa.VerifyPSS(k, h, d, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h})
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(k, d, sig) {
			return nil
		}
	case ed25519.PublicKey:
		if ed25519.Verify(k, d, sig) {
			return nil
		}
	}
	return errors.New("invalid CSTP TLS handshake signature")
}
func ocTLS12Sign(cert *tls.Certificate, schemes []tls.SignatureScheme, input []byte) ([]byte, error) {
	key, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("CSTP TLS certificate has no signing key")
	}
	for _, s := range schemes {
		if !ocTLS12SignatureKey(key.Public(), s) || len(cert.SupportedSignatureAlgorithms) > 0 && !slices.Contains(cert.SupportedSignatureAlgorithms, s) {
			continue
		}
		h, d, e := ocTLS12Digest(s, input)
		if e != nil {
			return nil, e
		}
		var options crypto.SignerOpts = h
		if s == tls.PSSWithSHA256 || s == tls.PSSWithSHA384 || s == tls.PSSWithSHA512 {
			options = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
		}
		sig, e := key.Sign(rand.Reader, d, options)
		if e != nil {
			return nil, e
		}
		return append(binary.BigEndian.AppendUint16(nil, uint16(s)), stVector(sig, 2)...), nil
	}
	return nil, errors.New("no common CSTP TLS signature scheme")
}
func ocTLS12Schemes(body []byte) ([]tls.SignatureScheme, error) {
	p := stCursor{data: body}
	data := p.vector(2)
	if p.end() != nil || len(data) == 0 || len(data)%2 != 0 {
		return nil, errors.New("invalid CSTP TLS signature algorithms")
	}
	var out []tls.SignatureScheme
	for len(data) > 0 {
		out = append(out, tls.SignatureScheme(binary.BigEndian.Uint16(data)))
		data = data[2:]
	}
	return out, nil
}
func ocTLS12Curve(id uint16) ecdh.Curve {
	switch tls.CurveID(id) {
	case tls.X25519:
		return ecdh.X25519()
	case tls.CurveP256:
		return ecdh.P256()
	case tls.CurveP384:
		return ecdh.P384()
	case tls.CurveP521:
		return ecdh.P521()
	}
	return nil
}
func ocTLS12Certificates(body []byte) ([]*x509.Certificate, error) {
	p := stCursor{data: body}
	list := stCursor{data: p.vector(3)}
	if e := p.end(); e != nil {
		return nil, e
	}
	var out []*x509.Certificate
	for len(list.data) > 0 && list.err == nil {
		if len(out) >= 32 {
			return nil, errors.New("CSTP TLS certificate chain exceeds limit")
		}
		der := list.vector(3)
		if list.err != nil {
			return nil, list.err
		}
		cert, e := x509.ParseCertificate(der)
		if e != nil {
			return nil, e
		}
		out = append(out, cert)
	}
	return out, list.end()
}
func ocTLS12Certificate(cert *tls.Certificate) []byte {
	var data []byte
	if cert != nil {
		for _, der := range cert.Certificate {
			data = append(data, stVector(der, 3)...)
		}
	}
	return stMessage(11, stVector(data, 3))
}
func ocTLS12SameIdentity(previous, next []*x509.Certificate) bool {
	if len(previous) == 0 || len(next) == 0 {
		return len(previous) == len(next)
	}
	return bytes.Equal(previous[0].Raw, next[0].Raw)
}
func (c *ocTLS12) peerCertificates(certs []*x509.Certificate) (tls.ConnectionState, error) {
	state := c.ConnectionState()
	if !ocTLS12SameIdentity(state.PeerCertificates, certs) {
		return state, errors.New("CSTP TLS peer identity changed during renegotiation")
	}
	state.PeerCertificates = certs
	state.VerifiedChains = nil
	state.OCSPResponse = nil
	state.SignedCertificateTimestamps = nil
	if !c.server {
		return state, stVerifyCertificates(c.config, &state)
	}
	required := c.config.ClientAuth == tls.RequireAnyClientCert || c.config.ClientAuth == tls.RequireAndVerifyClientCert
	if required && len(certs) == 0 {
		return state, errors.New("CSTP TLS client certificate required")
	}
	if len(certs) > 0 && (c.config.ClientAuth == tls.VerifyClientCertIfGiven || c.config.ClientAuth == tls.RequireAndVerifyClientCert) {
		pool := x509.NewCertPool()
		for _, cert := range certs[1:] {
			pool.AddCert(cert)
		}
		now := time.Now()
		if c.config.Time != nil {
			now = c.config.Time()
		}
		var e error
		state.VerifiedChains, e = certs[0].Verify(x509.VerifyOptions{Roots: c.config.ClientCAs, Intermediates: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now})
		if e != nil {
			return state, e
		}
	}
	if c.config.VerifyPeerCertificate != nil {
		raw := make([][]byte, len(certs))
		for i, cert := range certs {
			raw[i] = cert.Raw
		}
		if e := c.config.VerifyPeerCertificate(raw, state.VerifiedChains); e != nil {
			return state, e
		}
	}
	if c.config.VerifyConnection != nil {
		return state, c.config.VerifyConnection(state)
	}
	return state, nil
}

func (c *ocTLS12) makeClientHello() ([]byte, error) {
	_, old, e := ocTLS12ParseHello(c.clientHello, true)
	if e != nil {
		return nil, e
	}
	body := []byte{3, 3}
	random := make([]byte, 32)
	rand.Read(random)
	body = append(body, random...)
	body = append(body, 0, 0, 2, byte(c.state.CipherSuite>>8), byte(c.state.CipherSuite), 1, 0)
	var ext []byte
	for _, id := range []uint16{0, 10, 11, 13, 16} {
		if value, ok := old[id]; ok {
			ext = stExtension(ext, id, value)
		}
	}
	ext = stExtension(ext, 23, nil)
	ext = stExtension(ext, 0xff01, stVector(c.clientVerify, 1))
	return stMessage(1, append(body, stVector(ext, 2)...)), nil
}
func (c *ocTLS12) checkHello(body []byte, client bool) (map[uint16][]byte, error) {
	_, ext, e := ocTLS12ParseHello(body, client)
	if e != nil {
		return nil, e
	}
	want := bytes.Clone(c.clientVerify)
	if !client {
		want = append(want, c.serverVerify...)
	}
	if !bytes.Equal(ext[0xff01], stVector(want, 1)) {
		return nil, errors.New("CSTP TLS renegotiation binding mismatch")
	}
	if ems, ok := ext[23]; !ok || len(ems) != 0 {
		return nil, errors.New("CSTP TLS renegotiation EMS changed")
	}
	return ext, nil
}
func (c *ocTLS12) expect(kind byte, transcript *[]byte) ([]byte, error) {
	m, e := c.message()
	if e != nil {
		return nil, e
	}
	if m[0] != kind {
		return nil, errors.New("unexpected CSTP TLS handshake message")
	}
	if e = ocTLS12Append(transcript, m); e != nil {
		return nil, e
	}
	return m[4:], nil
}
func ocTLS12Append(transcript *[]byte, m []byte) error {
	if len(*transcript)+len(m) > 512<<10 {
		return errors.New("CSTP TLS transcript exceeds limit")
	}
	*transcript = append(*transcript, m...)
	return nil
}
func (c *ocTLS12) flight(m []byte, transcript *[]byte) error {
	if e := ocTLS12Append(transcript, m); e != nil {
		return e
	}
	return c.send(22, m)
}
func (c *ocTLS12) masterSecret(shared, transcript []byte) []byte {
	h := ocTLS12Hash(c.state.CipherSuite)()
	h.Write(transcript)
	return ocDTLSPRF(ocTLS12Hash(c.state.CipherSuite), shared, "extended master secret", h.Sum(nil), 48)
}
func (c *ocTLS12) finished(master, transcript []byte, client bool) []byte {
	h := ocTLS12Hash(c.state.CipherSuite)()
	h.Write(transcript)
	label := "server finished"
	if client {
		label = "client finished"
	}
	return stMessage(20, ocDTLSPRF(ocTLS12Hash(c.state.CipherSuite), master, label, h.Sum(nil), 12))
}
func (c *ocTLS12) changeRead(next *ocTLS12Cipher) error {
	if len(c.handshake) != 0 {
		return errors.New("extra CSTP TLS handshake before CCS")
	}
	for empty := 0; empty < 128; empty++ {
		kind, data, e := c.record()
		if e != nil {
			return e
		}
		if kind == 20 && bytes.Equal(data, []byte{1}) {
			c.readKey = next
			return nil
		}
		if kind != 23 || len(c.queue) >= 128 || c.queued+len(data) > 256<<10 {
			return errors.New("invalid CSTP TLS CCS")
		}
		c.queue = append(c.queue, bytes.Clone(data))
		c.queued += len(data)
	}
	return errors.New("missing CSTP TLS CCS")
}
func (c *ocTLS12) readFinished(master []byte, transcript *[]byte, client bool) ([]byte, error) {
	want := c.finished(master, *transcript, client)
	for empty := 0; empty < 128; empty++ {
		kind, data, e := c.record()
		if e != nil {
			return nil, e
		}
		if kind != 22 {
			return nil, errors.New("expected CSTP TLS Finished")
		}
		c.handshake = append(c.handshake, data...)
		if len(c.handshake) > len(want) {
			return nil, errors.New("extra CSTP TLS Finished bytes")
		}
		if len(c.handshake) < len(want) {
			continue
		}
		if !hmac.Equal(c.handshake, want) {
			return nil, errors.New("CSTP TLS Finished verification failed")
		}
		c.handshake = nil
		*transcript = append(*transcript, want...)
		return bytes.Clone(want[4:]), nil
	}
	return nil, errors.New("missing CSTP TLS Finished")
}
func (c *ocTLS12) commit(master, clientRandom, serverRandom, clientVerify, serverVerify []byte, state tls.ConnectionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	clear(c.master)
	c.master = bytes.Clone(master)
	c.clientRandom = bytes.Clone(clientRandom)
	c.serverRandom = bytes.Clone(serverRandom)
	c.clientVerify, c.serverVerify = clientVerify, serverVerify
	state.TLSUnique = bytes.Clone(clientVerify)
	c.state = state
	if c.interval > 0 {
		c.nextRekey = time.Now().Add(c.interval)
	}
}

func (c *ocTLS12) clientRenegotiate(sh []byte, h *ocTLS12Handshake) error {
	if sh[0] != 2 || h.hello == nil {
		return errors.New("unexpected CSTP TLS ServerHello")
	}
	ext, e := c.checkHello(sh[4:], false)
	if e != nil {
		return e
	}
	p := stCursor{data: sh[4:]}
	p.take(34)
	if len(p.vector(1)) > 32 {
		return errors.New("invalid CSTP TLS session ID")
	}
	if uint16(p.number(2)) != c.state.CipherSuite {
		return errors.New("CSTP TLS cipher changed")
	}
	for id := range ext {
		if id != 0 && id != 11 && id != 16 && id != 23 && id != 0xff01 {
			return errors.New("unsolicited CSTP TLS ServerHello extension")
		}
	}
	if alpn, ok := ext[16]; ok {
		if !bytes.Equal(alpn, stVector(stVector([]byte(c.state.NegotiatedProtocol), 1), 2)) {
			return errors.New("CSTP TLS ALPN changed")
		}
	} else if c.state.NegotiatedProtocol != "" {
		return errors.New("CSTP TLS ALPN removed")
	}
	transcript := append(bytes.Clone(h.hello), sh...)
	certBody, e := c.expect(11, &transcript)
	if e != nil {
		return e
	}
	certs, e := ocTLS12Certificates(certBody)
	if e != nil || len(certs) == 0 {
		return errors.New("invalid CSTP TLS server certificate")
	}
	state, e := c.peerCertificates(certs)
	if e != nil {
		return e
	}
	spec, ok := browserTLS12Cipher(c.state.CipherSuite)
	if !ok {
		return errors.New("unsupported CSTP TLS cipher")
	}
	clientRandom, serverRandom := h.hello[6:38], sh[6:38]
	var shared, exchange []byte
	defer func() { clear(shared) }()
	if spec.rsaKeyExchange {
		shared, exchange, e = browserTLS12RSAExchange(certs[0])
		if e != nil {
			return e
		}
	} else {
		ske, e := c.expect(12, &transcript)
		if e != nil {
			return e
		}
		q := stCursor{data: ske}
		if q.number(1) != 3 {
			return errors.New("CSTP TLS requires named ECDHE")
		}
		group := uint16(q.number(2))
		peer := q.vector(1)
		params := ske[:len(ske)-len(q.data)]
		scheme := tls.SignatureScheme(q.number(2))
		sig := q.vector(2)
		if e = q.end(); e != nil {
			return e
		}
		_, chExt, e := ocTLS12ParseHello(h.hello[4:], true)
		if e != nil {
			return e
		}
		schemes, e := ocTLS12Schemes(chExt[13])
		if e != nil || !slices.Contains(schemes, scheme) {
			return errors.New("unoffered CSTP TLS signature scheme")
		}
		groups := stCursor{data: chExt[10]}
		ids := groups.vector(2)
		found := false
		for len(ids) >= 2 {
			found = found || binary.BigEndian.Uint16(ids) == group
			ids = ids[2:]
		}
		curve := ocTLS12Curve(group)
		if !found || curve == nil {
			return errors.New("unoffered CSTP TLS ECDHE group")
		}
		input := append(append(bytes.Clone(clientRandom), serverRandom...), params...)
		if e = browserTLS12Verify(certs[0].PublicKey, scheme, input, sig); e != nil {
			return e
		}
		private, e := curve.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		pub, e := curve.NewPublicKey(peer)
		if e != nil {
			return e
		}
		shared, e = private.ECDH(pub)
		if e != nil {
			return e
		}
		exchange = stVector(private.PublicKey().Bytes(), 1)
	}
	next, e := c.message()
	if e != nil {
		return e
	}
	var clientCert *tls.Certificate
	var request *tls.CertificateRequestInfo
	if next[0] == 13 {
		if e = ocTLS12Append(&transcript, next); e != nil {
			return e
		}
		request, e = ocTLS12Request(next[4:])
		if e != nil {
			return e
		}
		types := stCursor{data: next[4:]}
		allowed := types.vector(1)
		if c.certificate != nil && (request.SupportsCertificate(c.certificate) == nil || browserTLS12ClientMatch(c.certificate, request, allowed)) {
			clientCert = c.certificate
		}
		next, e = c.message()
		if e != nil {
			return e
		}
	}
	if !bytes.Equal(next, stMessage(14, nil)) {
		return errors.New("expected CSTP TLS ServerHelloDone")
	}
	if e = ocTLS12Append(&transcript, next); e != nil {
		return e
	}
	if request != nil {
		if e = c.flight(ocTLS12Certificate(clientCert), &transcript); e != nil {
			return e
		}
	}
	if e = c.flight(stMessage(16, exchange), &transcript); e != nil {
		return e
	}
	master := c.masterSecret(shared, transcript)
	defer clear(master)
	keys, e := browserTLS12Keys(c.state.CipherSuite, master, clientRandom, serverRandom)
	if e != nil {
		return e
	}
	if clientCert != nil && len(clientCert.Certificate) > 0 {
		sig, e := browserTLS12Sign(clientCert, request.SignatureSchemes, transcript)
		if e != nil {
			return e
		}
		if e = c.flight(stMessage(15, sig), &transcript); e != nil {
			return e
		}
	}
	if e = c.send(20, []byte{1}); e != nil {
		return e
	}
	keys[0].buffer = c.writeKey.buffer
	c.writeKey = keys[0]
	finish := c.finished(master, transcript, true)
	if e = c.flight(finish, &transcript); e != nil {
		return e
	}
	if e = c.changeRead(keys[1]); e != nil {
		return e
	}
	serverVerify, e := c.readFinished(master, &transcript, false)
	if e != nil {
		return e
	}
	c.commit(master, clientRandom, serverRandom, bytes.Clone(finish[4:]), serverVerify, state)
	return nil
}

func ocTLS12Request(body []byte) (*tls.CertificateRequestInfo, error) {
	p := stCursor{data: body}
	types := p.vector(1)
	if len(types) == 0 {
		return nil, errors.New("empty CSTP TLS certificate types")
	}
	schemes := p.vector(2)
	list, e := ocTLS12Schemes(stVector(schemes, 2))
	if e != nil {
		return nil, e
	}
	r := &tls.CertificateRequestInfo{Version: tls.VersionTLS12, SignatureSchemes: list}
	ca := stCursor{data: p.vector(2)}
	if e = p.end(); e != nil {
		return nil, e
	}
	for len(ca.data) > 0 && ca.err == nil {
		r.AcceptableCAs = append(r.AcceptableCAs, bytes.Clone(ca.vector(2)))
	}
	return r, ca.end()
}
func (c *ocTLS12) serverRenegotiate(ch []byte, h *ocTLS12Handshake) error {
	if ch[0] != 1 {
		return errors.New("expected CSTP TLS ClientHello")
	}
	ext, e := c.checkHello(ch[4:], true)
	if e != nil {
		return e
	}
	_, initial, e := ocTLS12ParseHello(c.clientHello, true)
	if e != nil {
		return e
	}
	if !bytes.Equal(initial[0], ext[0]) {
		return errors.New("CSTP TLS SNI changed")
	}
	p := stCursor{data: ch[4:]}
	p.take(34)
	p.vector(1)
	suites := p.vector(2)
	found := false
	for len(suites) >= 2 {
		id := binary.BigEndian.Uint16(suites)
		if id == 0xff {
			return errors.New("SCSV in CSTP TLS renegotiation")
		}
		found = found || id == c.state.CipherSuite
		suites = suites[2:]
	}
	if p.err != nil || len(suites) != 0 || !found {
		return errors.New("CSTP TLS cipher changed")
	}
	schemes, e := ocTLS12Schemes(ext[13])
	if e != nil {
		return e
	}
	cert := c.certificate
	if cert == nil || len(cert.Certificate) == 0 {
		return errors.New("CSTP TLS server certificate missing")
	}
	groups := stCursor{data: ext[10]}
	data := groups.vector(2)
	if groups.end() != nil || len(data)%2 != 0 {
		return errors.New("invalid CSTP TLS groups")
	}
	var offered []uint16
	for len(data) > 0 {
		offered = append(offered, binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	prefs := c.config.CurvePreferences
	if len(prefs) == 0 {
		prefs = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
	}
	var group uint16
	for _, id := range prefs {
		if ocTLS12Curve(uint16(id)) != nil && slices.Contains(offered, uint16(id)) {
			group = uint16(id)
			break
		}
	}
	if group == 0 {
		return errors.New("no common CSTP TLS ECDHE group")
	}
	private, e := ocTLS12Curve(group).GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	clientRandom, serverRandom := ch[6:38], make([]byte, 32)
	rand.Read(serverRandom)
	sh := append([]byte{3, 3}, serverRandom...)
	sh = append(sh, 0, byte(c.state.CipherSuite>>8), byte(c.state.CipherSuite), 0)
	var se []byte
	se = stExtension(se, 23, nil)
	se = stExtension(se, 0xff01, stVector(append(bytes.Clone(c.clientVerify), c.serverVerify...), 1))
	if c.state.NegotiatedProtocol != "" {
		protocols := stCursor{data: ext[16]}
		list := stCursor{data: protocols.vector(2)}
		found := false
		for len(list.data) > 0 && list.err == nil {
			found = found || string(list.vector(1)) == c.state.NegotiatedProtocol
		}
		if protocols.end() != nil || list.end() != nil || !found {
			return errors.New("CSTP TLS ALPN changed")
		}
		se = stExtension(se, 16, stVector(stVector([]byte(c.state.NegotiatedProtocol), 1), 2))
	}
	sh = append(sh, stVector(se, 2)...)
	transcript := bytes.Clone(ch)
	if e = c.flight(stMessage(2, sh), &transcript); e != nil {
		return e
	}
	if e = c.flight(ocTLS12Certificate(cert), &transcript); e != nil {
		return e
	}
	params := []byte{3, byte(group >> 8), byte(group)}
	params = append(params, stVector(private.PublicKey().Bytes(), 1)...)
	input := append(append(bytes.Clone(clientRandom), serverRandom...), params...)
	signature, e := ocTLS12Sign(cert, schemes, input)
	if e != nil {
		return e
	}
	if e = c.flight(stMessage(12, append(params, signature...)), &transcript); e != nil {
		return e
	}
	request := c.config.ClientAuth != tls.NoClientCert
	if request {
		var schemes, ca []byte
		for _, s := range ocTLS12Signatures {
			schemes = binary.BigEndian.AppendUint16(schemes, uint16(s))
		}
		if c.config.ClientCAs != nil {
			for _, der := range c.config.ClientCAs.Subjects() {
				ca = append(ca, stVector(der, 2)...)
			}
		}
		if len(ca) > 65535 {
			return errors.New("CSTP TLS client CA list exceeds limit")
		}
		body := append([]byte{2, 1, 64}, stVector(schemes, 2)...)
		body = append(body, stVector(ca, 2)...)
		if e = c.flight(stMessage(13, body), &transcript); e != nil {
			return e
		}
	}
	if e = c.flight(stMessage(14, nil), &transcript); e != nil {
		return e
	}
	var certs []*x509.Certificate
	if request {
		body, e := c.expect(11, &transcript)
		if e != nil {
			return e
		}
		certs, e = ocTLS12Certificates(body)
		if e != nil {
			return e
		}
	}
	state, e := c.peerCertificates(certs)
	if e != nil {
		return e
	}
	cke, e := c.expect(16, &transcript)
	if e != nil {
		return e
	}
	q := stCursor{data: cke}
	peer := q.vector(1)
	if e = q.end(); e != nil {
		return e
	}
	pub, e := ocTLS12Curve(group).NewPublicKey(peer)
	if e != nil {
		return e
	}
	shared, e := private.ECDH(pub)
	if e != nil {
		return e
	}
	defer clear(shared)
	master := c.masterSecret(shared, transcript)
	defer clear(master)
	keys, e := ocTLS12Keys(c.state.CipherSuite, master, clientRandom, serverRandom)
	if e != nil {
		return e
	}
	if len(certs) > 0 {
		verify, e := c.message()
		if e != nil {
			return e
		}
		if verify[0] != 15 {
			return errors.New("expected CSTP TLS CertificateVerify")
		}
		q := stCursor{data: verify[4:]}
		scheme := tls.SignatureScheme(q.number(2))
		sig := q.vector(2)
		if e = q.end(); e != nil {
			return e
		}
		if e = ocTLS12Verify(certs[0].PublicKey, scheme, transcript, sig); e != nil {
			return e
		}
		if e = ocTLS12Append(&transcript, verify); e != nil {
			return e
		}
	}
	if e = c.changeRead(keys[0]); e != nil {
		return e
	}
	clientVerify, e := c.readFinished(master, &transcript, true)
	if e != nil {
		return e
	}
	if e = c.send(20, []byte{1}); e != nil {
		return e
	}
	keys[1].buffer = c.writeKey.buffer
	c.writeKey = keys[1]
	finish := c.finished(master, transcript, false)
	c.commit(master, clientRandom, serverRandom, clientVerify, bytes.Clone(finish[4:]), state)
	if e = c.flight(finish, &transcript); e != nil {
		return e
	}
	return nil
}
