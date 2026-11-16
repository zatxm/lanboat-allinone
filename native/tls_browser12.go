package native

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"slices"
)

func (f *stClientFlight) tls12() (*ocTLS12, error) {
	h, cfg, sh, reader := f.h, f.h.config, f.sh, f.reader
	if cfg.MinVersion > tls.VersionTLS12 || reader.ccs != 0 {
		return nil, errors.New("browser peer selected a forbidden TLS version or early CCS")
	}
	p := stCursor{data: sh[4:]}
	if p.number(2) != tls.VersionTLS12 {
		return nil, errors.New("browser requires TLS1.2 or TLS1.3")
	}
	serverRandom := p.take(32)
	sid := p.vector(1)
	suite := uint16(p.number(2))
	compression := p.number(1)
	extensions := p.vector(2)
	spec, known := browserTLS12Cipher(suite)
	if p.end() != nil || len(sid) > 32 || compression != 0 || !slices.Contains(h.suites, suite) || !known {
		return nil, errors.New("browser TLS1.2 requires an offered supported suite")
	}
	if cfg.MaxVersion != tls.VersionTLS12 && (bytes.Equal(serverRandom[24:], []byte("DOWNGRD\x01")) || bytes.Equal(serverRandom[24:], []byte("DOWNGRD\x00"))) {
		return nil, errors.New("browser TLS downgrade sentinel detected")
	}
	ext, err := stExtensions(extensions)
	if err != nil {
		return nil, err
	}
	if ems, ok := ext[23]; !ok || len(ems) != 0 || !bytes.Equal(ext[0xff01], []byte{0}) {
		return nil, errors.New("browser TLS1.2 requires EMS and secure renegotiation")
	}
	c := &ocTLS12{Conn: f.conn, config: cfg, state: tls.ConnectionState{Version: tls.VersionTLS12, CipherSuite: suite, ServerName: cfg.ServerName}, secure: true, ems: true}
	_, offered, err := ocTLS12ParseHello(f.ch[4:], true)
	if err != nil {
		return nil, err
	}
	for id, value := range ext {
		if _, ok := offered[id]; !ok {
			return nil, errors.New("unoffered browser TLS1.2 ServerHello extension")
		}
		switch id {
		case 0:
			if cfg.ServerName == "" || len(value) != 0 {
				return nil, errors.New("invalid browser TLS server_name acknowledgement")
			}
		case 11:
			points := stCursor{data: value}
			if !bytes.Contains(points.vector(1), []byte{0}) || points.end() != nil {
				return nil, errors.New("browser TLS requires uncompressed EC points")
			}
		case 16:
			p := stCursor{data: value}
			list := stCursor{data: p.vector(2)}
			protocol := string(list.vector(1))
			if p.end() != nil || list.end() != nil || !slices.Contains(cfg.NextProtos, protocol) {
				return nil, errors.New("invalid browser TLS ALPN selection")
			}
			c.state.NegotiatedProtocol, c.state.NegotiatedProtocolIsMutual = protocol, true
		case 5:
			if len(value) != 0 {
				return nil, errors.New("invalid browser TLS status acknowledgement")
			}
		case 18:
			p := stCursor{data: value}
			list := stCursor{data: p.vector(2)}
			if p.end() != nil || len(list.data) == 0 {
				return nil, errors.New("invalid browser TLS SCT list")
			}
			for len(list.data) > 0 && list.err == nil {
				sct := list.vector(2)
				if len(sct) == 0 {
					return nil, errors.New("empty browser TLS SCT")
				}
				c.state.SignedCertificateTimestamps = append(c.state.SignedCertificateTimestamps, bytes.Clone(sct))
			}
			if list.end() != nil {
				return nil, errors.New("invalid browser TLS SCT list")
			}
		case 23, 0xff01:
		case 35:
			if len(value) != 0 {
				return nil, errors.New("invalid TLS session ticket acknowledgement")
			}
		case 28:
			c.writeLimit, err = browserRecordLimit(value, false)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("unsolicited browser TLS1.2 ServerHello extension")
		}
	}
	transcript := append(bytes.Clone(f.ch), sh...)
	read := func() ([]byte, error) {
		m, err := reader.message()
		if err != nil {
			return nil, err
		}
		if reader.ccs != 0 {
			return nil, errors.New("early browser TLS1.2 CCS")
		}
		return m, ocTLS12Append(&transcript, m)
	}
	cert, err := read()
	if err != nil {
		return nil, err
	}
	if cert[0] != 11 {
		return nil, errors.New("expected browser TLS1.2 certificate")
	}
	c.state.PeerCertificates, err = ocTLS12Certificates(cert[4:])
	if err != nil || len(c.state.PeerCertificates) == 0 {
		return nil, errors.New("invalid browser TLS1.2 certificate chain")
	}
	switch c.state.PeerCertificates[0].PublicKey.(type) {
	case *rsa.PublicKey:
		if !spec.rsaCertificate {
			return nil, errors.New("browser TLS certificate does not match ECDSA suite")
		}
	case *ecdsa.PublicKey:
		if spec.rsaCertificate {
			return nil, errors.New("browser TLS certificate does not match RSA suite")
		}
	default:
		return nil, errors.New("browser TLS1.2 requires an RSA or ECDSA certificate")
	}
	if _, ok := ext[5]; ok {
		status, err := read()
		if err != nil {
			return nil, err
		}
		p := stCursor{data: status[4:]}
		kind := p.number(1)
		response := p.vector(3)
		if status[0] != 22 || kind != 1 || len(response) == 0 || p.end() != nil {
			return nil, errors.New("invalid browser TLS1.2 CertificateStatus")
		}
		c.state.OCSPResponse = bytes.Clone(response)
	}
	if err = stVerifyCertificates(cfg, &c.state); err != nil {
		return nil, err
	}
	next, err := read()
	if err != nil {
		return nil, err
	}
	var shared, exchange []byte
	defer func() { clear(shared) }()
	if spec.rsaKeyExchange {
		shared, exchange, err = browserTLS12RSAExchange(c.state.PeerCertificates[0])
		if err != nil {
			return nil, err
		}
	} else {
		ske := next
		q := stCursor{data: ske[4:]}
		curveType, group := q.number(1), uint16(q.number(2))
		public := q.vector(1)
		params := ske[4 : len(ske)-len(q.data)]
		scheme, signature := tls.SignatureScheme(q.number(2)), q.vector(2)
		if ske[0] != 12 || curveType != 3 || q.end() != nil || !slices.Contains(h.groups, tls.CurveID(group)) || !slices.Contains(browserSignatures(h.browser), uint16(scheme)) {
			return nil, errors.New("invalid browser TLS1.2 ServerKeyExchange selection")
		}
		curve := ocTLS12Curve(group)
		if curve == nil {
			return nil, errors.New("unsupported browser TLS1.2 ECDHE group")
		}
		input := append(append(bytes.Clone(h.random), serverRandom...), params...)
		if err = browserTLS12Verify(c.state.PeerCertificates[0].PublicKey, scheme, input, signature); err != nil {
			return nil, err
		}
		private, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		peer, err := curve.NewPublicKey(public)
		if err != nil {
			return nil, err
		}
		shared, err = private.ECDH(peer)
		if err != nil {
			return nil, err
		}
		exchange = stVector(private.PublicKey().Bytes(), 1)
		next, err = read()
		if err != nil {
			return nil, err
		}
	}
	var request *tls.CertificateRequestInfo
	var clientCert *tls.Certificate
	if next[0] == 13 {
		request, err = ocTLS12Request(next[4:])
		if err != nil {
			return nil, err
		}
		types := stCursor{data: next[4:]}
		allowed := types.vector(1)
		if cfg.GetClientCertificate != nil {
			clientCert, err = cfg.GetClientCertificate(request)
			if err != nil {
				return nil, err
			}
			if clientCert != nil && len(clientCert.Certificate) != 0 && !browserTLS12ClientMatch(clientCert, request, allowed) {
				return nil, errors.New("browser TLS client certificate does not match request")
			}
		} else {
			for i := range cfg.Certificates {
				if browserTLS12ClientMatch(&cfg.Certificates[i], request, allowed) {
					clientCert = &cfg.Certificates[i]
					break
				}
			}
		}
		next, err = read()
		if err != nil {
			return nil, err
		}
	}
	if !bytes.Equal(next, stMessage(14, nil)) || len(reader.pending) != 0 {
		return nil, errors.New("expected browser TLS1.2 ServerHelloDone")
	}
	send := func(message []byte) error {
		if err := ocTLS12Append(&transcript, message); err != nil {
			return err
		}
		for len(message) > 0 {
			n := min(len(message), 16384)
			if err := writeAll(f.conn, shadowFrame(22, message[:n])); err != nil {
				return err
			}
			message = message[n:]
		}
		return nil
	}
	if request != nil {
		if err = send(ocTLS12Certificate(clientCert)); err != nil {
			return nil, err
		}
	}
	if err = send(stMessage(16, exchange)); err != nil {
		return nil, err
	}
	master := c.masterSecret(shared, transcript)
	defer clear(master)
	keys, err := browserTLS12Keys(suite, master, h.random, serverRandom)
	if err != nil {
		return nil, err
	}
	if clientCert != nil && len(clientCert.Certificate) > 0 {
		signature, err := browserTLS12Sign(clientCert, request.SignatureSchemes, transcript)
		if err != nil {
			return nil, err
		}
		if err = send(stMessage(15, signature)); err != nil {
			return nil, err
		}
	}
	if err = writeAll(f.conn, shadowFrame(20, []byte{1})); err != nil {
		return nil, err
	}
	c.writeKey, c.readKey = keys[0], keys[1]
	finish := c.finished(master, transcript, true)
	if err = c.flight(finish, &transcript); err != nil {
		return nil, err
	}
	if _, ok := ext[35]; ok {
		ticket, err := reader.message()
		if err != nil {
			return nil, err
		}
		p := stCursor{data: ticket[4:]}
		p.take(4)
		p.vector(2)
		if ticket[0] != 4 || p.end() != nil || reader.ccs != 0 || len(reader.pending) != 0 {
			return nil, errors.New("invalid TLS1.2 session ticket")
		}
		if err = ocTLS12Append(&transcript, ticket); err != nil {
			return nil, err
		}
	}
	frame, err := shadowReadRecord(f.conn, reader.buffer[:])
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(frame, shadowFrame(20, []byte{1})) {
		return nil, errors.New("expected browser TLS1.2 server CCS")
	}
	serverVerify, err := c.readFinished(master, &transcript, false)
	if err != nil {
		return nil, err
	}
	c.state.HandshakeComplete = true
	c.clientHello, c.serverHello = bytes.Clone(f.ch[4:]), bytes.Clone(sh[4:])
	c.certificate = clientCert
	c.commit(master, h.random, serverRandom, bytes.Clone(finish[4:]), serverVerify, c.state)
	return c, nil
}
