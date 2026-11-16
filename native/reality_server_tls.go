package native

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"slices"
)

func realityServerTLS(ctx context.Context, raw net.Conn, cfg *tls.Config, hello, auth []byte, options *RealityOptions, cover *realityCover) (*realityConn, error) {

	h, ext, err := realityClientParameters(hello)
	if err != nil {
		return nil, err
	}
	suite := cover.suite
	q := stCursor{data: ext[51]}
	shares := stCursor{data: q.vector(2)}
	var hybrid, classic []byte
	for len(shares.data) > 0 && shares.err == nil {
		group := tls.CurveID(shares.number(2))
		key := shares.vector(2)
		if group == tls.X25519MLKEM768 {
			hybrid = key
		}
		if group == tls.X25519 {
			classic = key
		}
	}
	if q.end() != nil || shares.end() != nil {
		return nil, errors.New("invalid Reality key share list")
	}
	group, peer := cover.group, classic
	if group == tls.X25519MLKEM768 {
		group, peer = tls.X25519MLKEM768, hybrid[mlkem.EncapsulationKeySize768:]
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	public, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return nil, err
	}
	serverKey := private.PublicKey().Bytes()
	if group == tls.X25519MLKEM768 {
		kem, err := mlkem.NewEncapsulationKey768(hybrid[:mlkem.EncapsulationKeySize768])
		if err != nil {
			return nil, err
		}
		secret, ciphertext := kem.Encapsulate()
		shared = append(secret, shared...)
		serverKey = append(ciphertext, serverKey...)
	}
	var alpn string
	if len(cfg.NextProtos) > 0 {
		a := stCursor{data: ext[16]}
		list := stCursor{data: a.vector(2)}
		var offered []string
		for len(list.data) > 0 && list.err == nil {
			offered = append(offered, string(list.vector(1)))
		}
		if a.end() != nil || list.end() != nil {
			return nil, errors.New("invalid Reality ALPN offer")
		}
		for _, protocol := range cfg.NextProtos {
			if slices.Contains(offered, protocol) {
				alpn = protocol
				break
			}
		}
		if alpn == "" {
			return nil, errors.New("Reality ALPN does not overlap")
		}
	}

	serverHello := bytes.Clone(cover.hello)
	_, selection, _, err := stServerParameters(serverHello, h)
	if err != nil {
		return nil, err
	}
	copy(selection[51][4:], serverKey)
	transcript := suite.newHash()
	transcript.Write(hello)
	transcript.Write(serverHello)
	zero := make([]byte, suite.hash.Size())
	empty := suite.newHash()
	early := suite.extract(zero, zero)
	handshake := suite.extract(suite.derive(early, "derived", empty), shared)
	clear(shared)
	clientSecret := suite.derive(handshake, "c hs traffic", transcript)
	serverSecret := suite.derive(handshake, "s hs traffic", transcript)
	readerCipher, err := suite.recordCipher(clientSecret)
	if err != nil {
		return nil, err
	}
	writerCipher, err := suite.recordCipher(serverSecret)
	if err != nil {
		return nil, err
	}
	certificate, err := realityCertificate(auth, hello, serverHello, options)
	if err != nil {
		return nil, err
	}
	var messages [][]byte
	add := func(kind byte, body []byte) {
		message := stMessage(kind, body)
		messages = append(messages, message)
		transcript.Write(message)
	}
	var encryptedExt []byte
	if alpn != "" {
		encryptedExt = stExtension(nil, 16, stVector(stVector([]byte(alpn), 1), 2))
	}
	add(8, stVector(encryptedExt, 2))
	entry := append(stVector(certificate.Certificate[0], 3), 0, 0)
	add(11, append([]byte{0}, stVector(entry, 3)...))
	signature := ed25519.Sign(certificate.PrivateKey.(ed25519.PrivateKey), stSignatureInput(true, transcript))
	body := binary.BigEndian.AppendUint16(nil, uint16(tls.Ed25519))
	add(15, append(body, stVector(signature, 2)...))
	add(20, suite.finished(serverSecret, transcript))
	master := suite.extract(suite.derive(handshake, "derived", empty), zero)
	defer clear(master)
	clientAppSecret := suite.derive(master, "c ap traffic", transcript)
	serverAppSecret := suite.derive(master, "s ap traffic", transcript)

	flight, err := cover.flight(writerCipher, messages)
	if err != nil {
		return nil, err
	}
	if err = cover.writeHello(raw, serverHello); err != nil {
		return nil, err
	}
	if err = writeAll(raw, flight); err != nil {
		return nil, err
	}
	reader := &stTLSReader{conn: raw, cipher: readerCipher}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	finished, err := reader.message()
	if err != nil {
		return nil, err
	}
	if len(finished) != 4+suite.hash.Size() || finished[0] != 20 || !hmac.Equal(finished[4:], suite.finished(clientSecret, transcript)) || len(reader.pending) != 0 {
		return nil, errors.New("Reality client Finished authentication failed")
	}
	result := &stTLS13{conn: raw, suite: suite, clientSecret: serverAppSecret, serverSecret: clientAppSecret, state: tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, CipherSuite: suite.id, ServerName: cfg.ServerName, NegotiatedProtocol: alpn, NegotiatedProtocolIsMutual: alpn != ""}}
	result.exporter = suite.derive(master, "exp master", transcript)
	result.clientApp, err = suite.recordCipher(serverAppSecret)
	if err != nil {
		return nil, err
	}
	result.serverApp, err = suite.recordCipher(clientAppSecret)
	if err != nil {
		return nil, err
	}
	return &realityConn{Conn: raw, tls: result, server: true}, nil
}
