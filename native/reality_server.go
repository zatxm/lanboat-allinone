package native

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"time"
)

func realityCertificate(auth, clientHello, serverHello []byte, options *RealityOptions) (tls.Certificate, error) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Reality authenticates the public key and transcript itself; no ordinary
	// PKI identity is used. A compact certificate leaves room for cover padding.
	template := &x509.Certificate{SerialNumber: big.NewInt(0)}
	if options.MLDSA65Seed != "" {
		signing, err := realityMLDSAPrivate(options.MLDSA65Seed)
		if err != nil {
			return tls.Certificate{}, err
		}
		mac := hmac.New(sha512.New, auth)
		mac.Write(public)
		mac.Write(clientHello)
		mac.Write(serverHello)
		signature, err := signing.SignDeterministic(mac.Sum(nil), nil)
		if err != nil {
			return tls.Certificate{}, err
		}
		template.ExtraExtensions = []pkix.Extension{{Id: realityMLDSAOID, Value: signature}}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(leaf.Signature) != 64 || !bytes.HasSuffix(der, leaf.Signature) {
		return tls.Certificate{}, errors.New("unexpected Reality certificate encoding")
	}
	mac := hmac.New(sha512.New, auth)
	mac.Write(public)
	copy(der[len(der)-64:], mac.Sum(nil))
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func (r *Runtime) realityAccept(in Inbound, raw net.Conn, cfg *tls.Config) (net.Conn, error) {
	wire, hello, err := shadowHello(raw)
	if err != nil {
		return nil, err
	}
	name, _, ok := clientHelloSNI(hello)
	var auth []byte
	if ok && echDomain(name) && (in.TLS.ServerName == "" || strings.EqualFold(name, in.TLS.ServerName)) {
		auth, err = in.TLS.Reality.authenticate(hello, time.Now())
	} else {
		err = errors.New("Reality server name mismatch")
	}
	if err == nil {
		digest := sha256.Sum256(hello)
		err = r.replay.claimFor("reality:"+in.Tag+string(digest[:]), 30*time.Minute)
	}

	defer clear(auth)
	in.TLS.ServerName = name
	if cfg.ServerName != name {
		cfg = cfg.Clone()
		cfg.ServerName = name
	}
	remote, e := r.shadowHandshakeBackend(*in.TLS.Reality.Handshake)
	if e != nil {
		return nil, e
	}
	defer remote.Close()
	stop := context.AfterFunc(r.ctx, func() { remote.Close() })
	defer stop()
	if e = writeAll(remote, wire); e != nil {
		return nil, e
	}
	fallback := func(saved []byte) (net.Conn, error) {
		if e := writeAll(raw, saved); e != nil {
			return nil, e
		}
		raw.SetDeadline(time.Time{})
		remote.SetDeadline(time.Time{})
		r.relay(raw, remote)
		return nil, nil
	}
	if err != nil {
		return fallback(nil)
	}
	cover, e := readRealityCover(remote, hello)
	if e != nil {
		return fallback(cover.wire)
	}
	post, e := r.realityPostSizes(in, hello)
	if e != nil {
		return nil, e
	}
	securedRaw := raw
	if hasVision(in) {
		securedRaw = &visionRecordConn{Conn: raw}
	}
	secured, e := realityServerTLS(r.ctx, securedRaw, cfg, hello, auth, in.TLS.Reality, cover)
	if errors.Is(e, errRealityCoverShape) {
		return fallback(cover.wire)
	}
	if e != nil {
		return nil, e
	}
	if e = secured.writeCoverPost(post); e != nil {
		return nil, e
	}
	if in.TLS.KernelTX || in.TLS.KernelRX {
		secured.kernel, e = installKernelTLS(raw, secured.tls, in.TLS.KernelTX, in.TLS.KernelRX)
		if e != nil {
			return nil, e
		}
	}
	return secured, nil

}

func validateRealityTransport(kind string, t TLSOptions, tr Transport) error {
	if !t.realityEnabled() {
		return nil
	}
	switch kind {
	case "mixed", "socks", "http", "shadowsocks", "shadowsocksr", "vless", "vmess", "trojan", "anytls", "relay", "snell", "brook":
	default:
		return errors.New("Reality requires a TCP stream proxy")
	}
	switch tr.Type {
	case "", "ws", "httpupgrade", "http", "grpc", "xhttp":
	default:
		return errors.New("Reality requires a TCP stream transport")
	}
	if tr.xhttp3(t) {
		return errors.New("Reality does not use QUIC/HTTP3")
	}
	return nil
}
