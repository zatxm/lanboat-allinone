package native

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"slices"
	"strings"
	"time"
)

// Shared independently implemented TLS1.3 handshake and record primitives.
type stCursor struct {
	data []byte
	err  error
}

func (p *stCursor) take(n int) []byte {
	if p.err != nil {
		return nil
	}
	if n < 0 || n > len(p.data) {
		p.err = io.ErrUnexpectedEOF
		return nil
	}
	b := p.data[:n]
	p.data = p.data[n:]
	return b
}
func (p *stCursor) number(n int) int {
	v := 0
	for _, b := range p.take(n) {
		v = v<<8 | int(b)
	}
	return v
}
func (p *stCursor) vector(n int) []byte { return p.take(p.number(n)) }
func (p *stCursor) end() error {
	if p.err != nil {
		return p.err
	}
	if len(p.data) != 0 {
		return errors.New("unexpected TLS handshake bytes")
	}
	return nil
}
func stVector(b []byte, n int) []byte {
	out := make([]byte, n, len(b)+n)
	for i := range n {
		out[n-i-1] = byte(len(b) >> (8 * i))
	}
	return append(out, b...)
}
func stMessage(kind byte, b []byte) []byte { return append([]byte{kind}, stVector(b, 3)...) }
func stExtension(b []byte, kind uint16, data []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, kind)
	return append(b, stVector(data, 2)...)
}
func stExtensions(b []byte) (map[uint16][]byte, error) {
	p := stCursor{data: b}
	out := map[uint16][]byte{}
	for len(p.data) > 0 && p.err == nil {
		k := uint16(p.number(2))
		v := p.vector(2)
		if _, exists := out[k]; exists {
			return nil, errors.New("duplicate TLS extension")
		}
		if len(out) >= 128 {
			return nil, errors.New("too many TLS extensions")
		}
		out[k] = v
	}
	return out, p.end()
}
func stCurve(group tls.CurveID) (ecdh.Curve, error) {
	switch group {
	case tls.X25519:
		return ecdh.X25519(), nil
	case tls.CurveP256:
		return ecdh.P256(), nil
	case tls.CurveP384:
		return ecdh.P384(), nil
	case tls.CurveP521:
		return ecdh.P521(), nil
	}
	return nil, errors.New("unsupported ShadowTLS key share")
}

var stSignatures = []tls.SignatureScheme{tls.PSSWithSHA256, tls.ECDSAWithP256AndSHA256, tls.Ed25519, tls.PSSWithSHA384, tls.PSSWithSHA512, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512, tls.PKCS1WithSHA256, tls.PKCS1WithSHA384, tls.PKCS1WithSHA512}

type stClientHello struct {
	ech             *browserECH
	browser         string
	grease          [5]uint16
	random, session []byte
	serverHello     []byte
	groups          []tls.CurveID
	suites          []uint16
	key             *ecdh.PrivateKey
	fallback        *ecdh.PrivateKey
	additional      map[tls.CurveID]*ecdh.PrivateKey
	extensions      []uint16
	echGrease       []byte
	ffdhe           *browserFFDHE
	kem             *mlkem.DecapsulationKey768
	group           tls.CurveID
	config          *tls.Config
}

func newSTHello(config *tls.Config) (*stClientHello, error) {
	groups := slices.Clone(config.CurvePreferences)
	if len(groups) == 0 {
		groups = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
	}
	h := &stClientHello{random: make([]byte, 32), session: make([]byte, 32), groups: groups, suites: []uint16{0x1301, 0x1303, 0x1302}, config: config}
	rand.Read(h.random)
	rand.Read(h.session)
	return h, h.share(groups[0])
}
func (h *stClientHello) share(group tls.CurveID) error {
	if !slices.Contains(h.groups, group) {
		return errors.New("server requested an unoffered TLS group")
	}
	curveGroup := group
	h.kem = nil
	h.fallback = nil
	h.additional = nil
	h.ffdhe = nil
	if group == 256 || group == 257 {
		h.key = nil
		h.group = group
		var err error
		h.ffdhe, err = newBrowserFFDHE(group)
		return err
	}
	if group == tls.X25519MLKEM768 {
		curveGroup = tls.X25519
		var err error
		h.kem, err = mlkem.GenerateKey768()
		if err != nil {
			return err
		}
	}
	curve, e := stCurve(curveGroup)
	if e != nil {
		return e
	}
	h.key, e = curve.GenerateKey(rand.Reader)
	h.group = group
	if e == nil && h.kem != nil && h.browser != "" {
		h.fallback, e = ecdh.X25519().GenerateKey(rand.Reader)
	}
	return e
}
func (h *stClientHello) marshal(password string, cookie []byte, sign bool) ([]byte, error) {
	b, err := h.marshalPlain(password, cookie, sign)
	if err != nil || h.ech == nil {
		return b, err
	}
	return h.ech.seal(h, b)
}

func (h *stClientHello) marshalPlain(password string, cookie []byte, sign bool) ([]byte, error) {
	if h.browser != "" {
		b, err := h.browserHello(cookie)
		if err == nil && sign && password != "" {
			h.signHello(b, password)
		}
		return b, err
	}
	b := []byte{3, 3}
	b = append(b, h.random...)
	b = append(b, stVector(h.session, 1)...)
	var suites []byte
	for _, s := range h.suites {
		suites = binary.BigEndian.AppendUint16(suites, s)
	}
	b = append(b, stVector(suites, 2)...)
	b = append(b, 1, 0)
	var ext []byte
	if name := strings.TrimSuffix(h.config.ServerName, "."); name != "" && net.ParseIP(name) == nil {
		sni := append([]byte{0}, stVector([]byte(name), 2)...)
		ext = stExtension(ext, 0, stVector(sni, 2))
	}
	var groups []byte
	for _, g := range h.groups {
		groups = binary.BigEndian.AppendUint16(groups, uint16(g))
	}
	ext = stExtension(ext, 10, stVector(groups, 2))
	var signatures []byte
	for _, s := range stSignatures {
		signatures = binary.BigEndian.AppendUint16(signatures, uint16(s))
	}
	ext = stExtension(ext, 13, stVector(signatures, 2))
	ext = stExtension(ext, 43, []byte{2, 3, 4})
	key := binary.BigEndian.AppendUint16(nil, uint16(h.group))
	public := h.key.PublicKey().Bytes()
	if h.kem != nil {
		public = append(h.kem.EncapsulationKey().Bytes(), public...)
	}
	key = append(key, stVector(public, 2)...)
	if h.kem != nil && slices.Contains(h.groups, tls.X25519) {
		key = binary.BigEndian.AppendUint16(key, uint16(tls.X25519))
		key = append(key, stVector(h.key.PublicKey().Bytes(), 2)...)
	}
	ext = stExtension(ext, 51, stVector(key, 2))
	if len(h.config.NextProtos) > 0 {
		var protocols []byte
		for _, s := range h.config.NextProtos {
			if len(s) == 0 || len(s) > 255 {
				return nil, errors.New("invalid TLS ALPN")
			}
			protocols = append(protocols, stVector([]byte(s), 1)...)
		}
		ext = stExtension(ext, 16, stVector(protocols, 2))
	}
	if cookie != nil {
		ext = stExtension(ext, 44, cookie)
	}
	b = stMessage(1, append(b, stVector(ext, 2)...))
	if sign {
		h.signHello(b, password)
	}
	return b, nil
}

func (h *stClientHello) signHello(b []byte, password string) {
	clear(b[67:71])
	mac := shadowMAC(password, nil)
	mac.Write(b)
	copy(h.session[28:], shadowSum(mac, 4))
	copy(b[67:71], h.session[28:])
}

type stCipherSuite struct {
	id      uint16
	hash    crypto.Hash
	keySize int
}

func stSuite(id uint16) (stCipherSuite, error) {
	switch id {
	case 0x1301:
		return stCipherSuite{id, crypto.SHA256, 16}, nil
	case 0x1302:
		return stCipherSuite{id, crypto.SHA384, 32}, nil
	case 0x1303:
		return stCipherSuite{id, crypto.SHA256, 32}, nil
	}
	return stCipherSuite{}, errors.New("unoffered TLS1.3 cipher suite")
}
func (s stCipherSuite) newHash() hash.Hash {
	if s.hash == crypto.SHA384 {
		return sha512.New384()
	}
	return sha256.New()
}
func (s stCipherSuite) extract(salt, key []byte) []byte {
	b, e := hkdf.Extract(s.newHash, key, salt)
	if e != nil {
		panic(e)
	}
	return b
}
func (s stCipherSuite) expand(secret []byte, label string, context []byte, n int) []byte {
	info := binary.BigEndian.AppendUint16(nil, uint16(n))
	info = append(info, stVector([]byte("tls13 "+label), 1)...)
	info = append(info, stVector(context, 1)...)
	b, e := hkdf.Expand(s.newHash, secret, string(info), n)
	if e != nil {
		panic(e)
	}
	return b
}
func (s stCipherSuite) derive(secret []byte, label string, h hash.Hash) []byte {
	return s.expand(secret, label, h.Sum(nil), s.hash.Size())
}
func (s stCipherSuite) finished(secret []byte, h hash.Hash) []byte {
	mac := hmac.New(s.newHash, s.expand(secret, "finished", nil, s.hash.Size()))
	mac.Write(h.Sum(nil))
	return mac.Sum(nil)
}

type stRecordCipher struct {
	aead     cipher.AEAD
	iv       []byte
	sequence uint64
}

func (s stCipherSuite) recordCipher(secret []byte) (*stRecordCipher, error) {
	key := s.expand(secret, "key", nil, s.keySize)
	iv := s.expand(secret, "iv", nil, 12)
	var a cipher.AEAD
	var e error
	if s.id == 0x1303 {
		a, e = newChaChaAEAD(key, false)
	} else {
		var block cipher.Block
		block, e = aes.NewCipher(key)
		if e == nil {
			a, e = cipher.NewGCM(block)
		}
	}
	return &stRecordCipher{aead: a, iv: iv}, e
}
func (c *stRecordCipher) nonce() ([]byte, error) {
	if c.sequence == ^uint64(0) {
		return nil, errors.New("TLS record sequence exhausted")
	}
	nonce := bytes.Clone(c.iv)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], c.sequence)
	for i := range 8 {
		nonce[4+i] ^= b[i]
	}
	c.sequence++
	return nonce, nil
}
func (c *stRecordCipher) seal(kind byte, data []byte) ([]byte, error) {
	nonce, e := c.nonce()
	if e != nil {
		return nil, e
	}
	inner := append(bytes.Clone(data), kind)
	out := []byte{23, 3, 3}
	out = binary.BigEndian.AppendUint16(out, uint16(len(inner)+c.aead.Overhead()))
	return c.aead.Seal(out, nonce, inner, out), nil
}
func (c *stRecordCipher) open(frame []byte) (byte, []byte, error) {
	if len(frame) < 5 || len(frame) > 5+16640 || frame[0] != 23 || frame[1] != 3 || frame[2] != 3 {
		return 0, nil, errors.New("invalid encrypted TLS record")
	}
	nonce, e := c.nonce()
	if e != nil {
		return 0, nil, e
	}
	b, e := c.aead.Open(nil, nonce, frame[5:], frame[:5])
	if e != nil {
		return 0, nil, e
	}
	if len(b) > 16385 {
		return 0, nil, errors.New("TLS inner plaintext exceeds limit")
	}
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	if len(b) == 0 {
		return 0, nil, errors.New("empty TLS inner plaintext")
	}
	return b[len(b)-1], b[:len(b)-1], nil
}

type stTLSReader struct {
	conn    net.Conn
	cipher  *stRecordCipher
	pending []byte
	bytes   int
	ccs     int
	buffer  [5 + shadowRecordLimit]byte
}

func (r *stTLSReader) message() ([]byte, error) {
	for {
		if len(r.pending) >= 4 {
			n := 4 + (int(r.pending[1])<<16 | int(r.pending[2])<<8 | int(r.pending[3]))
			if n > 1<<20 {
				return nil, errors.New("TLS handshake message exceeds1MiB")
			}
			if len(r.pending) >= n {
				b := bytes.Clone(r.pending[:n])
				r.pending = r.pending[n:]
				return b, nil
			}
		}
		frame, e := shadowReadRecord(r.conn, r.buffer[:])
		if e != nil {
			return nil, e
		}
		r.bytes += len(frame)
		if r.bytes > 1<<20 {
			return nil, errors.New("TLS handshake flight exceeds1MiB")
		}
		kind, body := frame[0], frame[5:]
		if kind == 20 {
			r.ccs++
			if r.ccs > 4 || !bytes.Equal(body, []byte{1}) {
				return nil, errors.New("invalid TLS change cipher spec")
			}
			continue
		}
		if r.cipher != nil {
			kind, body, e = r.cipher.open(frame)
			if e != nil {
				return nil, e
			}
		} else if kind != 22 && kind != 21 {
			return nil, errors.New("encrypted TLS record before ServerHello")
		}
		if kind == 21 {
			return nil, fmt.Errorf("TLS handshake alert: %x", body)
		}
		if kind != 22 || len(body) == 0 {
			return nil, errors.New("unexpected TLS handshake record")
		}
		r.pending = append(r.pending, body...)
	}
}

var stRetryRandom = []byte{0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c}

func stServerParameters(msg []byte, h *stClientHello) (stCipherSuite, map[uint16][]byte, bool, error) {
	if len(msg) < 4 || msg[0] != 2 {
		return stCipherSuite{}, nil, false, errors.New("expected TLS ServerHello")
	}
	p := stCursor{data: msg[4:]}
	if p.number(2) != 0x0303 {
		return stCipherSuite{}, nil, false, errors.New("invalid TLS ServerHello version")
	}
	random := p.take(32)
	sid := p.vector(1)
	id := uint16(p.number(2))
	compression := p.number(1)
	extension := p.vector(2)
	if e := p.end(); e != nil {
		return stCipherSuite{}, nil, false, e
	}
	if compression != 0 || !hmac.Equal(sid, h.session) || !slices.Contains(h.suites, id) {
		return stCipherSuite{}, nil, false, errors.New("invalid TLS ServerHello selection")
	}
	ext, e := stExtensions(extension)
	if e != nil {
		return stCipherSuite{}, nil, false, e
	}
	retry := bytes.Equal(random, stRetryRandom)
	if !bytes.Equal(ext[43], []byte{3, 4}) || ext[51] == nil {
		return stCipherSuite{}, nil, false, errors.New("TLS1.3 key share and version required")
	}
	for k := range ext {
		if k != 43 && k != 51 && !(retry && k == 44) && !(retry && k == 0xfe0d && h.ech != nil) {
			return stCipherSuite{}, nil, false, errors.New("unsolicited TLS ServerHello extension")
		}
	}
	suite, e := stSuite(id)
	return suite, ext, retry, e
}

type stTLS13 struct {
	conn                       net.Conn
	clientApp, serverApp       *stRecordCipher
	state                      tls.ConnectionState
	suite                      stCipherSuite
	clientSecret, serverSecret []byte
	exporter                   []byte
	writeLimit                 int
}

func shadowTLS13(ctx context.Context, raw net.Conn, cfg *tls.Config, options TLSOptions, password string) (*stTLS13, error) {
	return independentTLS13(ctx, raw, cfg, options, password, nil)
}

func independentTLS13(ctx context.Context, raw net.Conn, cfg *tls.Config, options TLSOptions, password string, reality *RealityOptions) (*stTLS13, error) {
	f, err := startIndependentTLS(raw, cfg, options, password, reality)
	if err != nil {
		return nil, err
	}
	return f.tls13(ctx, options, password, reality)
}

type stClientFlight struct {
	conn   net.Conn
	h      *stClientHello
	ch, sh []byte
	reader *stTLSReader
}

func startIndependentTLS(raw net.Conn, cfg *tls.Config, options TLSOptions, password string, reality *RealityOptions) (*stClientFlight, error) {
	if cfg.ServerName == "" && !cfg.InsecureSkipVerify {
		return nil, errors.New("TLS server_name required for certificate verification")
	}
	if !options.browserEnabled() && cfg.MaxVersion != 0 && cfg.MaxVersion < tls.VersionTLS13 {
		return nil, errors.New("TLS1.3 required")
	}
	conn, cfg := clientTLSConnection(raw, cfg, options)
	h, e := newSTHello(cfg)
	if e != nil {
		return nil, e
	}
	if options.browserEnabled() {
		if e = h.initBrowser(options.UTLS.Fingerprint); e != nil {
			return nil, e
		}
	}
	if len(cfg.EncryptedClientHelloConfigList) != 0 {
		if e = h.initECH(); e != nil {
			return nil, e
		}
	}
	ch, e := h.marshal(password, nil, reality == nil)
	if e == nil && reality != nil {
		ch, e = reality.clientHello(h, ch)
		cfg = h.config
	}
	if e != nil {
		return nil, e
	}
	firstRecord := shadowFrame(22, ch)
	if options.browserEnabled() {
		firstRecord[2] = 1
	}
	if e = writeAll(conn, firstRecord); e != nil {
		return nil, e
	}
	if h.ech != nil {
		ch = h.ech.inner
	}
	reader := &stTLSReader{conn: conn}
	sh, e := reader.message()
	if e != nil {
		return nil, e
	}
	if sh[0] != 2 {
		return nil, errors.New("expected TLS ServerHello")
	}
	h.serverHello = sh
	return &stClientFlight{conn: conn, h: h, ch: ch, sh: sh, reader: reader}, nil
}

func (f *stClientFlight) tls13(ctx context.Context, options TLSOptions, password string, reality *RealityOptions) (*stTLS13, error) {
	conn, h, ch, sh, reader := f.conn, f.h, f.ch, f.sh, f.reader
	cfg := h.config
	suite, ext, retry, e := stServerParameters(sh, h)
	if e != nil {
		return nil, e
	}
	transcript := suite.newHash()
	transcript.Write(ch)
	if h.ech != nil {
		if e = h.ech.confirm(suite, transcript, sh, retry); e != nil {
			return nil, e
		}
	}
	ccsSent := false
	if retry {
		if reality != nil {
			return nil, errors.New("Reality peer requested an unsupported key-share retry")
		}
		if len(ext[51]) != 2 {
			return nil, errors.New("invalid TLS retry key share")
		}
		group := tls.CurveID(binary.BigEndian.Uint16(ext[51]))
		if h.hasShare(group) {
			return nil, errors.New("TLS retry requested existing key share")
		}
		if e = h.share(group); e != nil {
			return nil, e
		}
		if cookie, ok := ext[44]; ok {
			p := stCursor{data: cookie}
			if len(p.vector(2)) == 0 || p.end() != nil {
				return nil, errors.New("invalid TLS retry cookie")
			}
		}
		firstHash := transcript.Sum(nil)
		transcript.Reset()
		transcript.Write(stMessage(254, firstHash))
		transcript.Write(sh)
		ch, e = h.marshal(password, ext[44], false)
		if e != nil {
			return nil, e
		}
		if e = writeAll(conn, shadowFrame(20, []byte{1})); e != nil {
			return nil, e
		}
		ccsSent = true
		if e = writeAll(conn, shadowFrame(22, ch)); e != nil {
			return nil, e
		}
		if h.ech != nil {
			ch = h.ech.inner
		}
		transcript.Write(ch)
		sh, e = reader.message()
		if e != nil {
			return nil, e
		}
		if sh[0] != 2 {
			return nil, errors.New("expected TLS ServerHello after retry")
		}
		next, nextExt, again, e := stServerParameters(sh, h)
		if e != nil {
			return nil, e
		}
		if again || next.id != suite.id {
			return nil, errors.New("invalid TLS retry selection")
		}
		ext = nextExt
		if h.ech != nil {
			if e = h.ech.confirm(suite, transcript, sh, false); e != nil {
				return nil, e
			}
		}
	}
	transcript.Write(sh)
	share := stCursor{data: ext[51]}
	group := tls.CurveID(share.number(2))
	public := share.vector(2)
	if e = share.end(); e != nil || !h.hasShare(group) {
		return nil, errors.New("invalid TLS server key share")
	}
	shared, e := h.sharedSecret(group, public)
	if e != nil {
		return nil, e
	}
	defer clear(shared)
	zero := make([]byte, suite.hash.Size())
	empty := suite.newHash()
	early := suite.extract(zero, zero)
	handshake := suite.extract(suite.derive(early, "derived", empty), shared)
	defer clear(handshake)
	clientSecret := suite.derive(handshake, "c hs traffic", transcript)
	serverSecret := suite.derive(handshake, "s hs traffic", transcript)
	defer clear(clientSecret)
	defer clear(serverSecret)
	clientCipher, e := suite.recordCipher(clientSecret)
	if e != nil {
		return nil, e
	}
	reader.cipher, e = suite.recordCipher(serverSecret)
	if e != nil {
		return nil, e
	}
	result := &stTLS13{conn: conn, state: tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: suite.id, ServerName: cfg.ServerName}}
	result.state.ECHAccepted = h.ech != nil
	var certificateRequest *tls.CertificateRequestInfo
	var requestContext []byte
	var certificateKey any
	var delegatedScheme tls.SignatureScheme
	var clientALPS uint16
	stage := 0
	for {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		msg, e := reader.message()
		if e != nil {
			return nil, e
		}

		switch msg[0] {
		case 8:
			if stage != 0 {
				return nil, errors.New("unexpected TLS EncryptedExtensions")
			}
			p := stCursor{data: msg[4:]}
			extensions := p.vector(2)
			if e = p.end(); e != nil {
				return nil, e
			}
			values, e := stExtensions(extensions)
			if e != nil {
				return nil, e
			}
			for k, v := range values {
				switch k {
				case 0:
					if cfg.ServerName == "" || len(v) != 0 {
						return nil, errors.New("unsolicited TLS server_name extension")
					}
				case 16:
					p := stCursor{data: v}
					list := stCursor{data: p.vector(2)}
					protocol := string(list.vector(1))
					if p.end() != nil || list.end() != nil || !slices.Contains(cfg.NextProtos, protocol) {
						return nil, errors.New("invalid TLS ALPN selection")
					}
					result.state.NegotiatedProtocol = protocol
					result.state.NegotiatedProtocolIsMutual = true
				case 10:
				case 28:
					if !strings.HasPrefix(h.browser, "firefox") && h.browser != "random" {
						return nil, errors.New("invalid TLS record size limit")
					}
					result.writeLimit, e = browserRecordLimit(v, true)
					if e != nil {
						return nil, e
					}
				case 17513, 17613:
					if !slices.Contains(h.extensions, k) || clientALPS != 0 || len(v)%6 != 0 {
						return nil, errors.New("invalid ALPS settings")
					}
					for off := 0; off < len(v); off += 6 {
						id, value := binary.BigEndian.Uint16(v[off:]), binary.BigEndian.Uint32(v[off+2:])
						if id == 2 || id == 4 && value > 1<<31-1 || id == 5 && (value < 16384 || value > 16777215) || id == 8 && value > 1 {
							return nil, errors.New("invalid HTTP2 ALPS setting")
						}
					}
					clientALPS = k
				case 51764:
					if !slices.Contains(h.extensions, k) {
						return nil, errors.New("unsolicited trust anchors")
					}
					p := stCursor{data: v}
					list := stCursor{data: p.vector(2)}
					if p.end() != nil || len(list.data) == 0 {
						return nil, errors.New("invalid trust anchors")
					}
					for len(list.data) != 0 && list.err == nil {
						if len(list.vector(1)) == 0 {
							return nil, errors.New("empty trust anchor identifier")
						}
					}
					if list.end() != nil {
						return nil, errors.New("invalid trust anchors")
					}
				default:
					return nil, errors.New("unsupported TLS encrypted extension")
				}
			}
			if clientALPS != 0 && result.state.NegotiatedProtocol != "h2" {
				return nil, errors.New("ALPS without matching ALPN")
			}
			stage = 1
		case 13:
			if stage != 1 || certificateRequest != nil {
				return nil, errors.New("unexpected TLS CertificateRequest")
			}
			requestContext, certificateRequest, e = stCertificateRequest(msg[4:])
			if e != nil {
				return nil, e
			}
		case 11, 25:
			if stage != 1 {
				return nil, errors.New("unexpected TLS Certificate")
			}
			body := msg[4:]
			if msg[0] == 25 {
				if !options.browserEnabled() || len(msg) < 6 || !browserCompressionOffered(h.browser, binary.BigEndian.Uint16(msg[4:])) {
					return nil, errors.New("unsolicited compressed TLS certificate")
				}
				body, e = browserCertificate(msg)
				if e != nil {
					return nil, e
				}
			}
			result.state.PeerCertificates, e = stCertificates(body, options.browserEnabled())
			if e != nil {
				return nil, e
			}
			if e = stVerifyCertificates(cfg, &result.state); e != nil {
				return nil, e
			}
			certificateKey = result.state.PeerCertificates[0].PublicKey
			if options.browserEnabled() {
				now := time.Now()
				if cfg.Time != nil {
					now = cfg.Time()
				}
				certificateKey, delegatedScheme, e = browserDelegatedKey(body, result.state.PeerCertificates[0], h.browser, now)
				if e != nil {
					return nil, e
				}
			}
			stage = 2
		case 15:
			if stage != 2 {
				return nil, errors.New("unexpected TLS CertificateVerify")
			}
			if !options.browserEnabled() && (len(msg) < 6 || !slices.Contains(stSignatures, tls.SignatureScheme(binary.BigEndian.Uint16(msg[4:])))) {
				return nil, errors.New("server selected an unoffered TLS signature scheme")
			}
			// Reality authenticates its Ed25519 certificate with the shared secret.
			if options.browserEnabled() && !h.browserSignature(msg[4:]) && !(reality != nil && len(msg) >= 6 && binary.BigEndian.Uint16(msg[4:]) == uint16(tls.Ed25519)) {
				return nil, errors.New("server selected an unoffered browser signature scheme")
			}
			if delegatedScheme != 0 && (len(msg) < 6 || binary.BigEndian.Uint16(msg[4:]) != uint16(delegatedScheme)) {
				return nil, errors.New("delegated CertificateVerify scheme mismatch")
			}
			if e = stVerifyCertificateSignature(msg[4:], certificateKey, transcript); e != nil {
				return nil, e
			}
			stage = 3
		case 20:
			if stage != 3 || subtle.ConstantTimeCompare(msg[4:], suite.finished(serverSecret, transcript)) != 1 {
				return nil, errors.New("TLS server Finished verification failed")
			}
			transcript.Write(msg)
			if len(reader.pending) != 0 {
				return nil, errors.New("unexpected handshake data after TLS Finished")
			}
			master := suite.extract(suite.derive(handshake, "derived", empty), zero)
			defer clear(master)
			result.suite = suite
			result.exporter = suite.derive(master, "exp master", transcript)
			result.clientSecret = suite.derive(master, "c ap traffic", transcript)
			result.serverSecret = suite.derive(master, "s ap traffic", transcript)
			result.clientApp, e = suite.recordCipher(result.clientSecret)
			if e != nil {
				return nil, e
			}
			result.serverApp, e = suite.recordCipher(result.serverSecret)
			if e != nil {
				return nil, e
			}
			if !ccsSent {
				if e = writeAll(conn, shadowFrame(20, []byte{1})); e != nil {
					return nil, e
				}
			}
			send := func(kind byte, body []byte) error {
				message := stMessage(kind, body)
				for rest := message; len(rest) > 0; {
					n := min(len(rest), 16384)
					if result.writeLimit != 0 {
						n = min(n, result.writeLimit)
					}
					record, e := clientCipher.seal(22, rest[:n])
					if e != nil {
						return e
					}
					if e = writeAll(conn, record); e != nil {
						return e
					}
					rest = rest[n:]
				}
				transcript.Write(message)
				return nil
			}

			if clientALPS != 0 {
				if e = send(8, stVector(stExtension(nil, clientALPS, nil), 2)); e != nil {
					return nil, e
				}
			}
			if certificateRequest != nil {
				if e = stSendClientCertificate(cfg, certificateRequest, requestContext, transcript, send); e != nil {
					return nil, e
				}
			}
			if e = send(20, suite.finished(clientSecret, transcript)); e != nil {
				return nil, e
			}
			result.state.HandshakeComplete = true
			return result, nil
		default:
			return nil, fmt.Errorf("unexpected TLS handshake type%d", msg[0])
		}
		transcript.Write(msg)
	}
}
func (h *stClientHello) sharedSecret(group tls.CurveID, public []byte) ([]byte, error) {
	if h.ffdhe != nil {
		return h.ffdhe.shared(public)
	}
	var kemSecret []byte
	var e error
	curveGroup := group
	if group == tls.X25519MLKEM768 {
		if len(public) != mlkem.CiphertextSize768+32 {
			return nil, errors.New("invalid hybrid TLS server key share")
		}
		kemSecret, e = h.kem.Decapsulate(public[:mlkem.CiphertextSize768])
		if e != nil {
			return nil, e
		}
		public = public[mlkem.CiphertextSize768:]
		curveGroup = tls.X25519
	}
	curve, _ := stCurve(curveGroup)
	peer, e := curve.NewPublicKey(public)
	if e != nil {
		return nil, e
	}
	private := h.key
	if k := h.additional[group]; k != nil {
		private = k
	}
	if group == tls.X25519 && h.fallback != nil {
		private = h.fallback
	}
	shared, e := private.ECDH(peer)
	if e != nil {
		return nil, e
	}
	return append(kemSecret, shared...), nil
}

func (c *stTLS13) muddle(serverName string) {
	c.conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	var random [32]byte
	rand.Read(random[:])
	request := []byte("GET /" + hex.EncodeToString(random[:]) + " HTTP/1.1\r\nHost: " + serverName + "\r\nConnection: close\r\n\r\n")
	if c.state.NegotiatedProtocol == "h2" {
		stringField := func(b []byte, s string) []byte { return append(h3Int(b, 7, 0, uint64(len(s))), s...) }
		headers := []byte{0x82, 0x87, 0x04}
		headers = stringField(headers, "/"+hex.EncodeToString(random[:]))
		headers = append(headers, 1)
		headers = stringField(headers, serverName)
		request = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
		request = append(request, 0, 0, 0, 4, 0, 0, 0, 0, 0)
		request = append(request, byte(len(headers)>>16), byte(len(headers)>>8), byte(len(headers)), 1, 5, 0, 0, 0, 1)
		request = append(request, headers...)
	}
	b, e := c.clientApp.seal(23, request)
	if e == nil {
		e = writeAll(c.conn, b)
	}
	if e == nil {
		var buffer [5 + shadowRecordLimit]byte
		var pending []byte
		for range 16 {
			frame, e := shadowReadRecord(c.conn, buffer[:])
			if e != nil {
				break
			}
			kind, data, e := c.serverApp.open(frame)
			if e != nil || kind == 21 {
				break
			}
			if kind != 23 {
				continue
			}
			if c.state.NegotiatedProtocol != "h2" {
				break
			}
			pending = append(pending, data...)
			if len(pending) > 65536 {
				break
			}
			response := false
			for len(pending) >= 9 {
				n := int(pending[0])<<16 | int(pending[1])<<8 | int(pending[2])
				if n > len(pending)-9 {
					break
				}
				if pending[3] == 1 && binary.BigEndian.Uint32(pending[5:9]) == 1 {
					response = true
				}
				if pending[3] == 4 && pending[4]&1 == 0 {
					ack, err := c.clientApp.seal(23, []byte{0, 0, 0, 4, 1, 0, 0, 0, 0})
					if err == nil {
						_ = writeAll(c.conn, ack)
					}
				}
				pending = pending[n+9:]
			}
			if response {
				break
			}
		}
	}
	if b, e = c.clientApp.seal(21, []byte{1, 0}); e == nil {
		_ = writeAll(c.conn, b)
	}
}
func stVerifyCertificates(cfg *tls.Config, state *tls.ConnectionState) error {
	raw := make([][]byte, len(state.PeerCertificates))
	for i, c := range state.PeerCertificates {
		raw[i] = c.Raw
	}
	if !cfg.InsecureSkipVerify {
		pool := x509.NewCertPool()
		for _, c := range state.PeerCertificates[1:] {
			pool.AddCert(c)
		}
		now := time.Now()
		if cfg.Time != nil {
			now = cfg.Time()
		}
		chains, e := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: cfg.RootCAs, Intermediates: pool, DNSName: cfg.ServerName, CurrentTime: now})
		if e != nil {
			return e
		}
		state.VerifiedChains = chains
	}
	if cfg.VerifyPeerCertificate != nil {
		if e := cfg.VerifyPeerCertificate(raw, state.VerifiedChains); e != nil {
			return e
		}
	}
	if cfg.VerifyConnection != nil {
		return cfg.VerifyConnection(*state)
	}
	return nil
}
