package native

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// UTLS names the compatible configuration field, not a linked TLS library.
type BrowserTLSOptions struct {
	Enabled     bool   `json:"enabled,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

func (o TLSOptions) browserEnabled() bool { return o.UTLS != nil && o.UTLS.Enabled }

func (o TLSOptions) validateBrowser(server bool) error {
	if !o.browserEnabled() {
		return nil
	}
	if server || !o.Enabled {
		return errors.New("browser fingerprint requires outbound TLS")
	}
	switch strings.ToLower(o.UTLS.Fingerprint) {
	case "safari15_3", "safari15_5", "safari16_0", "safari26_3":
	case "chrome", "chrome100", "chrome110", "chrome120", "chrome140", "chrome150", "firefox", "firefox109", "firefox117", "firefox120", "firefox148", "random":
	default:
		return fmt.Errorf("browser fingerprint %q has no independently verified profile", o.UTLS.Fingerprint)
	}
	if len(o.CipherSuites)+len(o.CurvePreferences) != 0 {
		return errors.New("browser profile cannot be combined with cipher/curve overrides")
	}
	if o.MinVersion != "" && o.MinVersion != "1.2" && o.MinVersion != "1.3" || o.MaxVersion != "" && o.MaxVersion != "1.2" && o.MaxVersion != "1.3" {
		return errors.New("independent browser handshake requires TLS1.2 or TLS1.3")
	}
	return nil
}

func dialBrowserTLS(ctx context.Context, raw net.Conn, cfg *tls.Config, o TLSOptions, password string) (tlsSession, error) {
	config := cloneTLSConfig(cfg)
	// Match the browser's default offer unless the application supplies ALPN.
	if len(config.NextProtos) == 0 {
		config.NextProtos = []string{"h2", "http/1.1"}
	}
	f, err := startIndependentTLS(raw, config, o, password, nil)
	if err != nil {
		return nil, err
	}
	_, ext, err := ocTLS12ParseHello(f.sh[4:], false)
	if err != nil {
		return nil, err
	}
	if _, ok := ext[43]; !ok {
		return f.tls12()
	}
	if config.MaxVersion != 0 && config.MaxVersion < tls.VersionTLS13 {
		return nil, errors.New("browser server selected TLS1.3 above max_version")
	}
	secure, err := f.tls13(ctx, o, password, nil)
	if err != nil {
		return nil, err
	}
	return &realityConn{Conn: secure.conn, tls: secure}, nil
}

func (h *stClientHello) initBrowser(name string) error {
	name = strings.ToLower(name)
	if name == "chrome" {
		name = "chrome150"
	}
	if name == "firefox" {
		name = "firefox148"
	}
	if !strings.HasPrefix(name, "safari") {
		return h.initModernBrowser(name)
	}
	h.browser = name
	h.groups = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
	h.suites = []uint16{0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a}
	if name == "safari15_3" {
		h.suites = []uint16{0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc024, 0xc023, 0xc00a, 0xc009, 0xc028, 0xc027, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a}
	}
	if name == "safari26_3" {
		h.suites[0], h.suites[1], h.suites[2] = 0x1302, 0x1303, 0x1301
		h.groups = append([]tls.CurveID{tls.X25519MLKEM768}, h.groups...)
	}
	var seed [5]byte
	rand.Read(seed[:])
	for i, v := range seed {
		b := uint16(v&15)*16 + 10
		h.grease[i] = b<<8 | b
	}
	if h.grease[0] == h.grease[1] {
		h.grease[1] ^= 0x1010
	}
	h.suites = append([]uint16{h.grease[2]}, h.suites...)
	return h.share(h.groups[0])
}

func browserWords(values ...uint16) []byte {
	b := make([]byte, 0, len(values)*2)
	for _, v := range values {
		b = binary.BigEndian.AppendUint16(b, v)
	}
	return b
}

func browserSignatures(profile string) []uint16 {
	if strings.HasPrefix(profile, "chrome") {
		v := []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
		if profile == "chrome150" {
			v = append([]uint16{0x0904, 0x0905, 0x0906}, v...)
		}
		return v
	}
	if strings.HasPrefix(profile, "firefox") || profile == "random" {
		return []uint16{0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201}
	}
	if profile == "safari26_3" {
		return []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201}
	}
	return []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201}
}

func (h *stClientHello) browserSignature(body []byte) bool {
	return len(body) >= 2 && slices.Contains(browserSignatures(h.browser), binary.BigEndian.Uint16(body))
}

func (h *stClientHello) browserHello(cookie []byte) ([]byte, error) {
	if !strings.HasPrefix(h.browser, "safari") {
		return h.modernBrowserHello(cookie)
	}
	body := append([]byte{3, 3}, h.random...)
	body = append(body, stVector(h.session, 1)...)
	body = append(body, stVector(browserWords(h.suites...), 2)...)
	body = append(body, 1, 0)
	ext := stExtension(nil, h.grease[0], nil)
	if name := strings.TrimSuffix(h.config.ServerName, "."); name != "" && net.ParseIP(name) == nil {
		ext = stExtension(ext, 0, stVector(append([]byte{0}, stVector([]byte(name), 2)...), 2))
	}
	ext = stExtension(ext, 23, nil)
	ext = stExtension(ext, 0xff01, []byte{0})
	groups := []uint16{h.grease[3]}
	for _, id := range h.groups {
		groups = append(groups, uint16(id))
	}
	ext = stExtension(ext, 10, stVector(browserWords(groups...), 2))
	ext = stExtension(ext, 11, []byte{1, 0})
	if len(h.config.NextProtos) != 0 {
		var protocols []byte
		for _, p := range h.config.NextProtos {
			if len(p) == 0 || len(p) > 255 {
				return nil, errors.New("invalid browser ALPN")
			}
			protocols = append(protocols, stVector([]byte(p), 1)...)
		}
		ext = stExtension(ext, 16, stVector(protocols, 2))
	}
	ext = stExtension(ext, 5, []byte{1, 0, 0, 0, 0})
	ext = stExtension(ext, 13, stVector(browserWords(browserSignatures(h.browser)...), 2))
	ext = stExtension(ext, 18, nil)
	var shares []byte
	retry := len(h.serverHello) >= 38 && bytes.Equal(h.serverHello[6:38], stRetryRandom)
	if !retry {
		shares = append(browserWords(h.grease[3]), 0, 1, 0)
	}
	public := h.key.PublicKey().Bytes()
	if h.kem != nil {
		public = append(h.kem.EncapsulationKey().Bytes(), public...)
	}
	shares = append(shares, browserWords(uint16(h.group))...)
	shares = append(shares, stVector(public, 2)...)
	if h.kem != nil && !retry {
		shares = append(shares, browserWords(uint16(tls.X25519))...)
		shares = append(shares, stVector(h.fallback.PublicKey().Bytes(), 2)...)
	}
	ext = stExtension(ext, 51, stVector(shares, 2))
	ext = stExtension(ext, 45, []byte{1, 1})
	versions := browserWords(h.grease[4])
	for _, version := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		if (h.config.MinVersion == 0 || version >= h.config.MinVersion) && (h.config.MaxVersion == 0 || version <= h.config.MaxVersion) {
			versions = append(versions, browserWords(version)...)
		}
	}
	if h.browser != "safari26_3" && h.config.MinVersion <= tls.VersionTLS12 {
		versions = append(versions, 3, 2, 3, 1)
	}
	ext = stExtension(ext, 43, stVector(versions, 1))
	if h.browser != "safari15_3" {
		ext = stExtension(ext, 27, []byte{2, 0, 1})
	}
	ext = stExtension(ext, h.grease[1], []byte{0})
	if cookie != nil {
		ext = stExtension(ext, 44, cookie)
	}
	// These Safari profiles pad a 256..511-byte initial ClientHello to512.
	if h.browser != "safari26_3" {
		n := 4 + len(body) + 2 + len(ext)
		if n > 255 && n < 512 {
			ext = stExtension(ext, 21, make([]byte, max(1, 512-n-4)))
		}
	}
	return stMessage(1, append(body, stVector(ext, 2)...)), nil
}

func browserCertificate(message []byte) ([]byte, error) {
	if len(message) < 4 || message[0] != 25 || int(message[1])<<16|int(message[2])<<8|int(message[3]) != len(message)-4 {
		return nil, errors.New("invalid browser certificate message")
	}
	p := stCursor{data: message[4:]}
	algorithm, size := p.number(2), p.number(3)
	compressed := p.vector(3)
	if p.end() != nil || (algorithm < 1 || algorithm > 3) || size == 0 || size > 1<<20 {
		return nil, errors.New("invalid browser compressed certificate")
	}
	if algorithm == 3 {
		decoder, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(1<<20), zstd.WithDecoderMaxWindow(1<<20), zstd.WithDecodeAllCapLimit(true))
		if err != nil {
			return nil, err
		}
		defer decoder.Close()
		body, err := decoder.DecodeAll(compressed, make([]byte, 0, size))
		if err != nil || len(body) != size {
			return nil, errors.New("invalid zstd certificate compression")
		}
		return body, nil
	}
	input := bytes.NewReader(compressed)
	var z io.ReadCloser
	var err error
	if algorithm == 2 {
		z = io.NopCloser(brotli.NewReader(input))
	} else {
		z, err = zlib.NewReader(input)
	}
	if err != nil {
		return nil, err
	}
	defer z.Close()
	body, err := io.ReadAll(io.LimitReader(z, int64(size)+1))
	if err != nil || len(body) != size || input.Len() != 0 {
		return nil, errors.New("invalid browser certificate compression length or trailing data")
	}
	return body, nil
}
