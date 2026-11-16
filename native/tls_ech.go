package native

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync"
)

type ECHOptions struct {
	Enabled         bool     `json:"enabled,omitempty"`
	Key             []string `json:"key,omitempty"`
	KeyPath         string   `json:"key_path,omitempty"`
	Config          []string `json:"config,omitempty"`
	ConfigPath      string   `json:"config_path,omitempty"`
	QueryServerName string   `json:"query_server_name,omitempty"`

	mu     sync.Mutex
	stamp  os.FileInfo
	source string
	list   []byte
	keys   []tls.EncryptedClientHelloKey
}

type echReader struct {
	b   []byte
	err error
}

func (r *echReader) take(n int) []byte {
	if n > len(r.b) || r.err != nil {
		r.err = errors.New("truncated ECH data")
		return nil
	}
	b := r.b[:n]
	r.b = r.b[n:]
	return b
}
func (r *echReader) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func (r *echReader) u8() byte {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}
func (r *echReader) vec() []byte { return r.take(int(r.u16())) }

type echConfig struct {
	kem        hpke.KEM
	public     []byte
	usable     bool
	id         byte
	name       string
	nameLength byte
	kdf        hpke.KDF
	aead       hpke.AEAD
	raw        []byte
}

func echDomain(name string) bool {
	if len(name) == 0 || len(name) > 253 || strings.HasSuffix(name, ".") {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func parseECHConfig(data []byte) (echConfig, error) {
	var c echConfig
	r := echReader{b: data}
	version, body := r.u16(), r.vec()
	if r.err != nil || len(r.b) != 0 {
		return c, errors.New("invalid ECHConfig length")
	}
	if version != 0xfe0d {
		return c, nil
	}
	r = echReader{b: body}
	c.id = r.u8()
	kemID := r.u16()
	c.public = r.vec()
	suites := echReader{b: r.vec()}
	c.nameLength = r.u8()
	publicName := string(r.take(int(r.u8())))
	c.name, c.raw = publicName, data
	extensions := echReader{b: r.vec()}
	if r.err != nil || len(r.b) != 0 || len(suites.b) == 0 || len(suites.b)%4 != 0 || !echDomain(publicName) {
		return c, errors.New("invalid ECHConfig contents")
	}
	var err error
	c.kem, err = hpke.NewKEM(kemID)
	if err == nil {
		if _, err = c.kem.NewPublicKey(c.public); err != nil {
			return c, errors.New("invalid ECH public key")
		}
	}
	for len(suites.b) > 0 {
		kdfID := suites.u16()
		kdf, kdfErr := hpke.NewKDF(kdfID)
		aeadID := suites.u16()
		aead, aeadErr := hpke.NewAEAD(aeadID)
		if kdfErr == nil && aeadErr == nil && kdfID >= 1 && kdfID <= 3 && aeadID >= 1 && aeadID <= 3 {
			c.usable = c.kem != nil
			if c.kdf == nil {
				c.kdf, c.aead = kdf, aead
			}
		}
	}
	seen := make(map[uint16]bool)
	for len(extensions.b) > 0 && extensions.err == nil {
		id := extensions.u16()
		extensions.vec()
		if seen[id] {
			return c, errors.New("duplicate ECH configuration extension")
		}
		seen[id] = true
		if id&0x8000 != 0 {
			c.usable = false
		}
	}
	if extensions.err != nil {
		return c, extensions.err
	}
	return c, nil
}

func validateECHList(data []byte) error {
	if len(data) < 2 || len(data) > 65535 {
		return errors.New("invalid ECHConfigList size")
	}
	r := echReader{b: data}
	list := r.vec()
	if r.err != nil || len(r.b) != 0 {
		return errors.New("invalid ECHConfigList length")
	}
	r = echReader{b: list}
	usable := false
	for count := 0; len(r.b) > 0 && r.err == nil; count++ {
		if count == 64 {
			return errors.New("ECHConfigList exceeds64 entries")
		}
		before := r.b
		r.u16()
		r.vec()
		if r.err != nil {
			return r.err
		}
		c, err := parseECHConfig(before[:len(before)-len(r.b)])
		if err != nil {
			return err
		}
		usable = usable || c.usable
	}
	if !usable {
		return errors.New("ECHConfigList has no supported configuration")
	}
	return r.err
}

func parseECHKeys(data []byte) ([]tls.EncryptedClientHelloKey, error) {
	r := echReader{b: data}
	var keys []tls.EncryptedClientHelloKey
	for len(r.b) > 0 && r.err == nil {
		if len(keys) == 16 {
			return nil, errors.New("ECH key bundle exceeds16 keys")
		}
		private, config := r.vec(), r.vec()
		if r.err != nil {
			return nil, r.err
		}
		c, err := parseECHConfig(config)
		if err != nil || !c.usable {
			return nil, errors.New("invalid or unsupported ECH key configuration")
		}
		key, err := c.kem.NewPrivateKey(private)
		if err != nil || !bytes.Equal(key.PublicKey().Bytes(), c.public) {
			return nil, errors.New("ECH private key does not match configuration")
		}
		keys = append(keys, tls.EncryptedClientHelloKey{Config: config, PrivateKey: private, SendAsRetry: true})
	}
	if r.err != nil || len(keys) == 0 {
		return nil, errors.New("invalid or empty ECH key bundle")
	}
	return keys, nil
}

func (o *ECHOptions) material(server bool) ([]byte, []tls.EncryptedClientHelloKey, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	path, lines, kind := o.ConfigPath, o.Config, "ECH CONFIGS"
	if server {
		path, lines, kind = o.KeyPath, o.Key, "ECH KEYS"
	}
	if path != "" && len(lines) != 0 {
		return nil, nil, errors.New("ECH inline data and path are mutually exclusive")
	}
	var raw []byte
	var stamp os.FileInfo
	source := kind + ":" + path
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, err
		}
		defer f.Close()
		stamp, err = f.Stat()
		if err != nil {
			return nil, nil, err
		}
		if o.source == source && o.stamp != nil && sameTLSFiles([]os.FileInfo{o.stamp}, []os.FileInfo{stamp}) {
			return o.list, o.keys, nil
		}
		raw, err = io.ReadAll(io.LimitReader(f, (1<<20)+1))
		if err != nil {
			return nil, nil, err
		}
		after, err := f.Stat()
		if err != nil || !sameTLSFiles([]os.FileInfo{stamp}, []os.FileInfo{after}) {
			return nil, nil, errors.New("ECH file changed while loading")
		}
	} else {
		size := 0
		for _, line := range lines {
			size += len(line) + 1
			if size > (1<<20)+1 {
				return nil, nil, errors.New("ECH PEM exceeds1MiB")
			}
		}
		text := strings.Join(lines, "\n")
		digest := sha256.Sum256([]byte(text))
		source += string(digest[:])
		if o.source == source {
			return o.list, o.keys, nil
		}
		raw = []byte(text)
	}
	if len(raw) > 1<<20 {
		return nil, nil, errors.New("ECH PEM exceeds1MiB")
	}
	var body []byte
	for len(bytes.TrimSpace(raw)) != 0 {
		raw = bytes.TrimSpace(raw)
		if !bytes.HasPrefix(raw, []byte("-----BEGIN "+kind+"-----")) {
			return nil, nil, fmt.Errorf("expected %s PEM", kind)
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != kind || len(block.Headers) != 0 {
			return nil, nil, errors.New("invalid ECH PEM")
		}
		if !server && body != nil {
			return nil, nil, errors.New("ECH requires one CONFIGS block")
		}
		body = append(body, block.Bytes...)
		raw = rest
	}
	var keys []tls.EncryptedClientHelloKey
	var err error
	if server {
		keys, err = parseECHKeys(body)
	} else {
		err = validateECHList(body)
	}
	if err != nil {
		return nil, nil, err
	}
	o.source, o.stamp, o.list, o.keys = source, stamp, body, keys
	return body, keys, nil
}

func (o TLSOptions) configureECH(c *tls.Config, server bool) error {
	e := o.ECH
	if e == nil || !e.Enabled {
		return nil
	}
	if o.MinVersion != "" && o.MinVersion != "1.3" || o.MaxVersion != "" && o.MaxVersion != "1.3" {
		return errors.New("ECH requires TLS1.3")
	}
	c.MinVersion = tls.VersionTLS13
	if server {
		if len(e.Config) != 0 || e.ConfigPath != "" || e.QueryServerName != "" {
			return errors.New("ECH config and query_server_name are outbound options")
		}
		_, keys, err := e.material(true)
		c.EncryptedClientHelloKeys = keys
		return err
	}
	if len(e.Key) != 0 || e.KeyPath != "" {
		return errors.New("ECH key is an inbound option")
	}
	if o.DisableSNI {
		return errors.New("ECH conflicts with disable_sni")
	}
	if e.QueryServerName != "" && !echDomain(e.QueryServerName) {
		return errors.New("invalid ECH query_server_name")
	}
	if len(e.Config) != 0 || e.ConfigPath != "" {
		list, _, err := e.material(false)
		c.EncryptedClientHelloConfigList = list
		return err
	}
	if c.ServerName != "" && !echDomain(c.ServerName) && e.QueryServerName == "" {
		return errors.New("ECH DNS discovery requires a domain name")
	}
	return nil
}

func prepareClientTLS(ctx context.Context, c *tls.Config, o TLSOptions, r *resolver) (*tls.Config, error) {
	if c == nil || o.ECH == nil || !o.ECH.Enabled {
		return c, nil
	}
	if c.ServerName == "" {
		return nil, errors.New("ECH requires an inner server_name")
	}
	e := o.ECH
	if len(e.Config) != 0 && e.ConfigPath == "" {
		return c, nil
	}
	var list []byte
	var err error
	if e.ConfigPath != "" {
		list, _, err = e.material(false)
	} else if r == nil {
		return nil, errors.New("ECH DNS discovery requires a resolver")
	} else {
		name := e.QueryServerName
		if name == "" {
			name = c.ServerName
		}
		list, err = r.lookupECH(ctx, name)
	}
	if err != nil {
		return nil, err
	}
	current := cloneTLSConfig(c)
	current.EncryptedClientHelloConfigList = list
	return current, nil
}

func (r *Runtime) outboundTLS(ctx context.Context, o Outbound) (*tls.Config, error) {
	if o.echDynamic() && o.DomainResolver != "" {
		child, cancel := o.DomainResolver.apply(ctx)
		defer cancel()
		ctx = context.WithValue(child, dnsBootstrapKey{}, o.DomainResolver.tag())
	}
	return prepareClientTLS(ctx, r.clientTLS[o.Tag], o.TLS, r.resolver)
}

func (o Outbound) echDynamic() bool {
	return o.TLS.ECH != nil && o.TLS.ECH.Enabled && len(o.TLS.ECH.Config) == 0 && o.TLS.ECH.ConfigPath == ""
}

// GenerateECHKeyPair produces the interoperable ECH CONFIGS / ECH KEYS PEM
// encoding. Private key bytes are returned only to the explicit caller.
func GenerateECHKeyPair(publicName string) (config, key []byte, err error) {
	if !echDomain(publicName) {
		return nil, nil, errors.New("ECH public name must be a DNS hostname")
	}
	kem, _ := hpke.NewKEM(0x0020)
	private, err := kem.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	secret, err := private.Bytes()
	if err != nil {
		return nil, nil, err
	}
	defer clear(secret)
	body := make([]byte, 1)
	if _, err = rand.Read(body); err != nil {
		return nil, nil, err
	}
	body = binary.BigEndian.AppendUint16(body, kem.ID())
	public := private.PublicKey().Bytes()
	body = binary.BigEndian.AppendUint16(body, uint16(len(public)))
	body = append(body, public...)
	body = append(body, 0, 12, 0, 1, 0, 1, 0, 1, 0, 2, 0, 1, 0, 3, 0, byte(len(publicName)))
	body = append(body, publicName...)
	body = append(body, 0, 0)
	entry := binary.BigEndian.AppendUint16(nil, 0xfe0d)
	entry = binary.BigEndian.AppendUint16(entry, uint16(len(body)))
	entry = append(entry, body...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(entry)))
	list = append(list, entry...)
	bundle := binary.BigEndian.AppendUint16(nil, uint16(len(secret)))
	bundle = append(bundle, secret...)
	bundle = binary.BigEndian.AppendUint16(bundle, uint16(len(entry)))
	bundle = append(bundle, entry...)
	defer clear(bundle)
	return pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: list}), pem.EncodeToMemory(&pem.Block{Type: "ECH KEYS", Bytes: bundle}), nil
}
