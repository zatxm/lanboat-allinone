package native

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net"
	"slices"
	"sync"
)

var ocTLS12Suites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

type ocTLS12Cipher struct {
	cbc      *browserTLS12CBC
	buffer   []byte
	aead     cipher.AEAD
	iv       [12]byte
	sequence uint64
	limit    uint64
	explicit bool
}

func ocTLS12Hash(suite uint16) func() hash.Hash {
	if suite == tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 || suite == tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 || suite == 0x009d || suite == 0xc024 || suite == 0xc028 {
		return sha512.New384
	}
	return sha256.New
}

func ocTLS12Keys(suite uint16, master, client, server []byte) ([2]*ocTLS12Cipher, error) {
	var out [2]*ocTLS12Cipher
	if !slices.Contains(ocTLS12Suites, suite) && suite != 0x009c && suite != 0x009d {
		return out, errors.New("TLS1.2 requires an AEAD suite")
	}
	keySize, ivSize := 16, 4
	chacha := suite == tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 || suite == tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	if chacha || ocTLS12Hash(suite)().Size() == 48 {
		keySize = 32
	}
	if chacha {
		ivSize = 12
	}
	seed := append(bytes.Clone(server), client...)
	keys := ocDTLSPRF(ocTLS12Hash(suite), master, "key expansion", seed, 2*(keySize+ivSize))
	defer clear(keys)
	for i := range out {
		key := keys[i*keySize : (i+1)*keySize]
		var a cipher.AEAD
		var err error
		if chacha {
			a, err = newChaChaAEAD(key, false)
		} else {
			var block cipher.Block
			block, err = aes.NewCipher(key)
			if err == nil {
				a, err = cipher.NewGCM(block)
			}
		}
		if err != nil {
			return out, err
		}
		limit := uint64(1 << 24)
		if chacha {
			limit = 1 << 36
		}
		out[i] = &ocTLS12Cipher{aead: a, explicit: !chacha, limit: limit}
		copy(out[i].iv[:], keys[2*keySize+i*ivSize:2*keySize+(i+1)*ivSize])
	}
	return out, nil
}

func (c *ocTLS12Cipher) nonce(seq uint64) [12]byte {
	n := c.iv
	if c.explicit {
		binary.BigEndian.PutUint64(n[4:], seq)
	} else {
		for i := range 8 {
			n[11-i] ^= byte(seq >> (8 * i))
		}
	}
	return n
}

func (c *ocTLS12Cipher) seal(kind byte, data []byte) ([]byte, error) {
	if len(data) > 16384 || c.sequence >= c.limit {
		return nil, errors.New("CSTP TLS1.2 record limit")
	}
	if c.cbc != nil {
		return c.sealCBC(kind, data)
	}
	var aad [13]byte
	binary.BigEndian.PutUint64(aad[:8], c.sequence)
	aad[8], aad[9], aad[10] = kind, 3, 3
	binary.BigEndian.PutUint16(aad[11:], uint16(len(data)))
	nonce := c.nonce(c.sequence)
	n := len(data) + c.aead.Overhead()
	if c.explicit {
		n += 8
	}
	if cap(c.buffer) < n+5 {
		c.buffer = make([]byte, 0, n+5)
	}
	b := append(c.buffer[:0], kind, 3, 3, byte(n>>8), byte(n))
	if c.explicit {
		b = append(b, nonce[4:]...)
	}
	b = c.aead.Seal(b, nonce[:], data, aad[:])
	c.buffer = b
	c.sequence++
	return b, nil
}

func (c *ocTLS12Cipher) open(frame []byte) ([]byte, error) {
	if c.sequence >= c.limit || len(frame) < 5 || frame[1] != 3 || frame[2] != 3 || int(binary.BigEndian.Uint16(frame[3:5])) != len(frame)-5 {
		return nil, errors.New("invalid CSTP TLS1.2 record")
	}
	if c.cbc != nil {
		return c.openCBC(frame)
	}
	data := frame[5:]
	nonce := c.nonce(c.sequence)
	if c.explicit {
		if len(data) < 8 {
			return nil, io.ErrUnexpectedEOF
		}
		copy(nonce[4:], data[:8])
		data = data[8:]
	}
	n := len(data) - c.aead.Overhead()
	if n < 0 || n > 16384 {
		return nil, errors.New("invalid CSTP TLS1.2 record length")
	}
	var aad [13]byte
	binary.BigEndian.PutUint64(aad[:8], c.sequence)
	copy(aad[8:11], frame[:3])
	binary.BigEndian.PutUint16(aad[11:], uint16(n))
	b, err := c.aead.Open(data[:0], nonce[:], data, aad[:])
	if err == nil {
		c.sequence++
	}
	return b, err
}

// Observe only the authenticated initial handshake, then retire crypto/tls at an exact record boundary.
type ocTLS12Initial struct {
	net.Conn
	mu                                 sync.Mutex
	server, tls13, legacy, inactive    bool
	log                                io.Writer
	records, messages                  [2][]byte
	encrypted                          [2]bool
	keys                               [2]*ocTLS12Cipher
	master, clientRandom, serverRandom []byte
	clientHello, serverHello           []byte
	localCertificate                   []byte
	certificate                        *tls.Certificate
	finished                           [2][]byte // client,server
	suite                              uint16
}
type ocTLS12KeyLog struct{ wire *ocTLS12Initial }

func (l ocTLS12KeyLog) Write(p []byte) (int, error) {
	c := l.wire
	c.mu.Lock()
	defer c.mu.Unlock()
	f := bytes.Fields(p)
	if len(f) == 3 && string(f[0]) == "CLIENT_RANDOM" {
		master, err := hex.DecodeString(string(f[2]))
		if err != nil || len(master) != 48 {
			return 0, errors.New("invalid CSTP TLS1.2 master secret")
		}
		clear(c.master)
		c.master = master
	}
	if c.log != nil {
		return c.log.Write(p)
	}
	return len(p), nil
}
func (c *ocTLS12Initial) observe(direction int, p []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inactive {
		return nil
	}
	c.records[direction] = append(c.records[direction], p...)
	for len(c.records[direction]) >= 5 {
		frame := c.records[direction]
		n := 5 + int(binary.BigEndian.Uint16(frame[3:5]))
		if n > 18437 {
			return errors.New("CSTP TLS record exceeds limit")
		}
		if len(frame) < n {
			break
		}
		kind, data := frame[0], frame[5:n]
		if !c.tls13 && !c.legacy {
			if c.encrypted[direction] {
				if c.keys[0] == nil {
					if len(c.master) != 48 {
						return errors.New("missing CSTP TLS1.2 master secret")
					}
					var err error
					c.keys, err = ocTLS12Keys(c.suite, c.master, c.clientRandom, c.serverRandom)
					if err != nil {
						return err
					}
				}
				i := direction
				if !c.server {
					i = 1 - i
				}
				var err error
				data, err = c.keys[i].open(frame[:n])
				if err != nil {
					return err
				}
			}
			if kind == 20 {
				c.encrypted[direction] = true
			}
			if kind == 22 {
				c.messages[direction] = append(c.messages[direction], data...)
				for len(c.messages[direction]) >= 4 {
					m := c.messages[direction]
					size := 4 + int(readUint24(m[1:4]))
					if size > 256<<10 {
						return errors.New("CSTP TLS handshake exceeds limit")
					}
					if len(m) < size {
						break
					}
					body := m[4:size]
					switch m[0] {
					case 11:
						if direction == 1 {
							p := stCursor{data: body}
							list := stCursor{data: p.vector(3)}
							if len(list.data) > 0 {
								c.localCertificate = bytes.Clone(list.vector(3))
							}
							if p.end() != nil || list.err != nil {
								return errors.New("invalid initial CSTP TLS certificate")
							}
						}
					case 1:
						c.clientHello = bytes.Clone(body)
						if len(body) >= 34 {
							c.clientRandom = bytes.Clone(body[2:34])
						}
					case 2:
						c.serverHello = bytes.Clone(body)
						q := stCursor{data: body}
						q.take(2)
						c.serverRandom = bytes.Clone(q.take(32))
						q.vector(1)
						c.suite = uint16(q.number(2))
						q.take(1)
						if q.err != nil {
							return q.err
						}
						if c.suite >= 0x1301 && c.suite <= 0x1303 {
							c.tls13 = true
						}
						c.legacy = !c.tls13 && !slices.Contains(ocTLS12Suites, c.suite)
					case 20:
						i := direction
						if !c.server {
							i = 1 - i
						}
						c.finished[i] = bytes.Clone(body)
					}
					c.messages[direction] = m[size:]
				}
			}
		}
		c.records[direction] = frame[n:]
	}
	return nil
}
func (c *ocTLS12Initial) Read(p []byte) (int, error) {
	if c.inactive {
		return c.Conn.Read(p)
	}
	left := 5 - len(c.records[0])
	if len(c.records[0]) >= 5 {
		left = 5 + int(binary.BigEndian.Uint16(c.records[0][3:5])) - len(c.records[0])
	}
	if left <= 0 {
		return 0, errors.New("invalid CSTP TLS record boundary")
	}
	n, e := c.Conn.Read(p[:min(len(p), left)])
	if n > 0 {
		if err := c.observe(0, p[:n]); err != nil {
			return n, err
		}
	}
	return n, e
}
func (c *ocTLS12Initial) Write(p []byte) (int, error) {
	if c.inactive {
		return c.Conn.Write(p)
	}
	n, e := c.Conn.Write(p)
	if n > 0 {
		if err := c.observe(1, p[:n]); err != nil {
			return n, err
		}
	}
	return n, e
}

func ocTLS12Config(cfg *tls.Config, wire *ocTLS12Initial) *tls.Config {
	c := cfg.Clone()
	c.MinVersion = max(c.MinVersion, tls.VersionTLS12)
	c.ClientSessionCache = nil
	c.SessionTicketsDisabled = true
	c.KeyLogWriter = ocTLS12KeyLog{wire}
	if cfg.GetCertificate != nil {
		c.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, e := cfg.GetCertificate(h)
			wire.certificate = cert
			return cert, e
		}
	}
	if cfg.GetClientCertificate != nil {
		c.GetClientCertificate = func(h *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, e := cfg.GetClientCertificate(h)
			wire.certificate = cert
			return cert, e
		}
	}
	return c
}

func handshakeOCTLS(ctx context.Context, raw net.Conn, cfg *tls.Config, o TLSOptions, server bool) (tlsConnection, error) {
	if o.KernelTX || o.KernelRX || !server && o.browserEnabled() {
		c := serverTLSConnection(raw, cfg, o)
		if !server {
			c = clientTLS(raw, cfg, o)
		}
		if err := c.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		if h, ok := c.(*kernelTLSHandshake); ok {
			if legacy, ok := (*h.secure.Load()).(*ocTLS12); ok {
				return legacy, nil
			}
		}
		return c, nil
	}
	if !server {
		raw, cfg = clientTLSConnection(raw, cfg, o)
	}
	wire := &ocTLS12Initial{Conn: raw, server: server, log: cfg.KeyLogWriter}
	defer func() { clear(wire.master) }()
	config := ocTLS12Config(cfg, wire)
	if cfg.GetConfigForClient != nil {
		config.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			c, e := cfg.GetConfigForClient(h)
			if e != nil || c == nil {
				return c, e
			}
			config = ocTLS12Config(c, wire)
			return config, nil
		}
	}
	c := tls.Client(wire, config)
	if server {
		c = tls.Server(wire, config)
	}
	if e := c.HandshakeContext(ctx); e != nil {
		return nil, e
	}
	wire.inactive = true
	if c.ConnectionState().Version == tls.VersionTLS13 || wire.legacy {
		wire.records = [2][]byte{}
		wire.messages = [2][]byte{}
		wire.clientHello, wire.serverHello = nil, nil
		return c, nil
	}
	if len(wire.records[0])+len(wire.records[1]) != 0 || len(wire.finished[0]) != 12 || len(wire.finished[1]) != 12 {
		return nil, errors.New("incomplete CSTP TLS1.2 handoff")
	}
	config.KeyLogWriter = cfg.KeyLogWriter
	config.GetConfigForClient = nil
	config.GetCertificate = nil
	config.GetClientCertificate = nil
	return newOCTLS12(raw, config, c.ConnectionState(), wire)
}
