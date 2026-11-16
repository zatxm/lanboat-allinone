package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type tlsConnection interface {
	net.Conn
	Handshake() error
	HandshakeContext(context.Context) error
	ConnectionState() tls.ConnectionState
	NetConn() net.Conn
	CloseWrite() error
}

type tlsSession interface {
	tlsStream
	CloseWrite() error
}

type kernelTLS struct {
	tx, rx      bool
	raw         syscall.RawConn
	controllers []*controller
}

type kernelTLSHandshake struct {
	net.Conn
	config    *tls.Config
	options   TLSOptions
	server    bool
	once      sync.Once
	secure    atomic.Pointer[tlsSession]
	err       error
	closeOnce sync.Once
	closeErr  error
}

func serverTLSConnection(conn net.Conn, config *tls.Config, options TLSOptions) tlsConnection {
	if options.KernelTX || options.KernelRX {
		return &kernelTLSHandshake{Conn: conn, config: config, options: options, server: true}
	}
	return tls.Server(conn, config)
}

func (c *kernelTLSHandshake) Handshake() error { return c.HandshakeContext(context.Background()) }
func (c *kernelTLSHandshake) HandshakeContext(ctx context.Context) error {
	c.once.Do(func() {
		stop := context.AfterFunc(ctx, func() { c.Conn.Close() })
		defer stop()
		var secure tlsSession
		if c.options.browserEnabled() {
			secure, c.err = dialBrowserTLS(ctx, c.Conn, c.config, c.options, "")
		} else {
			secure, c.err = handoffTLS(ctx, c.Conn, c.config, c.server)
		}
		if c.err == nil {
			if c.options.KernelTX || c.options.KernelRX {
				if stream, ok := secure.(*realityConn); ok {
					stream.kernel, c.err = installKernelTLS(c.Conn, stream.tls, c.options.KernelTX, c.options.KernelRX)
				} else {
					c.err = errors.New("kernel TLS requires TLS1.3")
				}
			}
		}
		if c.err != nil {
			c.Conn.Close()
		} else {
			c.secure.Store(&secure)
		}
	})
	return c.err
}
func (c *kernelTLSHandshake) ConnectionState() tls.ConnectionState {
	secure := c.secure.Load()
	if secure == nil {
		return tls.ConnectionState{}
	}
	return (*secure).ConnectionState()
}
func (c *kernelTLSHandshake) NetConn() net.Conn { return c.Conn }
func (c *kernelTLSHandshake) Close() error {
	c.closeOnce.Do(func() {
		if secure := c.secure.Load(); secure != nil {
			c.Conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
			_ = (*secure).CloseWrite()
			c.closeErr = (*secure).Close()
		} else {
			c.closeErr = c.Conn.Close()
		}
		if errors.Is(c.closeErr, net.ErrClosed) {
			c.closeErr = nil
		}
	})
	return c.closeErr
}
func (c *kernelTLSHandshake) Read(p []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	return (*c.secure.Load()).Read(p)
}
func (c *kernelTLSHandshake) Write(p []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	return (*c.secure.Load()).Write(p)
}
func (c *kernelTLSHandshake) CloseWrite() error {
	if err := c.Handshake(); err != nil {
		return err
	}
	return (*c.secure.Load()).CloseWrite()
}

type kernelTLSListener struct {
	net.Listener
	config  *tls.Config
	options TLSOptions
}

func (l *kernelTLSListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return serverTLSConnection(c, l.config, l.options), nil
}

// Public TLS key-log callbacks remain in memory. Exact record reads prevent
// crypto/tls from retaining bytes that belong to the new record-layer owner.
type tlsHandoffWire struct {
	net.Conn
	server  bool
	mu      sync.Mutex
	log     io.Writer
	suite   stCipherSuite
	secrets [2][]byte // read,write
	ciphers [2]*stRecordCipher
	records [2][]byte
	hellos  [2][]byte
}

func (c *tlsHandoffWire) WriteKeyLog(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fields := bytes.Fields(p)
	if len(fields) == 3 && (string(fields[0]) == "CLIENT_TRAFFIC_SECRET_0" || string(fields[0]) == "SERVER_TRAFFIC_SECRET_0") {
		direction := 0
		if (string(fields[0]) == "CLIENT_TRAFFIC_SECRET_0") != c.server {
			direction = 1
		}
		secret, err := hex.DecodeString(string(fields[2]))
		if err != nil || len(secret) != 32 && len(secret) != 48 {
			return 0, errors.New("invalid TLS traffic secret")
		}
		c.secrets[direction] = secret
	}
	if c.log != nil {
		return c.log.Write(p)
	}
	return len(p), nil
}

type tlsHandoffLog struct{ wire *tlsHandoffWire }

func (l tlsHandoffLog) Write(p []byte) (int, error) { return l.wire.WriteKeyLog(p) }

func (c *tlsHandoffWire) observe(direction int, p []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records[direction] = append(c.records[direction], p...)
	for len(c.records[direction]) >= 5 {
		wire := c.records[direction]
		n := 5 + int(binary.BigEndian.Uint16(wire[3:5]))
		if n > 18437 {
			return errors.New("TLS handoff record exceeds limit")
		}
		if n > len(wire) {
			break
		}
		frame := wire[:n]
		if frame[0] == 22 {
			c.hellos[direction] = append(c.hellos[direction], frame[5:]...)
			for len(c.hellos[direction]) >= 4 {
				message := c.hellos[direction]
				length := 4 + int(readUint24(message[1:4]))
				if length > 65536 {
					return errors.New("TLS handoff hello exceeds limit")
				}
				if length > len(message) {
					break
				}
				if message[0] == 2 {
					q := stCursor{data: message[4:length]}
					q.take(34)
					q.vector(1)
					var err error
					c.suite, err = stSuite(uint16(q.number(2)))
					if err != nil || q.err != nil {
						return errors.New("kernel TLS requires a TLS1.3 AEAD suite")
					}
				}
				c.hellos[direction] = message[length:]
			}
		}
		if frame[0] == 23 && c.secrets[direction] != nil && c.suite.id != 0 {
			if c.ciphers[direction] == nil {
				var err error
				c.ciphers[direction], err = c.suite.recordCipher(c.secrets[direction])
				if err != nil {
					return err
				}
			}
			trial := *c.ciphers[direction]
			if _, _, err := trial.open(frame); err == nil {
				c.ciphers[direction].sequence = trial.sequence
			}
		}
		c.records[direction] = wire[n:]
	}
	return nil
}

func (c *tlsHandoffWire) Read(p []byte) (int, error) {
	remaining := 5 - len(c.records[0])
	if len(c.records[0]) >= 5 {
		remaining = 5 + int(binary.BigEndian.Uint16(c.records[0][3:5])) - len(c.records[0])
	}
	if remaining <= 0 {
		return 0, errors.New("invalid TLS handoff read boundary")
	}
	n, err := c.Conn.Read(p[:min(len(p), remaining)])
	if n > 0 {
		if cause := c.observe(0, p[:n]); cause != nil {
			return n, cause
		}
	}
	return n, err
}
func (c *tlsHandoffWire) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		if cause := c.observe(1, p[:n]); cause != nil {
			return n, cause
		}
	}
	return n, err
}

func handoffTLS(ctx context.Context, raw net.Conn, cfg *tls.Config, server bool) (*realityConn, error) {
	wire := &tlsHandoffWire{Conn: raw, server: server, log: cfg.KeyLogWriter}
	defer func() {
		for _, secret := range wire.secrets {
			clear(secret)
		}
	}()
	config := handoffTLSConfig(cfg, tlsHandoffLog{wire})
	var secure *tls.Conn
	if server {
		secure = tls.Server(wire, config)
	} else {
		secure = tls.Client(wire, config)
	}
	if err := secure.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	state := secure.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		return nil, errors.New("kernel TLS requires TLS1.3")
	}
	if len(wire.records[0])+len(wire.records[1]) != 0 {
		return nil, errors.New("TLS handoff has an incomplete record")
	}
	result := &stTLS13{conn: raw, state: state, suite: wire.suite, clientSecret: bytes.Clone(wire.secrets[1]), serverSecret: bytes.Clone(wire.secrets[0])}
	for i, target := range []**stRecordCipher{&result.serverApp, &result.clientApp} {
		if len(wire.secrets[i]) != wire.suite.hash.Size() {
			return nil, errors.New("TLS handoff missing traffic secret")
		}
		var err error
		*target, err = wire.suite.recordCipher(wire.secrets[i])
		if err != nil {
			return nil, err
		}
		if wire.ciphers[i] != nil {
			(*target).sequence = wire.ciphers[i].sequence
		}
	}
	return &realityConn{Conn: raw, tls: result, server: server}, nil
}

func handoffTLSConfig(cfg *tls.Config, log io.Writer) *tls.Config {
	c := cfg.Clone()
	c.MinVersion = max(c.MinVersion, tls.VersionTLS13)
	c.KeyLogWriter = log
	if load := cfg.GetConfigForClient; load != nil {
		c.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			current, e := load(hello)
			if e != nil || current == nil {
				return current, e
			}
			return handoffTLSConfig(current, log), nil
		}
	}
	return c
}
