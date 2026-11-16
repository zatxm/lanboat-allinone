package native

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

type realityConn struct {
	net.Conn
	kernel            *kernelTLS
	tls               *stTLS13
	readMu, writeMu   sync.Mutex
	frame             [5 + 16640]byte
	position, size    int
	data, handshake   []byte
	readErr, writeErr error
	writeClosed       bool
	server            bool
	exportMu          sync.Mutex
	exportClosed      bool
}

type tlsStream interface {
	net.Conn
	ConnectionState() tls.ConnectionState
}

func handshakeTLS(ctx context.Context, raw net.Conn, cfg *tls.Config, options TLSOptions) (tlsStream, error) {
	if options.realityEnabled() {
		return dialReality(ctx, raw, cfg, options)
	}
	conn := clientTLS(raw, cfg, options)
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return conn, nil
}

func dialReality(ctx context.Context, raw net.Conn, cfg *tls.Config, options TLSOptions) (*realityConn, error) {
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	config := cloneTLSConfig(cfg)
	if options.browserEnabled() && len(config.NextProtos) == 0 {
		config.NextProtos = []string{"h2", "http/1.1"}
	}
	config.MinVersion, config.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	config.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768, tls.X25519}
	secure, err := independentTLS13(ctx, raw, config, options, "", options.Reality)
	if cause := ctx.Err(); cause != nil {
		return nil, cause
	}
	if err != nil {
		return nil, err
	}
	conn := &realityConn{Conn: secure.conn, tls: secure}
	if options.KernelTX || options.KernelRX {
		conn.kernel, err = installKernelTLS(secure.conn, secure, options.KernelTX, options.KernelRX)
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

func (c *realityConn) ConnectionState() tls.ConnectionState { return c.tls.state }
func (c *realityConn) NetConn() net.Conn                    { return c.Conn }

func (c *realityConn) record() ([]byte, error) {
	if c.size == 0 {
		for c.position < 5 {
			n, err := c.Conn.Read(c.frame[c.position:5])
			c.position += n
			if err != nil {
				return nil, err
			}
		}
		c.size = 5 + int(binary.BigEndian.Uint16(c.frame[3:5]))
		if c.frame[0] != 23 || c.frame[1] != 3 || c.frame[2] != 3 || c.size < 22 || c.size > len(c.frame) {
			return nil, errors.New("invalid Reality TLS record")
		}
	}
	for c.position < c.size {
		n, err := c.Conn.Read(c.frame[c.position:c.size])
		c.position += n
		if err != nil {
			return nil, err
		}
	}
	b := c.frame[:c.size]
	c.position, c.size = 0, 0
	return b, nil
}

func (c *realityConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	for count := 0; len(c.data) == 0; count++ {
		if count == 128 {
			return c.failRead(errors.New("excessive Reality TLS control records"))
		}
		kind, data, err := c.readTLSRecord()
		if err != nil {
			if os.IsTimeout(err) {
				return 0, err
			}
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return c.failRead(err)
		}
		switch kind {
		case 23:
			if len(c.handshake) != 0 {
				return c.failRead(errors.New("interleaved Reality TLS handshake"))
			}
			c.data = data
		case 21:
			if len(data) == 2 && data[1] == 0 {
				c.readErr = io.EOF
				return 0, io.EOF
			}
			return c.failRead(errors.New("Reality TLS peer alert"))
		case 22:
			c.handshake = append(c.handshake, data...)
			if len(c.handshake) > 65536 {
				return c.failRead(errors.New("Reality TLS post-handshake exceeds64KiB"))
			}
			for len(c.handshake) >= 4 {
				n := 4 + (int(c.handshake[1])<<16 | int(c.handshake[2])<<8 | int(c.handshake[3]))
				if n > 65536 {
					return c.failRead(errors.New("Reality TLS control message exceeds64KiB"))
				}
				if n > len(c.handshake) {
					break
				}
				msg := c.handshake[:n]
				switch msg[0] {
				case 4:
					if c.server {
						return c.failRead(errors.New("client sent a TLS session ticket"))
					}
					p := stCursor{data: msg[4:]}
					p.take(8)
					p.vector(1)
					ticket := p.vector(2)
					ext := p.vector(2)
					if p.end() != nil || len(ticket) == 0 {
						return c.failRead(errors.New("invalid Reality TLS ticket"))
					}
					if _, err = stExtensions(ext); err != nil {
						return c.failRead(err)
					}
				case 24:
					if len(msg) != 5 || msg[4] > 1 {
						return c.failRead(errors.New("invalid Reality TLS KeyUpdate"))
					}
					c.tls.serverSecret = c.tls.suite.expand(c.tls.serverSecret, "traffic upd", nil, c.tls.suite.hash.Size())
					c.tls.serverApp, err = c.tls.suite.recordCipher(c.tls.serverSecret)
					if err != nil {
						return c.failRead(err)
					}
					if c.kernel != nil && c.kernel.rx {
						if err = c.kernel.setKey(c.tls, false); err != nil {
							return c.failRead(err)
						}
					}
					if msg[4] == 1 {
						c.writeMu.Lock()
						err = c.updateWriteKey()
						c.writeMu.Unlock()
						if err != nil {
							return c.failRead(err)
						}
					}
				default:
					return c.failRead(fmt.Errorf("unsupported Reality TLS control message%d", msg[0]))
				}
				c.handshake = c.handshake[n:]
			}
		default:
			return c.failRead(errors.New("invalid Reality TLS record type"))
		}
	}
	n := copy(b, c.data)
	c.data = c.data[n:]
	return n, nil
}

func (c *realityConn) failRead(err error) (int, error) {
	c.readErr = err
	c.Conn.Close()
	return 0, err
}

func (c *realityConn) readTLSRecord() (byte, []byte, error) {
	if c.kernel != nil && c.kernel.rx {
		kind, n, err := c.kernel.receive(c.frame[:])
		return kind, c.frame[:n], err
	}
	frame, err := c.record()
	if err != nil {
		return 0, nil, err
	}
	return c.tls.serverApp.open(frame)
}

func (c *realityConn) send(kind byte, data []byte) error {
	if c.writeErr != nil {
		return c.writeErr
	}
	var err error
	if c.kernel != nil && c.kernel.tx {
		var records uint64
		records, err = c.kernel.send(kind, data)
		c.tls.clientApp.sequence += records
	} else {
		var frame []byte
		frame, err = c.tls.clientApp.seal(kind, data)
		if err == nil {
			err = writeAll(c.Conn, frame)
		}
	}
	if err != nil {
		c.writeErr = err
		c.Conn.Close()
	}
	return err
}

func (c *realityConn) updateWriteKey() error {
	if c.writeClosed {
		return net.ErrClosed
	}
	if err := c.send(22, []byte{24, 0, 0, 1, 0}); err != nil {
		return err
	}
	c.tls.clientSecret = c.tls.suite.expand(c.tls.clientSecret, "traffic upd", nil, c.tls.suite.hash.Size())
	var err error
	c.tls.clientApp, err = c.tls.suite.recordCipher(c.tls.clientSecret)
	if err == nil && c.kernel != nil && c.kernel.tx {
		err = c.kernel.setKey(c.tls, true)
	}
	return err
}

func (c *realityConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return 0, net.ErrClosed
	}
	n := 0
	for len(b) > 0 {
		if c.tls.clientApp.sequence >= 1<<24 {
			if err := c.updateWriteKey(); err != nil {
				return n, err
			}
		}
		count := min(len(b), 16384)
		if c.tls.writeLimit != 0 {
			count = min(count, c.tls.writeLimit)
		}
		if err := c.send(23, b[:count]); err != nil {
			return n, err
		}
		n += count
		b = b[count:]
	}
	return n, nil
}

func (c *realityConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return nil
	}
	c.writeClosed = true
	err := c.send(21, []byte{1, 0})
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok && err == nil {
		return half.CloseWrite()
	}
	return err
}
