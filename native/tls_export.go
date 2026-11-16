package native

import (
	"crypto/tls"
	"errors"
	"net"
)

// ConnectionState cannot carry an independent handshake's unexported Go exporter.
func tlsExport(conn net.Conn, label string, context []byte, length int) ([]byte, error) {
	for {
		if c, ok := conn.(*bufferedConn); ok {
			conn = c.Conn
			continue
		}
		if c, ok := conn.(interface {
			ExportKeyingMaterial(string, []byte, int) ([]byte, error)
		}); ok {
			return c.ExportKeyingMaterial(label, context, length)
		}
		if c, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
			state := c.ConnectionState()
			return state.ExportKeyingMaterial(label, context, length)
		}
		return nil, errors.New("TLS exporter unavailable")
	}
}

func (c *kernelTLSHandshake) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	if err := c.Handshake(); err != nil {
		return nil, err
	}
	return tlsExport(*c.secure.Load(), label, context, length)
}

func (c *realityConn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	c.exportMu.Lock()
	defer c.exportMu.Unlock()
	if c.exportClosed {
		return nil, net.ErrClosed
	}
	if c.tls.exporter == nil {
		state := c.ConnectionState()
		return state.ExportKeyingMaterial(label, context, length)
	}
	suite := c.tls.suite
	if length < 0 || length > min(65535, 255*suite.hash.Size()) || len(label) > 249 {
		return nil, errors.New("invalid TLS1.3 exporter length or label")
	}
	switch label {
	case "client finished", "server finished", "master secret", "key expansion":
		return nil, errors.New("reserved TLS exporter label")
	}
	secret := suite.derive(c.tls.exporter, label, suite.newHash())
	defer clear(secret)
	h := suite.newHash()
	h.Write(context)
	return suite.expand(secret, "exporter", h.Sum(nil), length), nil
}

func (c *realityConn) Close() error {
	err := c.Conn.Close()
	c.exportMu.Lock()
	c.exportClosed = true
	clear(c.tls.exporter)
	c.exportMu.Unlock()
	return err
}
