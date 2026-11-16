package native

import (
	"net"
	"sync"
)

// Defer the HTTP upgrade until the protocol writes its first request bytes.
type earlyTransportConn struct {
	net.Conn
	transport        Transport
	server, protocol string
	once             sync.Once
	stream           net.Conn
	err              error
}

func (c *earlyTransportConn) handshake(first []byte) (int, error) {
	n := 0
	c.once.Do(func() {
		n = min(len(first), c.transport.MaxEarlyData)
		// Reference Trojan servers classify the first read using the complete56-byte hash.
		if c.protocol == "trojan" && n < 56 {
			n = 0
		}
		c.stream, c.err = dialTransportHandshake(c.Conn, Outbound{Type: c.protocol, Server: c.server, Transport: c.transport}, first[:n])
	})
	if c.err != nil {
		return 0, c.err
	}
	return n, nil
}

func (c *earlyTransportConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := c.handshake(p)
	if err != nil {
		return 0, err
	}
	if n == len(p) {
		return n, nil
	}
	m, err := c.stream.Write(p[n:])
	return n + m, err
}

func (c *earlyTransportConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if _, err := c.handshake(nil); err != nil {
		return 0, err
	}
	return c.stream.Read(p)
}

func (c *earlyTransportConn) CloseWrite() error {
	if _, err := c.handshake(nil); err != nil {
		return err
	}
	if half, ok := c.stream.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

type earlyDataConn struct {
	net.Conn
	mu      sync.Mutex
	pending []byte
}

func (c *earlyDataConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		if len(c.pending) == 0 {
			c.pending = nil
		}
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *earlyDataConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}
