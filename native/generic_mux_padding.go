package native

import (
	"encoding/binary"
	"io"
	"math/rand/v2"
	"net"
	"sync"
)

type genericPaddingConn struct {
	net.Conn
	readMu, writeMu                   sync.Mutex
	reads, writes, remaining, padding int
	buffer                            []byte
}

func (c *genericPaddingConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if c.remaining > 0 {
			n, err := c.Conn.Read(p[:min(len(p), c.remaining)])
			c.remaining -= n
			return n, err
		}
		if c.padding > 0 {
			_, err := io.CopyN(io.Discard, c.Conn, int64(c.padding))
			if err != nil {
				return 0, err
			}
			c.padding = 0
		}
		if c.reads == 16 {
			return c.Conn.Read(p)
		}
		var h [4]byte
		if _, err := io.ReadFull(c.Conn, h[:]); err != nil {
			return 0, err
		}
		c.remaining = int(binary.BigEndian.Uint16(h[:2]))
		c.padding = int(binary.BigEndian.Uint16(h[2:]))
		c.reads++
	}
}
func (c *genericPaddingConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		if c.writes == 16 {
			n, err := c.Conn.Write(p)
			return written + n, err
		}
		n := min(len(p), 65535)
		padding := 256 + rand.IntN(512)
		size := 4 + n + padding
		if cap(c.buffer) < size {
			c.buffer = make([]byte, size)
		}
		b := c.buffer[:size]
		binary.BigEndian.PutUint16(b, uint16(n))
		binary.BigEndian.PutUint16(b[2:], uint16(padding))
		copy(b[4:], p[:n])
		clear(b[4+n:])
		if err := writeAll(c.Conn, b); err != nil {
			return written, err
		}
		c.writes++
		written += n
		p = p[n:]
		if c.writes == 16 {
			c.buffer = nil
		}
	}
	return written, nil
}
