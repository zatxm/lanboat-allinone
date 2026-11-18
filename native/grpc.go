package native

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// The Tun RPC carries Hunk messages with a single length-delimited data field.
type grpcConn struct {
	net.Conn
	readMu, writeMu sync.Mutex
	pending         []byte
	frame           []byte
	// header is envelope scratch guarded by readMu; a local would escape.
	header [5]byte
	status func() string
}

var errGRPCVarint = errors.New("binary: varint overflows a 64-bit integer")

// grpcUvarint decodes a varint with binary.ReadUvarint's errors, without a reader.
func grpcUvarint(b []byte) (uint64, int, error) {
	v, n := binary.Uvarint(b)
	if n == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	if n < 0 {
		return 0, 0, errGRPCVarint
	}
	return v, n, nil
}

func (c *grpcConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.pending) == 0 {
		header := c.header[:]
		if _, err := io.ReadFull(c.Conn, header); err != nil {
			if err == io.EOF && c.status != nil {
				if status := c.status(); status != "0" {
					return 0, fmt.Errorf("gRPC stream ended with status %q", status)
				}
			}
			return 0, err
		}
		size := binary.BigEndian.Uint32(header[1:])
		if header[0] != 0 || size > 1<<20 {
			return 0, errors.New("invalid gRPC envelope or message limit exceeded")
		}
		if size == 0 {
			continue
		}
		if cap(c.frame) < int(size) {
			c.frame = make([]byte, int(size))
		}
		message := c.frame[:int(size)]
		if _, err := io.ReadFull(c.Conn, message); err != nil {
			return 0, err
		}
		rest := message
		for len(rest) > 0 {
			tag, n, err := grpcUvarint(rest)
			if err != nil {
				return 0, err
			}
			if tag != 10 {
				return 0, errors.New("invalid gRPC Hunk field")
			}
			rest = rest[n:]
			length, n, err := grpcUvarint(rest)
			if err != nil || length > uint64(len(rest)-n) {
				return 0, errors.New("invalid gRPC Hunk length")
			}
			rest = rest[n:]
			c.pending = rest[:length]
			rest = rest[length:]
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *grpcConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	owner := buffers.Get().(*[32 * 1024]byte)
	defer buffers.Put(owner)
	buffer := owner[:]
	for len(p) > 0 {
		n := min(len(p), len(buffer)-10)
		packet := append(buffer[:0], 0, 0, 0, 0, 0, 10)
		packet = binary.AppendUvarint(packet, uint64(n))
		packet = append(packet, p[:n]...)
		binary.BigEndian.PutUint32(packet[1:5], uint32(len(packet)-5))
		if err := writeAll(c.Conn, packet); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}
func (c *grpcConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}
