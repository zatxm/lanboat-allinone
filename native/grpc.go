package native

import (
	"bytes"
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
	status          func() string
}

func (c *grpcConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.pending) == 0 {
		var header [5]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
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
		reader := bytes.NewReader(message)
		for reader.Len() > 0 {
			tag, err := binary.ReadUvarint(reader)
			if err != nil {
				return 0, err
			}
			if tag != 10 {
				return 0, errors.New("invalid gRPC Hunk field")
			}
			length, err := binary.ReadUvarint(reader)
			if err != nil || length > uint64(reader.Len()) {
				return 0, errors.New("invalid gRPC Hunk length")
			}
			start := len(message) - reader.Len()
			c.pending = message[start : start+int(length)]
			reader.Seek(int64(length), io.SeekCurrent)
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
	buffer := buffers.Get().([]byte)
	defer buffers.Put(buffer)
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
