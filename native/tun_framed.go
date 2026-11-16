package native

import (
	"encoding/binary"
	"errors"
	"io"
)

// utun uses a network-order address-family word before every IP packet.
type framedTUN struct {
	io.ReadWriteCloser
	readBuffer, writeBuffer [65579]byte
}

func (d *framedTUN) Read(b []byte) (int, error) {
	n, e := d.ReadWriteCloser.Read(d.readBuffer[:])
	if e != nil {
		return 0, e
	}
	if n < 5 {
		return 0, errors.New("truncated utun packet")
	}
	family := binary.BigEndian.Uint32(d.readBuffer[:4])
	if family != 2 && family != 30 || family == 2 && d.readBuffer[4]>>4 != 4 || family == 30 && d.readBuffer[4]>>4 != 6 {
		return 0, errors.New("invalid utun address family")
	}
	if n-4 > len(b) {
		return 0, io.ErrShortBuffer
	}
	return copy(b, d.readBuffer[4:n]), nil
}
func (d *framedTUN) Write(b []byte) (int, error) {
	if len(b) == 0 || len(b) > 65575 {
		return 0, errors.New("invalid utun packet size")
	}
	family := uint32(2)
	if b[0]>>4 == 6 {
		family = 30
	} else if b[0]>>4 != 4 {
		return 0, errors.New("invalid utun IP version")
	}
	binary.BigEndian.PutUint32(d.writeBuffer[:4], family)
	copy(d.writeBuffer[4:], b)
	n, e := d.ReadWriteCloser.Write(d.writeBuffer[:4+len(b)])
	if e == nil && n != 4+len(b) {
		e = io.ErrShortWrite
	}
	return max(0, n-4), e
}
