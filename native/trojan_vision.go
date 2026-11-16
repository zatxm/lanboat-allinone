package native

import (
	"crypto/sha256"
	"errors"
	"io"
	"net"
)

// Native extension v1: distinct commands prevent a standard peer from treating
// padding as application data. The TLS-protected acknowledgement prevents downgrade.
const trojanVisionAck = "LBTV\x01"

func trojanVisionID(password string) (id [16]byte) {
	sum := sha256.Sum256([]byte("Lanboat Trojan Vision v1\x00" + password))
	copy(id[:], sum[:16])
	return
}

func trojanVisionClient(c net.Conn, password string) (net.Conn, error) {
	var ack [5]byte
	if _, err := io.ReadFull(c, ack[:]); err != nil {
		return nil, err
	}
	if string(ack[:]) != trojanVisionAck {
		return nil, errors.New("Trojan Vision peer did not acknowledge v1")
	}
	return newVisionConn(c, trojanVisionID(password))
}

func trojanVisionServer(c net.Conn, password string) (net.Conn, error) {
	v, err := newVisionConn(c, trojanVisionID(password))
	if err != nil {
		return nil, err
	}
	if err = writeAll(c, []byte(trojanVisionAck)); err != nil {
		return nil, err
	}
	return v, nil
}
