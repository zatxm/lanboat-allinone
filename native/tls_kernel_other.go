//go:build !linux

package native

import (
	"errors"
	"net"
)

func installKernelTLS(net.Conn, *stTLS13, bool, bool) (*kernelTLS, error) {
	return nil, errors.New("kernel TLS requires Linux")
}
func (*kernelTLS) setKey(*stTLS13, bool) error { return errors.New("kernel TLS requires Linux") }
func (*kernelTLS) send(byte, []byte) (uint64, error) {
	return 0, errors.New("kernel TLS requires Linux")
}
func (*kernelTLS) receive([]byte) (byte, int, error) {
	return 0, 0, errors.New("kernel TLS requires Linux")
}
