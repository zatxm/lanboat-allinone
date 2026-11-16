//go:build !linux

package native

import (
	"errors"
	"net"
)

func setTCPBrutal(net.Conn, uint64) error {
	return errors.New("TCP Brutal kernel acceleration requires Linux")
}
