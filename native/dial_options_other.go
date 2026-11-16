//go:build !linux && !darwin && !windows

package native

import (
	"errors"
	"syscall"
)

func dialSocketOptions(o DialOptions, network string, raw syscall.RawConn) error {
	if o.TCPFastOpen || o.UDPFragment != nil || o.ReuseAddr {
		return errors.New("explicit fast open, fragmentation and address reuse require Linux")
	}
	return nil
}

func listenSocketOptions(o DialOptions, network string, raw syscall.RawConn) error {
	return dialSocketOptions(o, network, raw)
}
