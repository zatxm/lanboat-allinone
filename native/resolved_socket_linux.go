package native

import (
	"net"
	"syscall"
)

func resolvedBindLink(raw syscall.RawConn, index int32) error {
	link, e := net.InterfaceByIndex(int(index))
	if e != nil {
		return e
	}
	var option error
	e = raw.Control(func(fd uintptr) {
		option = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, link.Name)
	})
	if e != nil {
		return e
	}
	return option
}
