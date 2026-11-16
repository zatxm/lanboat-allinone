package native

import "syscall"

func kcpSocketTraffic(fd uintptr, value int) error {
	address, err := syscall.Getsockname(syscall.Handle(fd))
	if err != nil {
		return err
	}
	level, option := syscall.IPPROTO_IP, 3
	if _, ok := address.(*syscall.SockaddrInet6); ok {
		level, option = syscall.IPPROTO_IPV6, 39
	}
	return syscall.SetsockoptInt(syscall.Handle(fd), level, option, value)
}
