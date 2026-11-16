//go:build !windows

package native

import "syscall"

func kcpSocketTraffic(fd uintptr, value int) error {
	address, err := syscall.Getsockname(int(fd))
	if err != nil {
		return err
	}
	level, option := syscall.IPPROTO_IP, syscall.IP_TOS
	if _, ok := address.(*syscall.SockaddrInet6); ok {
		level, option = syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS
	}
	return syscall.SetsockoptInt(int(fd), level, option, value)
}
