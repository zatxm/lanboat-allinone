package native

import "syscall"

func quicSocketDF(fd uintptr) error {
	h := syscall.Handle(fd)
	address, err := syscall.Getsockname(h)
	if err != nil {
		return err
	}
	level := syscall.IPPROTO_IP
	if _, ipv6 := address.(*syscall.SockaddrInet6); ipv6 {
		level = syscall.IPPROTO_IPV6
	}
	return syscall.SetsockoptInt(h, level, 14, 1) // IP_DONTFRAGMENT / IPV6_DONTFRAG
}
