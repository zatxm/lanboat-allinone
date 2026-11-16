package native

import "syscall"

func quicSocketDF(fd uintptr) error {
	address, err := syscall.Getsockname(int(fd))
	if err != nil {
		return err
	}
	if _, ipv6 := address.(*syscall.SockaddrInet6); ipv6 {
		return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, 62, 1) // IPV6_DONTFRAG
	}
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 28, 1) // IP_DONTFRAG
}
