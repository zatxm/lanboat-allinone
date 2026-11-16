//go:build !windows

package native

import (
	"runtime"
	"syscall"
)

func mdnsSocketOptions(fd uintptr, path mdnsPath, mark uint32) error {
	socket := int(fd)
	if runtime.GOOS == "linux" && mark != 0 {
		if err := syscall.SetsockoptInt(socket, syscall.SOL_SOCKET, 36, int(mark)); err != nil {
			return err
		}
	}
	if path.local.Is4() {
		if err := syscall.SetsockoptInet4Addr(socket, syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, path.local.As4()); err != nil {
			return err
		}
		return syscall.SetsockoptByte(socket, syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, 255)
	}
	if err := syscall.SetsockoptInt(socket, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, path.index); err != nil {
		return err
	}
	return syscall.SetsockoptInt(socket, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_HOPS, 255)
}
