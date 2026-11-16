package native

import "syscall"

func dhcpSocketOptions(fd uintptr, path dhcpDNSPath, mark uint32) error {
	socket := int(fd)
	for _, opt := range []int{syscall.SO_REUSEADDR, syscall.SO_BROADCAST} {
		if err := syscall.SetsockoptInt(socket, syscall.SOL_SOCKET, opt, 1); err != nil {
			return err
		}
	}
	if mark != 0 {
		if err := syscall.SetsockoptInt(socket, syscall.SOL_SOCKET, 36, int(mark)); err != nil {
			return err
		}
	}
	return syscall.SetsockoptString(socket, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, path.iface.Name)
}
