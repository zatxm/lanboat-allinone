package native

import "syscall"

func dhcpSocketOptions(fd uintptr, path dhcpDNSPath, _ uint32) error {
	socket := int(fd)
	for _, opt := range []int{syscall.SO_REUSEADDR, syscall.SO_REUSEPORT, syscall.SO_BROADCAST} {
		if err := syscall.SetsockoptInt(socket, syscall.SOL_SOCKET, opt, 1); err != nil {
			return err
		}
	}
	return syscall.SetsockoptInt(socket, syscall.IPPROTO_IP, 25, path.iface.Index) // IP_BOUND_IF
}
