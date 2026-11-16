package native

import (
	"encoding/binary"
	"syscall"
)

func dhcpSocketOptions(fd uintptr, path dhcpDNSPath, _ uint32) error {
	socket := syscall.Handle(fd)
	for _, opt := range []int{syscall.SO_REUSEADDR, syscall.SO_BROADCAST} {
		if err := syscall.SetsockoptInt(socket, syscall.SOL_SOCKET, opt, 1); err != nil {
			return err
		}
	}
	var index [4]byte
	binary.BigEndian.PutUint32(index[:], uint32(path.iface.Index))
	return syscall.SetsockoptInt(socket, syscall.IPPROTO_IP, 31, int(binary.NativeEndian.Uint32(index[:]))) // IP_UNICAST_IF
}
