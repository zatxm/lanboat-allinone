package native

import (
	"net"
	"syscall"
	"unsafe"
)

func waitUDPReadable(c *net.UDPConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var ioctlErr error
	waited := false
	err = raw.Read(func(fd uintptr) bool {
		var available, returned uint32
		ioctlErr = syscall.WSAIoctl(syscall.Handle(fd), 0x4004667f, nil, 0, (*byte)(unsafe.Pointer(&available)), 4, &returned, nil, 0) // FIONREAD
		ready := ioctlErr != nil || available != 0 || waited
		waited = true
		return ready
	})
	if err != nil {
		return err
	}
	return ioctlErr
}
