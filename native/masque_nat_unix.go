//go:build linux || darwin

package native

import (
	"net"
	"syscall"
)

// Peek without consuming: allocate the large payload buffer only after netpoll
// reports a packet. Idle NAT mappings then retain neither a 64KiB buffer nor a timer goroutine.
func masqueWaitPacket(c *net.UDPConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var one [1]byte
	var receiveErr error
	err = raw.Read(func(fd uintptr) bool {
		for {
			_, _, receiveErr = syscall.Recvfrom(int(fd), one[:], syscall.MSG_PEEK)
			if receiveErr != syscall.EINTR {
				break
			}
		}
		return receiveErr != syscall.EAGAIN && receiveErr != syscall.EWOULDBLOCK
	})
	if err != nil {
		return err
	}
	return receiveErr
}
