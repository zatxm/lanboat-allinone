package native

import (
	"syscall"
	"time"
	"unsafe"
)

func tcpFragmentRTT(fd uintptr) time.Duration {
	var info [256]byte
	size := uint32(len(info))
	_, _, err := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_TCP, 0x106, uintptr(unsafe.Pointer(&info[0])), uintptr(unsafe.Pointer(&size)), 0)
	if err != 0 {
		return 0
	}
	return tcpFragmentRTTValue(info[:min(size, uint32(len(info)))], 44, time.Millisecond)
}
