package native

import (
	"syscall"
	"time"
	"unsafe"
)

func tcpFragmentRTT(fd uintptr) time.Duration {
	var info [128]byte
	var version, size uint32
	err := syscall.WSAIoctl(syscall.Handle(fd), 0xd8000027, (*byte)(unsafe.Pointer(&version)), 4, &info[0], uint32(len(info)), &size, nil, 0)
	if err != nil {
		return 0
	}
	return tcpFragmentRTTValue(info[:min(size, uint32(len(info)))], 20, time.Microsecond)
}
