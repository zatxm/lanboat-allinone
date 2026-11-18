//go:build linux

package native

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"
)

// solUDP and udpSegment are Linux SOL_UDP and UDP_SEGMENT (UDP generic
// segmentation offload); the syscall package does not export them.
const (
	solUDP     = 17
	udpSegment = 103
)

func quicGSOSupported(c *net.UDPConn) bool {
	raw, err := c.SyscallConn()
	if err != nil {
		return false
	}
	supported := false
	_ = raw.Control(func(fd uintptr) {
		_, err := syscall.GetsockoptInt(int(fd), solUDP, udpSegment)
		supported = err == nil
	})
	return supported
}

func appendQUICGSOControl(b []byte, segment int) []byte {
	start := len(b)
	b = append(b, make([]byte, syscall.CmsgSpace(2))...)
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&b[start]))
	h.Level = solUDP
	h.Type = udpSegment
	h.SetLen(syscall.CmsgLen(2))
	binary.NativeEndian.PutUint16(b[start+syscall.CmsgLen(0):], uint16(segment))
	return b
}
