//go:build linux

package native

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"reflect"
	"syscall"
	"unsafe"
)

func setTCPBrutal(conn net.Conn, rate uint64) error {
	if rate < 65536 || rate > 125000000000 {
		return errors.New("TCP Brutal rate is outside the kernel range")
	}
	// Unwrap only real TCP carriers; a logical multiplex stream is not a kernel socket.
	for depth := 0; depth < 64; depth++ {
		if tcp, ok := conn.(*net.TCPConn); ok {
			raw, err := tcp.SyscallConn()
			if err != nil {
				return err
			}
			var cause error
			err = raw.Control(func(fd uintptr) {
				if cause = syscall.SetsockoptString(int(fd), syscall.IPPROTO_TCP, syscall.TCP_CONGESTION, "brutal"); cause != nil {
					return
				}
				// The 12-byte v1 ABI also works with v2 kernels (no application group).
				var params [12]byte
				binary.NativeEndian.PutUint64(params[:], rate)
				binary.NativeEndian.PutUint32(params[8:], 20)
				_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, fd, syscall.IPPROTO_TCP, 23301, uintptr(unsafe.Pointer(&params[0])), uintptr(len(params)), 0)
				if errno != 0 {
					cause = errno
				}
			})
			if err != nil {
				return err
			}
			if cause != nil {
				return fmt.Errorf("TCP Brutal requires the installed brutal kernel module: %w", cause)
			}
			return nil
		}
		if c, ok := conn.(interface{ NetConn() net.Conn }); ok {
			conn = c.NetConn()
			continue
		}
		value := reflect.ValueOf(conn)
		if value.Kind() == reflect.Pointer && !value.IsNil() {
			value = value.Elem()
			if value.Kind() == reflect.Struct {
				field := value.FieldByName("Conn")
				if field.IsValid() && field.CanInterface() {
					if next, ok := field.Interface().(net.Conn); ok {
						conn = next
						continue
					}
				}
			}
		}
		return errors.New("TCP Brutal requires a physical TCP carrier; nested multiplex transports are unsupported")
	}
	return errors.New("TCP Brutal carrier nesting exceeds limit")
}
