package native

import (
	"strings"
	"syscall"
)

func dialSocketOptions(o DialOptions, network string, raw syscall.RawConn) error {
	var result error
	err := raw.Control(func(fd uintptr) {
		set := func(level, option, value int) {
			if result == nil {
				result = syscall.SetsockoptInt(int(fd), level, option, value)
			}
		}
		if strings.HasPrefix(network, "udp") {
			// Darwin's default 9216-byte send buffer rejects larger UDP datagrams.
			var size int
			size, result = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
			if result == nil && size < 1<<16 {
				set(syscall.SOL_SOCKET, syscall.SO_SNDBUF, 1<<16)
			}
		}
		if o.ReuseAddr {
			set(syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		}
		if strings.HasPrefix(network, "tcp") && o.TCPFastOpen {
			set(syscall.IPPROTO_TCP, 0x105, 1) // TCP_FASTOPEN
		}
		if strings.HasPrefix(network, "udp") && o.UDPFragment != nil {
			value := 1
			if *o.UDPFragment {
				value = 0
			}
			if strings.HasSuffix(network, "6") {
				set(syscall.IPPROTO_IPV6, 62, value) // IPV6_DONTFRAG
			} else {
				set(syscall.IPPROTO_IP, 28, value) // IP_DONTFRAG
			}
		}
	})
	if err != nil {
		return err
	}
	return result
}

func listenSocketOptions(o DialOptions, network string, raw syscall.RawConn) error {
	if err := dialSocketOptions(o, network, raw); err != nil {
		return err
	}
	if !o.ReuseAddr {
		return nil
	}
	var result error
	err := raw.Control(func(fd uintptr) { result = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 0x200, 1) }) // SO_REUSEPORT
	if err != nil {
		return err
	}
	return result
}
