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
				result = syscall.SetsockoptInt(syscall.Handle(fd), level, option, value)
			}
		}
		if o.ReuseAddr {
			set(syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		}
		if strings.HasPrefix(network, "tcp") && o.TCPFastOpen {
			set(syscall.IPPROTO_TCP, 15, 1) // TCP_FASTOPEN
		}
		if strings.HasPrefix(network, "udp") && o.UDPFragment != nil {
			value := 1
			if *o.UDPFragment {
				value = 0
			}
			level := syscall.IPPROTO_IP
			if strings.HasSuffix(network, "6") {
				level = syscall.IPPROTO_IPV6
			}
			set(level, 14, value) // IP_DONTFRAGMENT / IPV6_DONTFRAG
		}
	})
	if err != nil {
		return err
	}
	return result
}

func listenSocketOptions(o DialOptions, network string, raw syscall.RawConn) error {
	return dialSocketOptions(o, network, raw)
}
