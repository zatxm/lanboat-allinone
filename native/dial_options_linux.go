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
		if o.ReuseAddr {
			set(syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		}
		if o.BindAddressNoPort {
			set(syscall.IPPROTO_IP, 24, 1) // IP_BIND_ADDRESS_NO_PORT also applies to IPv6 sockets.
		}
		if strings.HasPrefix(network, "tcp") && o.TCPFastOpen {
			set(syscall.IPPROTO_TCP, 30, 1) // TCP_FASTOPEN_CONNECT
		}
		if strings.HasPrefix(network, "udp") && o.UDPFragment != nil {
			mode := 2 // IP_PMTUDISC_DO
			if *o.UDPFragment {
				mode = 0 // IP_PMTUDISC_DONT
			}
			if strings.HasSuffix(network, "6") {
				set(syscall.IPPROTO_IPV6, 23, mode)
			} else {
				set(syscall.IPPROTO_IP, 10, mode)
			}
		}
	})
	if err != nil {
		return err
	}
	return result
}

func listenSocketOptions(o DialOptions, network string, raw syscall.RawConn) error {
	fastOpen := o.TCPFastOpen
	o.TCPFastOpen = false
	if err := dialSocketOptions(o, network, raw); err != nil {
		return err
	}
	var result error
	err := raw.Control(func(fd uintptr) {
		if o.ReuseAddr {
			result = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 15, 1)
		} // SO_REUSEPORT
		if result == nil && fastOpen && strings.HasPrefix(network, "tcp") {
			result = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 23, 1024)
		} // server TCP_FASTOPEN queue
	})
	if err != nil {
		return err
	}
	return result
}
