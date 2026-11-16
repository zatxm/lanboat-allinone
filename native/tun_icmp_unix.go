//go:build linux || darwin

package native

import "syscall"

func setICMPTTL(raw syscall.RawConn, ipv6 bool, ttl int) error {
	var optionErr error
	e := raw.Control(func(fd uintptr) {
		if ipv6 {
			optionErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
		} else {
			optionErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		}
	})
	if e != nil {
		return e
	}
	return optionErr
}
