package native

import "syscall"

func quicSocketDF(fd uintptr) error {
	// PROBE sets DF while allowing probes above a cached ICMP-derived PMTU.
	if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_PROBE); err != nil {
		return err
	}
	address, err := syscall.Getsockname(int(fd))
	if err != nil {
		return err
	}
	if _, ipv6 := address.(*syscall.SockaddrInet6); ipv6 {
		return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MTU_DISCOVER, syscall.IP_PMTUDISC_PROBE)
	}
	return nil
}
