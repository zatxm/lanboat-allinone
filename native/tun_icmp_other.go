//go:build !linux && !darwin && !windows

package native

import "syscall"

func setICMPTTL(raw syscall.RawConn, ipv6 bool, ttl int) error { return nil }
