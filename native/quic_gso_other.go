//go:build !linux

package native

import "net"

func quicGSOSupported(*net.UDPConn) bool { return false }

func appendQUICGSOControl(b []byte, _ int) []byte { return b }
