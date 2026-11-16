//go:build !linux

package native

import "syscall"

func resolvedBindLink(raw syscall.RawConn, index int32) error {
	return resolvedUnsupported("resolved link binding requires Linux")
}
