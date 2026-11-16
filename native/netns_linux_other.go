//go:build linux && !amd64

package native

import "syscall"

const namespaceSetns = syscall.SYS_SETNS
