//go:build linux

package native

import (
	"os"
	"syscall"
)

func (t *tunTunnel) configureMonitor() error {
	if t.namespace != nil {
		return nil
	}
	if !t.in.AutoRoute {
		return nil
	}
	fd, e := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if e != nil {
		return e
	}
	if e = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: 1 | 16 | 64 | 256 | 1024}); e != nil {
		syscall.Close(fd)
		return e
	}
	if e = syscall.SetNonblock(fd, true); e != nil {
		syscall.Close(fd)
		return e
	}
	f := os.NewFile(uintptr(fd), "lanboat-network-events")
	if t.runtime.namespaceKernelOnly {
		t.namespaceMonitor = f
	}
	previous := t.cleanup
	t.cleanup = func() { f.Close(); previous() }
	events := make(chan struct{}, 1)
	t.networkEvents = events
	t.monitor = func() { b := make([]byte, 65536); t.watchNetwork(func() error { _, e := f.Read(b); return e }, events) }
	// Linux's protected sockets follow the current kernel default route on every new dial.
	t.refreshEgress = func() error { t.refreshNetworkDNS(); return nil }
	return nil
}
