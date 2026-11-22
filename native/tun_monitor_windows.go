//go:build windows

package native

import (
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

var tunWindowsWatches sync.Map
var tunWindowsWatchID atomic.Uintptr
var tunWindowsNotify = syscall.NewCallback(func(token, row, kind uintptr) uintptr {
	if v, ok := tunWindowsWatches.Load(token); ok {
		select {
		case v.(chan struct{}) <- struct{}{}:
		default:
		}
	}
	return 0
})

func (t *tunTunnel) configureMonitor() error {
	if !t.in.AutoRoute {
		return nil
	}
	events := make(chan struct{}, 1)
	token := tunWindowsWatchID.Add(1)
	tunWindowsWatches.Store(token, events)
	var handles []uintptr
	cancel := func() {
		for _, h := range handles {
			tunIPHelper.NewProc("CancelMibChangeNotify2").Call(h)
		}
		tunWindowsWatches.Delete(token)
	}
	for _, name := range []string{"NotifyRouteChange2", "NotifyUnicastIpAddressChange"} {
		var handle uintptr
		code, _, _ := tunIPHelper.NewProc(name).Call(0, tunWindowsNotify, token, 0, uintptr(unsafe.Pointer(&handle)))
		if code != 0 {
			cancel()
			return syscall.Errno(code)
		}
		handles = append(handles, handle)
	}
	previous := t.cleanup
	t.cleanup = func() { cancel(); previous() }
	t.networkEvents = events
	t.refreshEgress = func() error {
		if e := t.runtime.refreshWindowsEgress(t.windowsTUNLUID()); e != nil {
			return e
		}
		t.refreshNetworkDNS()
		return nil
	}
	return nil
}
