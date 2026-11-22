package native

import (
	"net"
	"unsafe"
)

func (t *tunTunnel) windowsTUNLUID() uint64 {
	if d, ok := t.device.(*wintunDevice); ok {
		return d.luid
	}
	iface, err := net.InterfaceByName(t.name)
	if err != nil {
		return 0
	}
	var luid uint64
	tunIPHelper.NewProc("ConvertInterfaceIndexToLuid").Call(uintptr(iface.Index), uintptr(unsafe.Pointer(&luid)))
	return luid
}

func (t *tunTunnel) prepareDesktopEgress() error {
	if err := t.runtime.refreshWindowsEgress(t.windowsTUNLUID()); err != nil {
		return err
	}
	t.runtime.tunRouting.Store(true)
	return nil
}
