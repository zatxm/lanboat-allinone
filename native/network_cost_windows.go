//go:build windows

package native

import (
	"runtime"
	"syscall"
	"unsafe"
)

func windowsNetworkCost(m *Metadata) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	library := syscall.NewLazyDLL("ole32.dll")
	if library.Load() != nil {
		return
	}
	code, _, _ := library.NewProc("CoInitializeEx").Call(0, 0)
	if uint32(code) > 1 && uint32(code) != 0x80010106 {
		return
	}
	if uint32(code) <= 1 {
		defer library.NewProc("CoUninitialize").Call()
	}
	clsid := syscall.GUID{Data1: 0xdcb00c01, Data2: 0x570f, Data3: 0x4a9b, Data4: [8]byte{0x8d, 0x69, 0x19, 0x9f, 0xdb, 0xa5, 0x72, 0x3b}}
	iid := syscall.GUID{Data1: 0xdcb00008, Data2: 0x570f, Data3: 0x4a9b, Data4: clsid.Data4}
	var object unsafe.Pointer
	code, _, _ = library.NewProc("CoCreateInstance").Call(uintptr(unsafe.Pointer(&clsid)), 0, 23, uintptr(unsafe.Pointer(&iid)), uintptr(unsafe.Pointer(&object)))
	if code != 0 || object == nil {
		return
	}
	methods := unsafe.Slice(*(**uintptr)(object), 5)
	defer syscall.SyscallN(methods[2], uintptr(object))
	var cost uint32
	code, _, _ = syscall.SyscallN(methods[3], uintptr(object), uintptr(unsafe.Pointer(&cost)), 0)
	if code == 0 {
		m.NetworkIsExpensive = cost&(2|4|0x10000|0x20000) != 0
	}
}
