//go:build windows

package native

import (
	"crypto/rand"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"go.uber.org/zap"
)

type wfpDisplay struct{ Name, Description *uint16 }
type wfpBlob struct {
	Size uint32
	Data *byte
}
type wfpValue struct {
	Type  uint32
	Value uintptr
}
type wfpCondition struct {
	Key   syscall.GUID
	Match uint32
	Value wfpValue
}
type wfpSession struct {
	Key                 syscall.GUID
	Display             wfpDisplay
	Flags, Timeout, PID uint32
	SID, User           uintptr
	KernelMode          int32
}
type wfpSublayer struct {
	Key      syscall.GUID
	Display  wfpDisplay
	Flags    uint32
	Provider *syscall.GUID
	Data     wfpBlob
	Weight   uint16
}
type wfpAction struct {
	Type uint32
	Key  syscall.GUID
}
type wfpFilter struct {
	Key             syscall.GUID
	Display         wfpDisplay
	Flags           uint32
	Provider        *syscall.GUID
	Data            wfpBlob
	Layer, Sublayer syscall.GUID
	Weight          wfpValue
	Count           uint32
	Conditions      *wfpCondition
	Action          wfpAction
	Context         [2]uint64
	Reserved        *syscall.GUID
	ID              uint64
	EffectiveWeight wfpValue
}

// Dynamic WFP objects disappear even if the process terminates before Close.
func (t *tunTunnel) blockDNSLeak() error {
	dll := syscall.NewLazyDLL("fwpuclnt.dll")
	var engine syscall.Handle
	name, _ := syscall.UTF16PtrFromString("Lanboat TUN DNS")
	session := wfpSession{Display: wfpDisplay{Name: name}, Flags: 1}
	code, _, _ := dll.NewProc("FwpmEngineOpen0").Call(0, 10, 0, uintptr(unsafe.Pointer(&session)), uintptr(unsafe.Pointer(&engine)))
	if code != 0 {
		return fmt.Errorf("open WFP: %w", syscall.Errno(code))
	}
	success := false
	defer func() {
		if !success {
			dll.NewProc("FwpmEngineClose0").Call(uintptr(engine))
		}
	}()
	var key syscall.GUID
	if _, e := rand.Read(unsafe.Slice((*byte)(unsafe.Pointer(&key)), 16)); e != nil {
		return e
	}
	sublayer := wfpSublayer{Key: key, Display: wfpDisplay{Name: name}, Weight: 0xffff}
	code, _, _ = dll.NewProc("FwpmSubLayerAdd0").Call(uintptr(engine), uintptr(unsafe.Pointer(&sublayer)), 0)
	if code != 0 {
		return fmt.Errorf("add WFP sublayer: %w", syscall.Errno(code))
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	path, _ := syscall.UTF16PtrFromString(exe)
	var app *wfpBlob
	code, _, _ = dll.NewProc("FwpmGetAppIdFromFileName0").Call(uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&app)))
	if code != 0 {
		return fmt.Errorf("get WFP app identity: %w", syscall.Errno(code))
	}
	defer dll.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&app)))
	luid := t.device.(*wintunDevice).luid
	conditions := []wfpCondition{
		{Key: syscall.GUID{Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a, Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}}, Value: wfpValue{Type: 2, Value: 53}},
		{Key: syscall.GUID{Data1: 0x4cd62a49, Data2: 0x59c3, Data3: 0x4969, Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}}, Match: 10, Value: wfpValue{Type: 4, Value: uintptr(unsafe.Pointer(&luid))}},
		{Key: syscall.GUID{Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5, Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}}, Match: 10, Value: wfpValue{Type: 12, Value: uintptr(unsafe.Pointer(app))}},
	}
	layers := []syscall.GUID{
		{Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33, Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}},
		{Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc, Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}},
	}
	for _, layer := range layers {
		filter := wfpFilter{Display: wfpDisplay{Name: name}, Layer: layer, Sublayer: key, Weight: wfpValue{Type: 1, Value: 15}, Count: uint32(len(conditions)), Conditions: &conditions[0], Action: wfpAction{Type: 0x1001}}
		code, _, _ = dll.NewProc("FwpmFilterAdd0").Call(uintptr(engine), uintptr(unsafe.Pointer(&filter)), 0, 0)
		if code != 0 {
			return fmt.Errorf("add WFP DNS filter: %w", syscall.Errno(code))
		}
	}
	runtime.KeepAlive(app)
	runtime.KeepAlive(luid)
	runtime.KeepAlive(conditions)
	previous := t.cleanup
	t.cleanup = func() {
		code, _, _ := dll.NewProc("FwpmEngineClose0").Call(uintptr(engine))
		if code != 0 {
			t.runtime.logger.Warn("restore TUN DNS filters", zap.Uint64("code", uint64(code)))
		}
		previous()
	}
	success = true
	return nil
}
