package native

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func lockStateFile(name string) (*os.File, error) {
	f, e := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	var overlapped syscall.Overlapped
	result, _, err := syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx").Call(f.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if result == 0 {
		f.Close()
		return nil, fmt.Errorf("state file is already in use: %w", err)
	}
	return f, nil
}
