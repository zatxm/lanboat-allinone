package native

import (
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

func tsRenameat2Trap() uintptr {
	switch runtime.GOARCH {
	case "amd64":
		return 316
	case "arm64", "riscv64", "loong64":
		return 276
	case "386":
		return 353
	case "arm":
		return 382
	case "ppc64", "ppc64le":
		return 357
	case "s390x":
		return 347
	}
	return ^uintptr(0)
}
func tsSFTPMetadata(info os.FileInfo) (uint32, uint32, uint32) {
	if s, ok := info.Sys().(*syscall.Stat_t); ok {
		return s.Uid, s.Gid, uint32(s.Atim.Sec)
	}
	return 0, 0, uint32(info.ModTime().Unix())
}
func tsSFTPChtimes(f *os.File, a, m time.Time) error {
	return syscall.Futimes(int(f.Fd()), []syscall.Timeval{syscall.NsecToTimeval(a.UnixNano()), syscall.NsecToTimeval(m.UnixNano())})
}
func tsSFTPRename(old, new string, replace bool) error {
	if replace {
		return os.Rename(old, new)
	}
	// renameat2 prevents a concurrent writer from turning a no-replace request into an overwrite.
	src, e := syscall.BytePtrFromString(old)
	if e != nil {
		return e
	}
	dst, e := syscall.BytePtrFromString(new)
	if e != nil {
		return e
	}
	_, _, errno := syscall.Syscall6(tsRenameat2Trap(), ^uintptr(99), uintptr(unsafe.Pointer(src)), ^uintptr(99), uintptr(unsafe.Pointer(dst)), 1, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
