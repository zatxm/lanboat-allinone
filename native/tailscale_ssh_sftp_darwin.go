package native

import (
	"os"
	"syscall"
	"time"
	"unsafe"
)

func tsSFTPMetadata(info os.FileInfo) (uint32, uint32, uint32) {
	if s, ok := info.Sys().(*syscall.Stat_t); ok {
		return s.Uid, s.Gid, uint32(s.Atimespec.Sec)
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
	src, e := syscall.BytePtrFromString(old)
	if e != nil {
		return e
	}
	dst, e := syscall.BytePtrFromString(new)
	if e != nil {
		return e
	}
	_, _, errno := syscall.Syscall6(488, ^uintptr(1), uintptr(unsafe.Pointer(src)), ^uintptr(1), uintptr(unsafe.Pointer(dst)), 4, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
