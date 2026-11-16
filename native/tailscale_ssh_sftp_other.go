//go:build !linux && !darwin

package native

import (
	"os"
	"time"
)

func tsSFTPMetadata(info os.FileInfo) (uint32, uint32, uint32) {
	return 0, 0, uint32(info.ModTime().Unix())
}
func tsSFTPChtimes(*os.File, time.Time, time.Time) error { return os.ErrInvalid }
func tsSFTPRename(old, new string, replace bool) error {
	if replace {
		return os.Rename(old, new)
	}
	return os.ErrInvalid
}
