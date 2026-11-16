//go:build linux || darwin

package native

import (
	"fmt"
	"os"
	"syscall"
)

func lockStateFile(name string) (*os.File, error) {
	f, e := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, fmt.Errorf("state file is already in use: %w", e)
	}
	return f, nil
}
