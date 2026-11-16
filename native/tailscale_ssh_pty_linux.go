package native

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"unsafe"
)

func tsSSHOpenPTY(u *user.User, w, h uint32, modes []byte) (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			master.Close()
			if slave != nil {
				slave.Close()
			}
		}
	}()
	var zero, number uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&zero))); e != 0 {
		err = e
		return
	}
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&number))); e != 0 {
		err = e
		return
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return
	}
	if os.Geteuid() == 0 {
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		if err = slave.Chown(uid, gid); err != nil {
			return
		}
	}
	if err = slave.Chmod(0600); err != nil {
		return
	}
	if err = tsSSHResize(master, w, h); err != nil {
		return
	}
	var state syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, slave.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&state))); e != 0 {
		err = e
		return
	}
	err = tsSSHTerminalModes(modes, func(op byte, v uint32) {
		cc := map[byte]int{1: syscall.VINTR, 2: syscall.VQUIT, 3: syscall.VERASE, 4: syscall.VKILL, 5: syscall.VEOF, 6: syscall.VEOL, 7: syscall.VEOL2, 8: syscall.VSTART, 9: syscall.VSTOP, 10: syscall.VSUSP, 12: syscall.VREPRINT, 13: syscall.VWERASE, 14: syscall.VLNEXT}
		if i, ok := cc[op]; ok {
			state.Cc[i] = byte(v)
			return
		}
		set := func(field *uint32, flag uint32) {
			if v == 0 {
				*field &= ^flag
			} else {
				*field |= flag
			}
		}
		switch op {
		case 30:
			set(&state.Iflag, syscall.IGNPAR)
		case 31:
			set(&state.Iflag, syscall.PARMRK)
		case 32:
			set(&state.Iflag, syscall.INPCK)
		case 33:
			set(&state.Iflag, syscall.ISTRIP)
		case 34:
			set(&state.Iflag, syscall.INLCR)
		case 35:
			set(&state.Iflag, syscall.IGNCR)
		case 36:
			set(&state.Iflag, syscall.ICRNL)
		case 38:
			set(&state.Iflag, syscall.IXON)
		case 39:
			set(&state.Iflag, syscall.IXANY)
		case 40:
			set(&state.Iflag, syscall.IXOFF)
		case 50:
			set(&state.Lflag, syscall.ISIG)
		case 51:
			set(&state.Lflag, syscall.ICANON)
		case 53:
			set(&state.Lflag, syscall.ECHO)
		case 54:
			set(&state.Lflag, syscall.ECHOE)
		case 55:
			set(&state.Lflag, syscall.ECHOK)
		case 56:
			set(&state.Lflag, syscall.ECHONL)
		case 57:
			set(&state.Lflag, syscall.NOFLSH)
		case 58:
			set(&state.Lflag, syscall.TOSTOP)
		case 59:
			set(&state.Lflag, syscall.IEXTEN)
		case 70:
			set(&state.Oflag, syscall.OPOST)
		case 72:
			set(&state.Oflag, syscall.ONLCR)
		case 73:
			set(&state.Oflag, syscall.OCRNL)
		case 74:
			set(&state.Oflag, syscall.ONOCR)
		case 75:
			set(&state.Oflag, syscall.ONLRET)
		case 92:
			set(&state.Cflag, syscall.PARENB)
		case 93:
			set(&state.Cflag, syscall.PARODD)
		}
	})
	if err != nil {
		return
	}
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, slave.Fd(), syscall.TCSETS, uintptr(unsafe.Pointer(&state))); e != 0 {
		err = e
	}
	return
}
func tsSSHResize(f *os.File, w, h uint32) error {
	if w == 0 {
		w = 80
	}
	if h == 0 {
		h = 24
	}
	size := [4]uint16{uint16(min(h, 65535)), uint16(min(w, 65535)), 0, 0}
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(&size)))
	if e != 0 {
		return e
	}
	return nil
}
