// This init runs only inside the disposable ICMP test VM.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

func main() {
	if os.Getpid() != 1 {
		fmt.Fprintln(os.Stderr, "testicmp requires an isolated VM PID1")
		os.Exit(2)
	}
	code := 1
	defer func() {
		fmt.Printf("LANBOAT_ICMP_TEST_EXIT=%d\n", code)
		syscall.Sync()
		syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	}()
	for _, p := range []struct{ dst, kind string }{{"/proc", "proc"}, {"/sys", "sysfs"}, {"/dev", "devtmpfs"}} {
		os.MkdirAll(p.dst, 0755)
		if err := syscall.Mount(p.kind, p.dst, p.kind, 0, ""); err != nil {
			fmt.Println(err)
			return
		}
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		fmt.Println(err)
		return
	}
	var request [40]byte
	copy(request[:], "lo")
	binary.NativeEndian.PutUint16(request[16:], syscall.IFF_UP|syscall.IFF_LOOPBACK|syscall.IFF_RUNNING)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&request[0])))
	syscall.Close(fd)
	if errno != 0 {
		fmt.Println(errno)
		return
	}
	modules, err := os.ReadFile("/modules.list")
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, name := range strings.Fields(string(modules)) {
		b, err := os.ReadFile("/" + name + ".ko")
		if err != nil {
			fmt.Println(err)
			return
		}
		params := []byte{0}
		_, _, errno := syscall.Syscall(syscall.SYS_INIT_MODULE, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&params[0])))
		if errno != 0 {
			fmt.Println("module", name, errno)
			return
		}
	}
	os.MkdirAll("/tmp", 0700)
	cmd := exec.Command("/native.test", "-test.run", "^TestICMPTraceLinuxKernel$", "-test.v", "-test.timeout=120s")
	cmd.Env = []string{"LANBOAT_TEST_ICMP_TRACE_CHILD=1", "TMPDIR=/tmp", "HOME=/tmp", "GOMAXPROCS=2"}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stdout
	if err = cmd.Run(); err != nil {
		fmt.Println(err)
		return
	}
	code = 0
}
