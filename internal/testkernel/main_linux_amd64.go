// The isolated kernel integration-test VM runs this as PID1.
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
		fmt.Fprintln(os.Stderr, "testkernel is only an isolated VM init, not a host command")
		os.Exit(2)
	}
	code := 1
	defer func() {
		fmt.Printf("LANBOAT_KERNEL_TEST_EXIT=%d\n", code)
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
	cmdline, _ := os.ReadFile("/proc/cmdline")
	brutal := strings.Contains(string(cmdline), "lanboat_test_brutal=1")
	modules := []string{"gf128mul", "aesni-intel", "chacha", "chacha20poly1305", "tls"}
	if brutal {
		modules = []string{"brutal"}
	}
	for _, name := range modules {
		b, e := os.ReadFile("/" + name + ".ko")
		if e != nil {
			fmt.Println(e)
			return
		}
		params := []byte{0}
		_, _, e1 := syscall.Syscall(syscall.SYS_INIT_MODULE, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&params[0])))
		if e1 != 0 {
			fmt.Println("module", name, e1)
			return
		}
	}
	os.MkdirAll("/tmp", 0700)
	test := "^TestKernelTLSLinux$"
	if brutal {
		test = "^TestGenericMuxBrutalKernel$"
	}
	cmd := exec.Command("/native.test", "-test.run", test, "-test.v", "-test.timeout=90s")
	cmd.Env = []string{"LANBOAT_TEST_KERNEL_TLS_CHILD=1", "TMPDIR=/tmp", "HOME=/tmp", "GOMAXPROCS=2"}
	if brutal {
		cmd.Env = append(cmd.Env, "LANBOAT_TEST_BRUTAL_KERNEL=1")
		if _, err := os.Stat("/sing-box"); err == nil {
			cmd.Env = append(cmd.Env, "LANBOAT_TEST_SINGBOX15=/sing-box")
		}
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stdout
	if err = cmd.Run(); err != nil {
		fmt.Println(err)
		return
	}
	code = 0
}
