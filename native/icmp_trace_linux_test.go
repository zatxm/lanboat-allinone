package native

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestICMPTraceLinuxKernel(t *testing.T) {
	if mode := os.Getenv("LANBOAT_ICMP_SENDER"); mode != "" {
		icmpTraceSender(t, mode)
		return
	}
	if os.Getenv("LANBOAT_TEST_ICMP_TRACE_CHILD") != "1" {
		if os.Getenv("LANBOAT_TEST_ICMP_TRACE_VM") != "1" {
			t.Skip("set LANBOAT_TEST_ICMP_TRACE_VM=1 for isolated real-kernel validation")
		}
		cmd := exec.Command("bash", filepath.Join("..", "scripts", "test-icmp-trace.sh"))
		output, err := cmd.CombinedOutput()
		t.Log(string(output))
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if init, err := os.Readlink("/proc/1/exe"); err != nil || init != "/init" {
		t.Fatal("kernel integration tests require the isolated test VM")
	}
	f := &processFinder{}
	if err := f.start(); err != nil {
		t.Fatal(err)
	}
	defer f.close()
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "ipv4", true: "ipv6"}[ipv6], func(t *testing.T) {
			family, protocol, ip, kind := syscall.AF_INET, syscall.IPPROTO_ICMP, netip.MustParseAddr("127.0.0.1"), byte(8)
			var remote syscall.Sockaddr = &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
			if ipv6 {
				family, protocol, ip, kind = syscall.AF_INET6, syscall.IPPROTO_ICMPV6, netip.MustParseAddr("::1"), 128
				remote = &syscall.SockaddrInet6{Addr: ip.As16()}
			}
			fd, err := syscall.Socket(family, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, protocol)
			if err != nil {
				t.Fatal(err)
			}
			defer syscall.Close(fd)
			packet := []byte{kind, 0, 0, 0, 0, 0, 0, 7, 'r', 'a', 'w', '-', 'i', 'c', 'm', 'p'}
			if !ipv6 {
				binary.BigEndian.PutUint16(packet[2:], checksum(packet, 0))
			}
			if err = syscall.Sendto(fd, packet, 0, remote); err != nil {
				t.Fatal(err)
			}
			key, _ := icmpProcessKey(ip, ip, packet)
			owner, err := f.raw.lookup(key)
			if err != nil {
				t.Fatal("kernel event missing", err)
			}
			name, path, seen := f.lookupICMP(context.Background(), ip, ip, packet)
			want, _ := os.Executable()
			if !seen || path != want || name != filepath.Base(want) {
				t.Fatal("wrong sender", name, path, seen, owner)
			}
			for _, change := range []func(*icmpTraceOwner){func(o *icmpTraceOwner) { o.flags = 1 }, func(o *icmpTraceOwner) { o.start += 1e9 }, func(o *icmpTraceOwner) { o.inode++ }, func(o *icmpTraceOwner) { o.device++ }, func(o *icmpTraceOwner) { o.at = 0 }, func(o *icmpTraceOwner) { o.at = ^uint64(0) }} {
				invalid := owner
				change(&invalid)
				if _, path := f.raw.identity(context.Background(), invalid); path != "" {
					t.Fatal("accepted stale/ambiguous process identity")
				}
			}
			t.Log("real kernel identity", owner.pid, owner.start, owner.inode, owner.device, "key/value sizes", unsafe.Sizeof(key), unsafe.Sizeof(owner))
			generated := append([]byte(nil), packet...)
			generated[0] = 0
			if ipv6 {
				generated[0] = 129
			}
			replyKey, _ := icmpProcessKey(ip, ip, generated)
			if _, err := f.raw.lookup(replyKey); err != syscall.ENOENT {
				t.Fatal("kernel-generated Echo reply attributed", err)
			}
			packet[0], packet[1], packet[7] = 3, 1, 9
			if ipv6 {
				packet[0] = 1
			}
			icmpTraceSend(t, fd, packet, ip)
			key, _ = icmpProcessKey(ip, ip, packet)
			if owner, err := f.raw.lookup(key); err != nil || owner.pid != uint32(os.Getpid()) {
				t.Fatal("non-Echo ICMP sender missing", owner, err)
			}
		})
	}
	t.Run("inherited-and-ambiguous", func(t *testing.T) {
		file := icmpTraceRawSocket(t, false)
		a := icmpTraceWorker(t, file, "shared", nil)
		b := icmpTraceWorker(t, file, "shared", nil)
		packet := []byte{8, 0, 0, 0, 0, 0, 0, 19, 's', 'h', 'a', 'r', 'e', 'd', '!', '!'}
		ip := netip.MustParseAddr("127.0.0.1")
		key, _ := icmpProcessKey(ip, ip, packet)
		a.send(t, packet)
		owner, err := f.raw.lookup(key)
		if err != nil || owner.pid != uint32(a.cmd.Process.Pid) || owner.flags != 0 {
			t.Fatal("identified creator instead of actual writer", owner, err)
		}
		if _, path, _ := f.lookupICMP(context.Background(), ip, ip, packet); path == "" {
			t.Fatal("inherited socket writer missing")
		}
		b.send(t, packet)
		owner, err = f.raw.lookup(key)
		if err != nil || owner.flags == 0 {
			t.Fatal("different writers not marked ambiguous", owner, err)
		}
		if _, path, seen := f.lookupICMP(context.Background(), ip, ip, packet); !seen || path != "" {
			t.Fatal("ambiguous event attributed", path, seen)
		}
		a.send(t, packet)
		if _, path, seen := f.lookupICMP(context.Background(), ip, ip, packet); !seen || path != "" {
			t.Fatal("ambiguity was erased")
		}
		packet[7]++
		a.send(t, packet)
		key, _ = icmpProcessKey(ip, ip, packet)
		owner, err = f.raw.lookup(key)
		if err != nil || owner.flags != 0 {
			t.Fatal(owner, err)
		}
		a.stop(t)
		if _, path := f.raw.identity(context.Background(), owner); path != "" {
			t.Fatal("attributed exited writer")
		}
	})
	t.Run("other-network-namespace", func(t *testing.T) {
		worker := icmpTraceWorker(t, nil, "isolated", &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET})
		packet := []byte{8, 0, 0, 0, 0, 0, 0, 29, 'n', 'e', 't', 'n', 's'}
		worker.send(t, packet)
		ip := netip.MustParseAddr("127.0.0.1")
		key, _ := icmpProcessKey(ip, ip, packet)
		if _, err := f.raw.lookup(key); err != syscall.ENOENT {
			t.Fatal("foreign namespace event escaped filter", err)
		}
	})
	t.Run("pid-namespace", func(t *testing.T) {
		pid, _ := os.Readlink("/proc/self/ns/pid")
		mnt, _ := os.Readlink("/proc/self/ns/mnt")
		cmd := exec.Command(os.Args[0], "-test.run=^TestICMPTraceLinuxKernel$", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), "LANBOAT_ICMP_SENDER=pidns", "LANBOAT_ICMP_PARENT_PID="+pid, "LANBOAT_ICMP_PARENT_MNT="+mnt)
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWPID | syscall.CLONE_NEWNS}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatal(err, string(out))
		}
	})
	t.Run("bounded-cache", func(t *testing.T) {
		file := icmpTraceRawSocket(t, false)
		ip := netip.MustParseAddr("127.0.0.1")
		packet := []byte{8, 0, 0, 0, 2, 3, 0, 0, 'l', 'r', 'u', '!'}
		for i := range 4200 {
			binary.BigEndian.PutUint16(packet[6:], uint16(i))
			icmpTraceSend(t, int(file.Fd()), packet, ip)
		}
		key, _ := icmpProcessKey(ip, ip, packet)
		if owner, err := f.raw.lookup(key); err != nil || owner.pid != uint32(os.Getpid()) {
			t.Fatal("last event missing", owner, err)
		}
		var current, next icmpTraceKey
		var keyPointer unsafe.Pointer
		count := 0
		for {
			attr := struct {
				fd, padding uint32
				key, next   unsafe.Pointer
			}{uint32(f.raw.mapFD), 0, keyPointer, unsafe.Pointer(&next)}
			_, err := icmpBPFCall(4, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
			if err == syscall.ENOENT {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			count++
			if count > 4096 {
				t.Fatal("cache exceeded bound")
			}
			current = next
			keyPointer = unsafe.Pointer(&current)
		}
		t.Log("bounded map entries", count)
	})
	t.Run("injection", func(t *testing.T) { testICMPInjection(t, f) })
	t.Run("tx-ring", func(t *testing.T) { testICMPTXRing(t, f) })
	t.Run("injection-lifecycle", func(t *testing.T) { testICMPInjectionLifecycle(t, f) })
	t.Run("tun-routing", testICMPTraceTUN)
	t.Run("release-cli", testICMPTraceRelease)
	t.Run("ipv6-options", func(t *testing.T) {
		file := icmpTraceRawSocket(t, true)
		fd := int(file.Fd())
		ip := netip.MustParseAddr("::1")
		if err := syscall.SetsockoptString(fd, syscall.IPPROTO_IPV6, 54, string([]byte{58, 0, 0, 0, 0, 0, 0, 0})); err != nil {
			t.Fatal(err)
		}
		packet := []byte{128, 0, 0, 0, 0, 0, 0, 89, 'h', 'o', 'p', 'b', 'y', 'h', 'o', 'p'}
		icmpTraceSend(t, fd, packet, ip)
		if _, path, seen := f.lookupICMP(context.Background(), ip, ip, packet); !seen || path == "" {
			t.Fatal("IPv6 extension header was not decoded")
		}
	})
	t.Run("dynamic-rules", func(t *testing.T) {
		set := RuleSet{Type: "inline", Tag: "dynamic", Rules: []Rule{{IPCIDR: []string{"192.0.2.0/24"}}}}
		r := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "tun", Tag: "tun", InterfaceName: "lbproc0", DNSMode: "disabled"}}, Route: Route{RuleSet: []RuleSet{set}, Rules: []Rule{{RuleSet: []string{"dynamic"}, Outbound: "direct"}}}})
		if r.processes.raw != nil {
			t.Fatal("IP-only rules enabled tracking")
		}
		for i := range 2 {
			snapshot, err := compileRuleSet([]Rule{{ProcessName: []string{filepath.Base(os.Args[0])}}})
			if err != nil {
				t.Fatal(err)
			}
			r.publishRuleSet(r.ruleSets["dynamic"], snapshot)
			if r.processes.raw == nil {
				t.Fatal("live process rule failed to enable tracking")
			}
			file := icmpTraceRawSocket(t, false)
			ip := netip.MustParseAddr("127.0.0.1")
			packet := []byte{8, 0, 0, 0, 0, 0, 0, byte(79 + i), 'l', 'i', 'v', 'e'}
			icmpTraceSend(t, int(file.Fd()), packet, ip)
			q := request{inbound: "tun", network: "icmp", source: "127.0.0.1:0", address: "127.0.0.1:0", payload: packet}
			r.enrichProcess(context.Background(), &q)
			if q.metadata.ProcessPath == "" {
				t.Fatal("new process rule missed first packet")
			}
			snapshot, err = compileRuleSet(set.Rules)
			if err != nil {
				t.Fatal(err)
			}
			r.publishRuleSet(r.ruleSets["dynamic"], snapshot)
			if r.processes.raw != nil {
				t.Fatal("removed process rule retained tracking resources")
			}
		}
	})
	t.Run("exec-revalidation", func(t *testing.T) {
		file := icmpTraceRawSocket(t, false)
		worker := icmpTraceWorker(t, file, "shared", nil)
		packet := []byte{8, 0, 0, 0, 0, 0, 0, 59, 'e', 'x', 'e', 'c', '!'}
		ip := netip.MustParseAddr("127.0.0.1")
		worker.send(t, packet)
		key, _ := icmpProcessKey(ip, ip, packet)
		old, err := f.raw.lookup(key)
		if err != nil {
			t.Fatal(err)
		}
		copyPath := filepath.Join(t.TempDir(), "new-image")
		source, err := os.Open(os.Args[0])
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		image, err := os.OpenFile(copyPath, os.O_CREATE|os.O_WRONLY, 0700)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.Copy(image, source); err != nil {
			image.Close()
			t.Fatal(err)
		}
		if err = image.Close(); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(worker.in, "exec "+copyPath)
		if line, err := worker.out.ReadString('\n'); err != nil || line != "exec\n" {
			t.Fatal(line, err)
		}
		for i := range 100 {
			target, _ := os.Readlink(fmt.Sprint("/proc/", worker.cmd.Process.Pid, "/exe"))
			if target == copyPath {
				break
			}
			if i == 99 {
				t.Fatal("exec did not complete")
			}
			time.Sleep(10 * time.Millisecond)
		}
		if _, path := f.raw.identity(context.Background(), old); path != "" {
			t.Fatal("exec reused previous process image")
		}
		packet[7]++
		worker.send(t, packet)
		if _, path, seen := f.lookupICMP(context.Background(), ip, ip, packet); !seen || path != copyPath {
			t.Fatal("new executable not identified", path, seen)
		}
	})
	t.Run("capture-expiration", func(t *testing.T) {
		file := icmpTraceRawSocket(t, false)
		ip := netip.MustParseAddr("127.0.0.1")
		packet := []byte{8, 0, 0, 0, 0, 0, 0, 69, 'e', 'x', 'p', 'i', 'r', 'e'}
		icmpTraceSend(t, int(file.Fd()), packet, ip)
		key, _ := icmpProcessKey(ip, ip, packet)
		owner, err := f.raw.lookup(key)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(5100 * time.Millisecond)
		if _, path := f.raw.identity(context.Background(), owner); path != "" {
			t.Fatal("expired event attributed")
		}
	})
}

func icmpTraceRawSocket(t *testing.T, v6 bool) *os.File {
	t.Helper()
	family, protocol := syscall.AF_INET, syscall.IPPROTO_ICMP
	if v6 {
		family, protocol = syscall.AF_INET6, syscall.IPPROTO_ICMPV6
	}
	fd, err := syscall.Socket(family, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, protocol)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "raw-icmp")
	t.Cleanup(func() { f.Close() })
	return f
}

func icmpTraceSend(t *testing.T, fd int, packet []byte, target netip.Addr) {
	t.Helper()
	packet = append([]byte(nil), packet...)
	var remote syscall.Sockaddr = &syscall.SockaddrInet6{Addr: target.As16()}
	if target.Is4() {
		packet[2], packet[3] = 0, 0
		binary.BigEndian.PutUint16(packet[2:], checksum(packet, 0))
		remote = &syscall.SockaddrInet4{Addr: target.As4()}
	}
	if err := syscall.Sendto(fd, packet, 0, remote); err != nil {
		t.Fatal(err)
	}
}

type icmpTraceTestWorker struct {
	cmd     *exec.Cmd
	in      io.WriteCloser
	out     *bufio.Reader
	stopped bool
}

func icmpTraceWorker(t *testing.T, file *os.File, mode string, attr *syscall.SysProcAttr) *icmpTraceTestWorker {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestICMPTraceLinuxKernel$", "-test.timeout=90s")
	ns, _ := os.Readlink("/proc/self/ns/net")
	cmd.Env = append(os.Environ(), "LANBOAT_ICMP_SENDER="+mode, "LANBOAT_ICMP_PARENT_NET="+ns)
	if file != nil {
		cmd.ExtraFiles = []*os.File{file}
	}
	cmd.SysProcAttr = attr
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	w := &icmpTraceTestWorker{cmd: cmd, in: in, out: bufio.NewReader(out)}
	t.Cleanup(func() { w.stop(t) })
	return w
}

func (w *icmpTraceTestWorker) send(t *testing.T, packet []byte) {
	t.Helper()
	if _, err := fmt.Fprintln(w.in, hex.EncodeToString(packet)); err != nil {
		t.Fatal(err)
	}
	if line, err := w.out.ReadString('\n'); err != nil || line != "sent\n" {
		t.Fatal("sender failed", line, err)
	}
}
func (w *icmpTraceTestWorker) stop(t *testing.T) {
	t.Helper()
	if w.stopped {
		return
	}
	w.stopped = true
	w.in.Close()
	if err := w.cmd.Wait(); err != nil {
		t.Error("sender exit", err)
	}
}

func icmpTraceSender(t *testing.T, mode string) {
	if mode == "pidns" {
		pid, _ := os.Readlink("/proc/self/ns/pid")
		mnt, _ := os.Readlink("/proc/self/ns/mnt")
		if os.Getpid() != 1 || pid == os.Getenv("LANBOAT_ICMP_PARENT_PID") || mnt == os.Getenv("LANBOAT_ICMP_PARENT_MNT") {
			t.Fatal("PID/mount namespace isolation missing")
		}
		if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
			t.Fatal(err)
		}
		finder := &processFinder{}
		if err := finder.start(); err != nil {
			t.Fatal(err)
		}
		defer finder.close()
		file := icmpTraceRawSocket(t, false)
		ip := netip.MustParseAddr("127.0.0.1")
		packet := []byte{8, 0, 0, 0, 0, 0, 0, 39, 'p', 'i', 'd', 'n', 's'}
		icmpTraceSend(t, int(file.Fd()), packet, ip)
		key, _ := icmpProcessKey(ip, ip, packet)
		owner, err := finder.raw.lookup(key)
		if err != nil || owner.pid != 1 {
			t.Fatal("wrong namespace PID", owner, err)
		}
		if _, path, _ := finder.lookupICMP(context.Background(), ip, ip, packet); path == "" {
			t.Fatal("namespace identity unavailable")
		}
		return
	}
	fd := 3
	if mode == "isolated" {
		ns, _ := os.Readlink("/proc/self/ns/net")
		parent := os.Getenv("LANBOAT_ICMP_PARENT_NET")
		if parent == "" || ns == parent {
			t.Fatal("network namespace isolation missing")
		}
		link, err := net.InterfaceByName("lo")
		if err != nil {
			t.Fatal(err)
		}
		if err = configureLink(link.Index, 65536); err != nil {
			t.Fatal(err)
		}
		fd = int(icmpTraceRawSocket(t, false).Fd())
	}
	var ring *icmpTXRing
	if version, ok := strings.CutPrefix(mode, "txring"); ok {
		n, err := strconv.Atoi(version)
		if err != nil || n < 0 || n > 2 {
			t.Fatal("invalid ring version", version)
		}
		ring = mapICMPTXRing(t, fd, n)
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if path, ok := strings.CutPrefix(scanner.Text(), "exec "); ok {
			fmt.Println("exec")
			if err := syscall.Exec(path, []string{path, "-test.run=^TestICMPTraceLinuxKernel$", "-test.timeout=90s"}, os.Environ()); err != nil {
				t.Fatal(err)
			}
		}
		packet, err := hex.DecodeString(scanner.Text())
		if err != nil {
			t.Fatal(err)
		}
		if ring != nil {
			ring.send(t, packet, packet, packet, packet)
		} else if mode == "hdr4" || mode == "hdr6" || mode == "packet" {
			icmpInjectionSend(t, fd, packet, mode)
		} else {
			icmpTraceSend(t, fd, packet, netip.MustParseAddr("127.0.0.1"))
		}
		fmt.Println("sent")
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func testICMPTraceTUN(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		t.Run(fmt.Sprint("redirect=", redirect), func(t *testing.T) {
			path, _ := os.Executable()
			r := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "tun", Tag: "tun", InterfaceName: "lbraw0", AutoRoute: true, AutoRedirect: redirect, StrictRoute: true, DNSMode: "disabled"}}, Outbounds: []Outbound{{Type: "block", Tag: "deny"}}, Route: Route{Final: "deny", Rules: []Rule{{Network: []string{"icmp"}, ProcessPath: []string{path}, Action: "reject", Method: "reply"}}}})
			if r.processes.raw == nil {
				t.Fatal("TUN did not start process tracker")
			}
			icmpTraceTunnelEcho(t, "lbraw0")
			r.Close()
			if r.processes.raw != nil {
				t.Fatal("runtime did not release tracker")
			}
		})
	}
}

func icmpTraceTunnelEcho(t *testing.T, interfaceName string) {
	for _, v6 := range []bool{false, true} {
		t.Run(fmt.Sprint("ipv6=", v6), func(t *testing.T) {
			target, kind, reply := netip.MustParseAddr("203.0.113.31"), byte(8), byte(0)
			if v6 {
				target, kind, reply = netip.MustParseAddr("2001:db8::31"), 128, 129
			}
			file := icmpTraceRawSocket(t, v6)
			fd := int(file.Fd())
			if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 2}); err != nil {
				t.Fatal(err)
			}
			packet := []byte{kind, 0, 0, 0, 0, 0, 0, 49, 't', 'u', 'n', '!'}
			for index, method := range []string{"raw", "hdr", "packet", "txring0", "txring1", "txring2"} {
				t.Run(method, func(t *testing.T) {
					packet := append([]byte(nil), packet...)
					packet[7] = byte(49 + index)
					if method == "raw" {
						icmpTraceSend(t, fd, packet, target)
					} else {
						link, err := net.InterfaceByName(interfaceName)
						if err != nil {
							t.Fatal(err)
						}
						addresses, err := link.Addrs()
						if err != nil {
							t.Fatal(err)
						}
						var source netip.Addr
						for _, a := range addresses {
							prefix, err := netip.ParsePrefix(a.String())
							if err == nil && prefix.Addr().Is6() == v6 {
								source = prefix.Addr()
								break
							}
						}
						if !source.IsValid() {
							t.Fatal("TUN source unavailable")
						}
						ipPacket := icmpInjectionPacket(source, target, byte(49+index))
						header := 20
						if v6 {
							header = 40
						}
						packet = ipPacket[header:]
						if method == "hdr" {
							sender := icmpInjectionSocket(t, v6)
							var remote syscall.Sockaddr = &syscall.SockaddrInet6{Addr: target.As16()}
							if !v6 {
								remote = &syscall.SockaddrInet4{Addr: target.As4()}
							}
							if err = syscall.Sendto(int(sender.Fd()), ipPacket, 0, remote); err != nil {
								t.Fatal(err)
							}
						} else if version, ok := strings.CutPrefix(method, "txring"); ok {
							n, err := strconv.Atoi(version)
							if err != nil {
								t.Fatal(err)
							}
							ring := newICMPTXRing(t, n, v6, false, false, interfaceName)
							ring.send(t, ipPacket)
						} else {
							ether := uint16(0x0800)
							if v6 {
								ether = 0x86dd
							}
							sender, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, int(ether>>8|ether<<8))
							if err != nil {
								t.Fatal(err)
							}
							defer syscall.Close(sender)
							if err = syscall.Sendto(sender, ipPacket, 0, &syscall.SockaddrLinklayer{Ifindex: link.Index, Protocol: ether>>8 | ether<<8}); err != nil {
								t.Fatal(err)
							}
						}
					}
					var buf [128]byte
					n, from, err := syscall.Recvfrom(fd, buf[:], 0)
					if !v6 && n >= 20 {
						h := int(buf[0]&15) * 4
						n -= h
						copy(buf[:], buf[h:])
					}
					if err != nil || n != len(packet) || buf[0] != reply || buf[7] != packet[7] || string(buf[8:n]) != string(packet[8:]) {
						t.Fatal("raw process rule did not reply", n, from, err)
					}
				})
			}
		})
	}
}

func testICMPTraceRelease(t *testing.T) {
	path, _ := os.Executable()
	ready := unusedPort(t)
	cfg := Config{Inbounds: []Inbound{{Type: "tun", Tag: "tun", InterfaceName: "lbcli0", AutoRoute: true, AutoRedirect: true, StrictRoute: true, DNSMode: "disabled"}, {Type: "mixed", Tag: "ready", Listen: "127.0.0.1", ListenPort: ready}}, Outbounds: []Outbound{{Type: "block", Tag: "deny"}}, Route: Route{Final: "deny", Rules: []Rule{{Network: []string{"icmp"}, ProcessPath: []string{path}, Action: "reject", Method: "reply"}}}}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "config.json")
	if err = os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(t.TempDir(), "core.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.Command("/lanboat-allinone", "run", "-c", file)
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-done:
			if err != nil {
				b, _ := os.ReadFile(log.Name())
				t.Error(err, string(b))
			}
		case <-time.After(3 * time.Second):
			cmd.Process.Kill()
			<-done
			t.Error("core did not shut down")
		}
	})
	for i := range 600 {
		c, err := net.DialTimeout("tcp", fmt.Sprint("127.0.0.1:", ready), 20*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if i == 599 {
			b, _ := os.ReadFile(log.Name())
			t.Fatal("core not ready", string(b))
		}
		time.Sleep(10 * time.Millisecond)
	}
	icmpTraceTunnelEcho(t, "lbcli0")
	status, err := os.ReadFile(fmt.Sprint("/proc/", cmd.Process.Pid, "/status"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "VmHWM:") {
			t.Log("release core", line)
		}
	}
	binary, err := os.ReadFile("/lanboat-allinone")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("release sha256=%x", sha256.Sum256(binary))
}
