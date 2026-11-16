package native

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"go.uber.org/zap"
)

type icmpTraceKey struct {
	family, length      uint32
	source, destination [16]byte
	prefix              [16]byte
}

type icmpTraceOwner struct {
	pid, padding                    uint32
	start, inode, device, flags, at uint64
}

type icmpProcessTracker struct {
	mapFD, ipv4, ipv6 int
	ticks             uint64
	sendFD            int
	injectionLinks    []int
	injectionErr      error
	ringErr           error
}

func icmpBPFCall(command uint32, attr unsafe.Pointer, size uintptr) (int, error) {
	var number uintptr
	switch runtime.GOARCH {
	case "amd64":
		number = 321
	case "arm64", "riscv64", "loong64":
		number = 280
	default:
		return -1, syscall.ENOSYS
	}
	fd, _, errno := syscall.Syscall(number, uintptr(command), uintptr(attr), size)
	runtime.KeepAlive(attr)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

func newICMPProcessTracker() (_ *icmpProcessTracker, err error) {
	netNS, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	pidNS, err := os.Stat("/proc/self/ns/pid")
	if err != nil {
		return nil, err
	}
	var create [5]uint32
	create[0], create[1], create[2], create[3] = 9, 56, 48, 4096 // bounded LRU hash
	fd, err := icmpBPFCall(0, unsafe.Pointer(&create), unsafe.Sizeof(create))
	if err != nil {
		return nil, err
	}
	t := &icmpProcessTracker{mapFD: fd, ipv4: -1, ipv6: -1, sendFD: -1}
	defer func() {
		if err != nil {
			t.close()
		}
	}()
	data, err := os.ReadFile("/sys/kernel/btf/vmlinux")
	if err != nil {
		return nil, err
	}
	btf, err := parseICMPBTF(data)
	if err != nil {
		return nil, err
	}
	auxv, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return nil, err
	}
	for len(auxv) >= 16 {
		if binary.NativeEndian.Uint64(auxv) == 17 { // AT_CLKTCK
			t.ticks = binary.NativeEndian.Uint64(auxv[8:])
			break
		}
		auxv = auxv[16:]
	}
	if t.ticks == 0 || t.ticks > 1000000 {
		return nil, errors.New("ICMP process clock tick rate unavailable")
	}
	netStat, pidStat := netNS.Sys().(*syscall.Stat_t), pidNS.Sys().(*syscall.Stat_t)
	if netStat.Ino > 1<<32-1 {
		return nil, errors.New("ICMP tracing network namespace identifier exceeds kernel field")
	}
	for _, v6 := range []bool{false, true} {
		name := "__ip_local_out"
		if v6 {
			name = "__ip6_local_out"
		}
		id, e := btf.hook(name, "net", "sock", "sk_buff")
		if e != nil {
			return nil, e
		}
		code, e := icmpTraceProgram(btf, fd, -1, name, uint32(netStat.Ino), pidStat.Dev, pidStat.Ino)
		if e != nil {
			return nil, e
		}
		link, e := attachICMPTrace(id, code, false)
		if e != nil {
			return nil, fmt.Errorf("%s: %w", name, e)
		}
		if v6 {
			t.ipv6 = link
		} else {
			t.ipv4 = link
		}
	}
	t.injectionErr = t.startInjection(btf, uint32(netStat.Ino), pidStat.Dev, pidStat.Ino)
	if t.injectionErr == nil {
		t.ringErr = t.startTXRing(btf, uint32(netStat.Ino), pidStat.Dev, pidStat.Ino)
	}
	return t, nil
}

func (t *icmpProcessTracker) startTXRing(b *icmpBTF, netNS uint32, pidDev, pidNS uint64) error {
	id, _, _, err := b.txRingHook()
	if err != nil {
		return err
	}
	code, err := icmpTraceProgram(b, t.mapFD, t.sendFD, "tpacket_fill_skb", netNS, pidDev, pidNS)
	if err != nil {
		return err
	}
	link, err := attachICMPTrace(id, code, true)
	if err != nil {
		return fmt.Errorf("TX_RING: %w", err)
	}
	t.injectionLinks = append(t.injectionLinks, link)
	return nil
}

func (t *icmpProcessTracker) startInjection(b *icmpBTF, netNS uint32, pidDev, pidNS uint64) (err error) {
	create := [5]uint32{9, 8, 8, 4096}
	t.sendFD, err = icmpBPFCall(0, unsafe.Pointer(&create), unsafe.Sizeof(create))
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			t.closeInjection()
		}
	}()
	for _, hook := range []struct {
		name      string
		arguments []string
	}{
		{"nf_hook_slow", []string{"sk_buff", "nf_hook_state", "nf_hook_entries", ""}},
		{"__dev_queue_xmit", []string{"sk_buff", "net_device"}},
		{"__dev_direct_xmit", []string{"sk_buff", ""}},
		{"raw_sendmsg", []string{"sock", "msghdr", ""}},
		{"rawv6_sendmsg", []string{"sock", "msghdr", ""}},
		{"packet_sendmsg", []string{"socket", "msghdr", ""}},
	} {
		id, e := b.hook(hook.name, hook.arguments...)
		if e != nil {
			return e
		}
		sender := strings.HasSuffix(hook.name, "sendmsg")
		// Attach return hooks first so no newly recorded send outlives its syscall.
		for _, exit := range []bool{true, false} {
			if exit && !sender {
				continue
			}
			var code []byte
			if sender {
				code, e = icmpSendProgram(b, t.sendFD, hook.name == "packet_sendmsg", exit)
			} else {
				code, e = icmpTraceProgram(b, t.mapFD, t.sendFD, hook.name, netNS, pidDev, pidNS)
			}
			if e != nil {
				return e
			}
			fd, e := attachICMPTrace(id, code, exit)
			if e != nil {
				return fmt.Errorf("%s exit=%t: %w", hook.name, exit, e)
			}
			t.injectionLinks = append(t.injectionLinks, fd)
		}
	}
	return nil
}

func attachICMPTrace(id uint32, code []byte, exit bool) (int, error) {
	log := make([]byte, 65536)
	// This tag is required by the kernel for tracing helpers; no external BPF code is linked.
	license := []byte("GPL\x00")
	var pinned runtime.Pinner
	pinned.Pin(&code[0])
	pinned.Pin(&license[0])
	pinned.Pin(&log[0])
	defer pinned.Unpin()
	var attr [112]byte
	put := binary.NativeEndian
	put.PutUint32(attr[:], 26) // BPF_PROG_TYPE_TRACING
	put.PutUint32(attr[4:], uint32(len(code)/8))
	put.PutUint64(attr[8:], uint64(uintptr(unsafe.Pointer(&code[0]))))
	put.PutUint64(attr[16:], uint64(uintptr(unsafe.Pointer(&license[0]))))
	put.PutUint32(attr[24:], 1)
	put.PutUint32(attr[28:], uint32(len(log)))
	put.PutUint64(attr[32:], uint64(uintptr(unsafe.Pointer(&log[0]))))
	copy(attr[48:], "lanboat_icmp")
	attach := uint32(24) // BPF_TRACE_FENTRY
	if exit {
		attach = 25
	} // BPF_TRACE_FEXIT
	put.PutUint32(attr[68:], attach)
	put.PutUint32(attr[108:], id)
	var prog int
	var err error
	for attempt := 0; attempt < 8; attempt++ {
		// The verifier returns EAGAIN for pending signals, including Go's SIGURG preemption.
		prog, err = icmpBPFCall(5, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
		if !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	runtime.KeepAlive(code)
	runtime.KeepAlive(license)
	runtime.KeepAlive(log)
	if err != nil {
		text := strings.TrimRight(string(log), "\x00")
		if len(text) > 4096 {
			text = text[len(text)-4096:]
		}
		return -1, fmt.Errorf("BPF load: %w: %s", err, text)
	}
	defer syscall.Close(prog)
	link := [4]uint32{uint32(prog), 0, attach, 0}
	return icmpBPFCall(28, unsafe.Pointer(&link), unsafe.Sizeof(link))
}

func (t *icmpProcessTracker) close() {
	t.closeInjection()
	for _, fd := range []*int{&t.ipv4, &t.ipv6, &t.mapFD} {
		if *fd >= 0 {
			syscall.Close(*fd)
			*fd = -1
		}
	}
}

func (t *icmpProcessTracker) closeInjection() {
	for i := len(t.injectionLinks) - 1; i >= 0; i-- {
		syscall.Close(t.injectionLinks[i])
	}
	t.injectionLinks = nil
	if t.sendFD >= 0 {
		syscall.Close(t.sendFD)
		t.sendFD = -1
	}
}

func icmpProcessKey(source, destination netip.Addr, packet []byte) (icmpTraceKey, bool) {
	var key icmpTraceKey
	if len(packet) < 8 || len(packet) > 65535 || !source.IsValid() || !destination.IsValid() || source.Is4() != destination.Is4() {
		return key, false
	}
	key.family, key.length = 4, uint32(len(packet))
	if source.Is4() {
		s, d := source.As4(), destination.As4()
		copy(key.source[:], s[:])
		copy(key.destination[:], d[:])
	} else {
		key.family, key.source, key.destination = 6, source.As16(), destination.As16()
	}
	copy(key.prefix[:], packet)
	key.prefix[2], key.prefix[3] = 0, 0
	return key, true
}

func (t *icmpProcessTracker) lookup(key icmpTraceKey) (icmpTraceOwner, error) {
	var owner icmpTraceOwner
	attr := struct {
		fd, padding uint32
		key, value  unsafe.Pointer
	}{fd: uint32(t.mapFD), key: unsafe.Pointer(&key), value: unsafe.Pointer(&owner)}
	_, err := icmpBPFCall(1, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(key)
	runtime.KeepAlive(&owner)
	return owner, err
}

func processStartTick(stat []byte) (uint64, error) {
	i := strings.LastIndexByte(string(stat), ')')
	if i < 0 {
		return 0, errors.New("invalid process stat")
	}
	fields := strings.Fields(string(stat[i+1:]))
	if len(fields) < 20 {
		return 0, errors.New("short process stat")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

func (t *icmpProcessTracker) identity(ctx context.Context, owner icmpTraceOwner, uidOut ...*uint32) (string, string) {
	var now syscall.Timespec
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 7, uintptr(unsafe.Pointer(&now)), 0) // CLOCK_BOOTTIME
	if errno != 0 || owner.pid == 0 || owner.flags != 0 || owner.at == 0 || uint64(now.Nano()) < owner.at || uint64(now.Nano())-owner.at > 5e9 {
		return "", ""
	}
	base := "/proc/" + strconv.FormatUint(uint64(owner.pid), 10) + "/"
	tick := owner.start/1e9*t.ticks + owner.start%1e9*t.ticks/1e9
	check := func() bool {
		stat, err := os.ReadFile(base + "stat")
		if err != nil || ctx.Err() != nil {
			return false
		}
		start, err := processStartTick(stat)
		if err != nil || start != tick {
			return false
		}
		exe, err := os.Stat(base + "exe")
		if err != nil {
			return false
		}
		s := exe.Sys().(*syscall.Stat_t)
		major := s.Dev>>8&0xfff | s.Dev>>32&0xfffff000
		minor := s.Dev&0xff | s.Dev>>12&0xffffff00
		return s.Ino == owner.inode && major<<20|minor == owner.device
	}
	if !check() {
		return "", ""
	}
	if len(uidOut) != 0 {
		info, err := os.Stat(base)
		if err != nil {
			return "", ""
		}
		*uidOut[0] = info.Sys().(*syscall.Stat_t).Uid
	}
	path, err := os.Readlink(base + "exe")
	if err != nil || !check() {
		return "", ""
	}
	path = strings.TrimSuffix(path, " (deleted)")
	return filepath.Base(path), path
}

func (f *processFinder) start() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return os.ErrClosed
	}
	f.rawOnce.Do(func() { f.raw, f.rawErr = newICMPProcessTracker() })
	if f.rawErr == nil && f.raw != nil {
		return errors.Join(f.raw.injectionErr, f.raw.ringErr)
	}
	return f.rawErr
}

func (f *processFinder) close() {
	f.stop(true)
}

func (f *processFinder) stop(closed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = f.closed || closed
	if f.raw != nil {
		f.raw.close()
		f.raw = nil
	}
	f.rawOnce, f.rawErr = sync.Once{}, nil
}

func (f *processFinder) lookupICMP(ctx context.Context, source, destination netip.Addr, packet []byte) (string, string, bool) {
	m, seen := f.lookupICMPIdentity(ctx, source, destination, packet)
	return m.ProcessName, m.ProcessPath, seen
}
func (f *processFinder) lookupICMPIdentity(ctx context.Context, source, destination netip.Addr, packet []byte) (Metadata, bool) {
	if ctx.Err() != nil {
		return Metadata{}, false
	}
	f.mu.Lock()
	t := f.raw
	if t == nil {
		f.mu.Unlock()
		return Metadata{}, false
	}
	key, valid := icmpProcessKey(source, destination, packet)
	if !valid || !processLocalAddress(source) {
		f.mu.Unlock()
		return Metadata{}, false
	}
	owner, err := t.lookup(key)
	f.mu.Unlock()
	if err != nil {
		return Metadata{}, !errors.Is(err, syscall.ENOENT)
	}
	var uid uint32
	name, path := t.identity(ctx, owner, &uid)
	if path == "" {
		return Metadata{}, true
	}
	return Metadata{ProcessName: name, ProcessPath: path, UserID: &uid}, true
}

func (r *Runtime) startProcessTracking(needed bool) {
	for _, in := range r.config.Inbounds {
		if in.Type == "tun" {
			if !needed {
				r.processes.stop(false)
			} else if err := r.processes.start(); err != nil {
				r.logger.Warn("ICMP process tracking incomplete", zap.Error(err))
			}
			return
		}
	}
}
