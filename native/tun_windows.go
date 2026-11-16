//go:build windows

package native

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var tunKernel = syscall.NewLazyDLL("kernel32.dll")
var tunIPHelper = syscall.NewLazyDLL("iphlpapi.dll")

func systemDNSBeforeTUN() []string {
	path, e := winSystemPath("WindowsPowerShell\\v1.0\\powershell.exe")
	if e != nil {
		return nil
	}
	text, e := tunCommand(path, "", "-NoProfile", "-NonInteractive", "-Command", "$indices = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' | Sort-Object RouteMetric | Select-Object -ExpandProperty InterfaceIndex -Unique); (Get-DnsClientServerAddress | Where-Object {$_.InterfaceIndex -in $indices}).ServerAddresses")
	if e != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, value := range strings.Fields(text) {
		ip, e := netip.ParseAddr(value)
		if e == nil && !ip.IsLoopback() && !seen[ip.String()] {
			seen[ip.String()] = true
			out = append(out, net.JoinHostPort(ip.String(), "53"))
		}
	}
	return out
}

func winSystemPath(name string) (string, error) {
	var b [32768]uint16
	n, _, e := tunKernel.NewProc("GetSystemDirectoryW").Call(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	if n == 0 || n >= uintptr(len(b)) {
		return "", e
	}
	return filepath.Join(syscall.UTF16ToString(b[:n]), name), nil
}
func validateTUNPlatform(in Inbound) error {
	if in.linuxTUNOptions() {
		return errors.New("Linux TUN options cannot be used on Windows")
	}
	if strconv.IntSize != 64 {
		return errors.New("Windows TUN requires amd64 or arm64")
	}
	if in.AutoRedirect {
		return errors.New("auto_redirect requires Linux nftables")
	}
	if len(in.InterfaceName) > 128 || strings.ContainsAny(in.InterfaceName, "/\\\x00\r\n\t\"") {
		return errors.New("invalid Windows TUN interface name")
	}
	if in.MultiQueue || in.IPRoute2TableIndex != 0 || in.IPRoute2RuleIndex != 0 {
		return errors.New("multi_queue and iproute2 options require Linux")
	}
	return nil
}
func (r *Runtime) socketControlFor(o DialOptions, network, address string, raw syscall.RawConn) error {
	host, _, _ := net.SplitHostPort(address)
	if host == "" {
		host = address
	}
	if ip, e := netip.ParseAddr(host); e == nil && ip.IsLoopback() && o.BindInterface == "" {
		return nil
	}
	ipv6 := strings.HasPrefix(address, "[") || strings.HasSuffix(network, "6") || strings.HasPrefix(network, "ip6:")
	index := r.tunEgress4.Load()
	if ipv6 {
		index = r.tunEgress6.Load()
	}
	ifaceName := o.BindInterface
	if ifaceName == "" && !r.config.Route.AutoDetectInterface {
		ifaceName = r.config.Route.DefaultInterface
	}
	if ifaceName != "" {
		iface, e := net.InterfaceByName(ifaceName)
		if e != nil {
			return e
		}
		index = int32(iface.Index)
	}
	if index == 0 {
		if r.tunRouting.Load() {
			return errors.New("no physical egress for this IP family")
		}
		return nil
	}
	var optionErr error
	e := raw.Control(func(fd uintptr) {
		if ipv6 {
			optionErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, 31, int(index))
		} else {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(index))
			optionErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, 31, int(binary.NativeEndian.Uint32(b[:])))
		}
	})
	if e != nil {
		return e
	}
	return optionErr
}

// The driver is an OS dependency, loaded only from an absolute path beside the executable.
// Verify its Authenticode signature before loading code into a privileged process.
func loadWintun() (*syscall.DLL, error) {
	exe, e := os.Executable()
	if e != nil {
		return nil, e
	}
	path := filepath.Join(filepath.Dir(exe), "wintun.dll")
	if e = verifyWintunSignature(path); e != nil {
		return nil, e
	}
	w, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, _, e := tunKernel.NewProc("LoadLibraryExW").Call(uintptr(unsafe.Pointer(w)), 0, 0x100|0x800)
	if h == 0 {
		return nil, fmt.Errorf("load signed wintun.dll beside the executable: %w", e)
	}
	return &syscall.DLL{Name: path, Handle: syscall.Handle(h)}, nil
}
func verifyWintunSignature(path string) error {
	w, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	type fileInfo struct {
		Size    uint32
		Path    *uint16
		File    syscall.Handle
		Subject *syscall.GUID
	}
	type trustData struct {
		Size                   uint32
		Callback, Client       uintptr
		UI, Revocation, Choice uint32
		File                   *fileInfo
		State                  uint32
		StateData              syscall.Handle
		URL                    *uint16
		Flags, UIContext       uint32
		Signature              uintptr
	}
	file := fileInfo{Path: w}
	file.Size = uint32(unsafe.Sizeof(file))
	data := trustData{UI: 2, Choice: 1, File: &file, State: 1, Flags: 0x1000}
	data.Size = uint32(unsafe.Sizeof(data))
	action := syscall.GUID{Data1: 0x00aac56b, Data2: 0xcd44, Data3: 0x11d0, Data4: [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}}
	verify := syscall.NewLazyDLL("wintrust.dll").NewProc("WinVerifyTrust")
	code, _, _ := verify.Call(^uintptr(0), uintptr(unsafe.Pointer(&action)), uintptr(unsafe.Pointer(&data)))
	data.State = 2
	verify.Call(^uintptr(0), uintptr(unsafe.Pointer(&action)), uintptr(unsafe.Pointer(&data)))
	if code != 0 {
		return fmt.Errorf("wintun.dll signature verification failed: 0x%x", uint32(code))
	}
	return nil
}

type wintunDevice struct {
	luid                                                uint64
	dll                                                 *syscall.DLL
	adapter, session, readEvent, stopEvent              uintptr
	receive, release, allocate, send, end, closeAdapter *syscall.Proc
	mu                                                  sync.RWMutex
	once                                                sync.Once
}

func (d *wintunDevice) Read(b []byte) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.session == 0 {
		return 0, net.ErrClosed
	}
	for {
		var size uint32
		p, _, e := d.receive.Call(d.session, uintptr(unsafe.Pointer(&size)))
		if p != 0 {
			if size > 65535 {
				d.release.Call(d.session, p)
				return 0, errors.New("oversized Wintun packet")
			}
			n := copy(b, wintunPacket(p, int(size)))
			d.release.Call(d.session, p)
			if n != int(size) {
				return 0, io.ErrShortBuffer
			}
			return n, nil
		}
		if e != syscall.Errno(259) {
			return 0, e
		}
		events := [2]uintptr{d.stopEvent, d.readEvent}
		result, _, e := tunKernel.NewProc("WaitForMultipleObjects").Call(2, uintptr(unsafe.Pointer(&events[0])), 0, 0xffffffff)
		if result == 0 {
			return 0, net.ErrClosed
		}
		if result != 1 {
			return 0, e
		}
	}
}
func (d *wintunDevice) Write(b []byte) (int, error) {
	if len(b) == 0 || len(b) > 65535 {
		return 0, errors.New("invalid Wintun packet size")
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.session == 0 {
		return 0, net.ErrClosed
	}
	p, _, e := d.allocate.Call(d.session, uintptr(len(b)))
	if p == 0 {
		return 0, e
	}
	copy(wintunPacket(p, len(b)), b)
	d.send.Call(d.session, p)
	return len(b), nil
}

// Interpret the foreign API's pointer-sized return value without Go heap pointer arithmetic.
func wintunPacket(p uintptr, n int) []byte { return unsafe.Slice(*(**byte)(unsafe.Pointer(&p)), n) }
func (d *wintunDevice) Close() error {
	d.once.Do(func() {
		if d.stopEvent != 0 {
			tunKernel.NewProc("SetEvent").Call(d.stopEvent)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.session != 0 {
			d.end.Call(d.session)
			d.session = 0
		}
		if d.adapter != 0 {
			d.closeAdapter.Call(d.adapter)
			d.adapter = 0
		}
		if d.stopEvent != 0 {
			syscall.CloseHandle(syscall.Handle(d.stopEvent))
		}
		d.dll.Release()
	})
	return nil
}
func (r *Runtime) prepareEndpointTUN() error {
	if err := r.refreshWindowsEgress(0); err != nil {
		return err
	}
	if r.tunEgress4.Load() == 0 && r.tunEgress6.Load() == 0 {
		return errors.New("no physical default route for TUN egress")
	}
	r.tunRouting.Store(true)
	return nil
}

func openTUN(r *Runtime, in Inbound) (*tunTunnel, error) {
	dll, e := loadWintun()
	if e != nil {
		return nil, e
	}
	d := &wintunDevice{dll: dll}
	find := func(name string) (*syscall.Proc, error) { return dll.FindProc(name) }
	for _, v := range []struct {
		name string
		dst  **syscall.Proc
	}{{"WintunReceivePacket", &d.receive}, {"WintunReleaseReceivePacket", &d.release}, {"WintunAllocateSendPacket", &d.allocate}, {"WintunSendPacket", &d.send}, {"WintunEndSession", &d.end}, {"WintunCloseAdapter", &d.closeAdapter}} {
		*v.dst, e = find(v.name)
		if e != nil {
			dll.Release()
			return nil, e
		}
	}
	success := false
	defer func() {
		if !success {
			d.Close()
			r.tunProtectMu.Lock()
			if r.tunProtectUsers == 0 {
				r.tunEgress4.Store(0)
				r.tunEgress6.Store(0)
				r.tunRouting.Store(false)
			}
			r.tunProtectMu.Unlock()
		}
	}()
	if in.AutoRoute {
		if e = r.refreshWindowsEgress(0); e != nil {
			return nil, e
		}
		if r.tunEgress4.Load() == 0 && r.tunEgress6.Load() == 0 {
			return nil, errors.New("no physical default route for TUN egress")
		}
		r.tunRouting.Store(true)
	}
	name := in.InterfaceName
	if name == "" {
		name = "Lanboat"
	}
	wname, _ := syscall.UTF16PtrFromString(name)
	kind, _ := syscall.UTF16PtrFromString("Lanboat")
	create, e := find("WintunCreateAdapter")
	if e != nil {
		return nil, e
	}
	d.adapter, _, e = create.Call(uintptr(unsafe.Pointer(wname)), uintptr(unsafe.Pointer(kind)), 0)
	if d.adapter == 0 {
		return nil, fmt.Errorf("create Wintun adapter (administrator required): %w", e)
	}
	getLUID, e := find("WintunGetAdapterLUID")
	if e != nil {
		return nil, e
	}
	getLUID.Call(d.adapter, uintptr(unsafe.Pointer(&d.luid)))
	start, e := find("WintunStartSession")
	if e != nil {
		return nil, e
	}
	d.session, _, e = start.Call(d.adapter, 1<<20)
	if d.session == 0 {
		return nil, e
	}
	getEvent, e := find("WintunGetReadWaitEvent")
	if e != nil {
		return nil, e
	}
	d.readEvent, _, e = getEvent.Call(d.session)
	if d.readEvent == 0 {
		return nil, e
	}
	d.stopEvent, _, e = tunKernel.NewProc("CreateEventW").Call(0, 1, 0, 0)
	if d.stopEvent == 0 {
		return nil, e
	}
	t := &tunTunnel{runtime: r, in: in, name: name, device: d}
	if in.AutoRoute {
		r.retainTUNProtection(0)
	}
	t.cleanup = func() {
		if t.routes != nil {
			_ = t.routes.replace(nil)
		}
		if in.AutoRoute {
			r.releaseTUNProtection()
		}
	}
	defer func() {
		if !success {
			t.cleanup()
		}
	}()
	mtu := in.MTU
	if mtu == 0 {
		mtu = 1500
	}
	configured := make(map[uint16]bool, 2)
	for _, value := range tunAddresses(in) {
		p, _ := netip.ParsePrefix(value)
		family := uint16(2)
		if p.Addr().Is6() {
			family = 23
		}
		if !configured[family] {
			if e = winConfigureIPInterface(d.luid, family, uint32(mtu)); e != nil {
				return nil, e
			}
			configured[family] = true
		}
		if e = winAddAddress(r.ctx, d.luid, p); e != nil {
			return nil, e
		}
		t.addLocal(p.Addr())
	}
	if in.AutoRoute {
		t.routes = &tunRouteState{add: func(p netip.Prefix) error { return winChangeRoute(d.luid, p, true) }, remove: func(p netip.Prefix) error { return winChangeRoute(d.luid, p, false) }}
		if e = t.routes.replace(t.routePlan(in)); e != nil {
			return nil, e
		}
	}
	r.network.exclude(t.name, true)
	success = true
	return t, nil
}
func (t *tunTunnel) configureDNS() error {
	if t.dnsMode() == "disabled" {
		return nil
	}
	if t.in.StrictRoute && t.in.AutoRoute {
		if e := t.blockDNSLeak(); e != nil {
			return e
		}
	}
	netsh, e := winSystemPath("netsh.exe")
	if e != nil {
		return e
	}
	count := map[string]int{}
	for _, address := range t.dnsAddresses() {
		ip := netip.MustParseAddr(address)
		family := "ipv4"
		if ip.Is6() {
			family = "ipv6"
		}
		count[family]++
		action := "set"
		args := []string{"source=static"}
		if count[family] > 1 {
			action = "add"
			args = []string{"index=" + strconv.Itoa(count[family])}
		}
		args = append([]string{"interface", family, action, "dnsservers", "name=" + t.name, "address=" + address, "validate=no"}, args...)
		if _, e = tunCommand(netsh, "", args...); e != nil {
			return e
		}
	}
	return nil
}
