//go:build linux

package native

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"go.uber.org/zap"
)

func (r *Runtime) prepareEndpointTUN() error { return nil }

func systemDNSBeforeTUN() []string {
	for _, path := range []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"} {
		f, e := os.Open(path)
		if e != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		var ips []string
		for scanner.Scan() {
			parts := strings.Fields(scanner.Text())
			if len(parts) > 1 && parts[0] == "nameserver" {
				if ip, e := netip.ParseAddr(parts[1]); e == nil && !ip.IsLoopback() {
					ips = append(ips, net.JoinHostPort(ip.String(), "53"))
				}
			}
		}
		f.Close()
		if len(ips) > 0 {
			return ips
		}
	}
	return nil
}

func validateTUNPlatform(in Inbound) error {
	if in.AutoRedirect && !in.AutoRoute {
		return errors.New("auto_redirect requires auto_route")
	}
	if len(in.InterfaceName) > 15 || strings.ContainsAny(in.InterfaceName, "/\x00\r\n\t ") || in.InterfaceName == "." || in.InterfaceName == ".." {
		return errors.New("invalid Linux TUN interface name")
	}
	return nil
}

func (t *tunTunnel) configureDNS() error {
	if t.namespace != nil {
		return nil
	}
	if t.dnsMode() == "disabled" {
		return nil
	}
	// A host D-Bus socket is visible in unshared network namespaces; never configure it there.
	own, _ := os.Readlink("/proc/self/ns/net")
	initial, _ := os.Readlink("/proc/1/ns/net")
	_, busErr := os.Stat("/run/dbus/system_bus_socket")
	_, toolErr := os.Stat("/usr/bin/resolvectl")
	if own != initial || busErr != nil || toolErr != nil {
		if t.dnsMode() == "native" {
			return errors.New("native DNS requires systemd-resolved in the current network namespace")
		}
		t.runtime.logger.Debug("system DNS unavailable; port53 hijack remains enabled")
		return nil
	}
	args := append([]string{"dns", t.name}, t.dnsAddresses()...)
	if _, e := tunCommand("/usr/bin/resolvectl", "", "status"); e != nil {
		if t.dnsMode() == "native" {
			return e
		}
		t.runtime.logger.Debug("systemd-resolved unavailable; port53 hijack remains enabled")
		return nil
	}
	if _, e := tunCommand("/usr/bin/resolvectl", "", args...); e != nil {
		return e
	}
	previous := t.cleanup
	t.cleanup = func() {
		if _, e := tunCommand("/usr/bin/resolvectl", "", "revert", t.name); e != nil {
			t.runtime.logger.Warn("restore TUN DNS", zap.Error(e))
		}
		if previous != nil {
			previous()
		}
	}
	if _, e := tunCommand("/usr/bin/resolvectl", "", "domain", t.name, "~."); e != nil {
		return e
	}
	_, e := tunCommand("/usr/bin/resolvectl", "", "default-route", t.name, "yes")
	return e
}

func (r *Runtime) socketControlFor(o DialOptions, network, address string, raw syscall.RawConn) error {
	ifaceName := r.config.Route.DefaultInterface
	if r.config.Route.AutoDetectInterface {
		ifaceName = ""
	}
	if o.BindInterface != "" {
		ifaceName = o.BindInterface
	}
	mark := r.protectMark.Load()
	if mark != 0 && o.RoutingMark != 0 && uint32(o.RoutingMark) != mark {
		return errors.New("routing_mark conflicts with the active TUN protection mark")
	}
	if mark == 0 {
		mark = uint32(r.config.Route.DefaultMark)
		if o.RoutingMark != 0 {
			mark = uint32(o.RoutingMark)
		}
	}
	if mark == 0 && ifaceName == "" {
		return nil
	}
	var optionErr error
	err := raw.Control(func(fd uintptr) {
		if mark != 0 {
			optionErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 36, int(mark))
		}
		if optionErr == nil && ifaceName != "" {
			optionErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifaceName)
		}
	})
	if err != nil {
		return err
	}
	return optionErr
}
func nlAttribute(kind uint16, data []byte) []byte {
	n := 4 + len(data)
	out := make([]byte, (n+3)&^3)
	binary.NativeEndian.PutUint16(out, uint16(n))
	binary.NativeEndian.PutUint16(out[2:], kind)
	copy(out[4:], data)
	return out
}
func nlU32(kind uint16, value uint32) []byte {
	data := make([]byte, 4)
	binary.NativeEndian.PutUint32(data, value)
	return nlAttribute(kind, data)
}
func openTunNetlink() (int, error) {
	fd, e := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if e != nil {
		return -1, e
	}
	if e = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 3}); e == nil {
		e = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
	}
	if e != nil {
		syscall.Close(fd)
		return -1, e
	}
	return fd, nil
}
func netlinkChange(kind uint16, body []byte, create bool) error {
	fd, e := openTunNetlink()
	if e != nil {
		return e
	}
	defer syscall.Close(fd)
	return tunNetlinkChange(fd, 1, kind, body, create)
}
func tunNetlinkChange(fd int, sequence uint32, kind uint16, body []byte, create bool) error {
	flags := uint16(1 | 4)
	if create {
		flags |= 0x600
	}
	packet := make([]byte, 16+len(body))
	binary.NativeEndian.PutUint32(packet, uint32(len(packet)))
	binary.NativeEndian.PutUint16(packet[4:], kind)
	binary.NativeEndian.PutUint16(packet[6:], flags)
	binary.NativeEndian.PutUint32(packet[8:], sequence)
	copy(packet[16:], body)
	if err := syscall.Sendto(fd, packet, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	var reply [4096]byte
	for {
		n, _, err := syscall.Recvfrom(fd, reply[:], 0)
		if err != nil {
			return err
		}
		messages, err := syscall.ParseNetlinkMessage(reply[:n])
		if err != nil {
			return err
		}
		for _, message := range messages {
			if message.Header.Type == syscall.NLMSG_ERROR && message.Header.Seq == sequence {
				if len(message.Data) < 4 {
					return errors.New("truncated netlink acknowledgement")
				}
				code := int32(binary.NativeEndian.Uint32(message.Data))
				if code == 0 {
					return nil
				}
				return syscall.Errno(-code)
			}
		}
	}
}
func configureLink(index, mtu int) error {
	body := make([]byte, 16)
	binary.NativeEndian.PutUint32(body[4:], uint32(index))
	binary.NativeEndian.PutUint32(body[8:], syscall.IFF_UP)
	binary.NativeEndian.PutUint32(body[12:], syscall.IFF_UP)
	if mtu > 0 {
		body = append(body, nlU32(4, uint32(mtu))...)
	}
	return netlinkChange(16, body, false)
}
func addTunAddress(index int, prefix netip.Prefix) error {
	family := byte(syscall.AF_INET)
	if prefix.Addr().Is6() {
		family = syscall.AF_INET6
	}
	body := []byte{family, byte(prefix.Bits()), 2, 0, 0, 0, 0, 0}
	binary.NativeEndian.PutUint32(body[4:], uint32(index))
	body = append(body, nlAttribute(1, prefix.Addr().AsSlice())...)
	body = append(body, nlAttribute(2, prefix.Addr().AsSlice())...)
	return netlinkChange(20, body, true)
}
func tunRoute(index int, table uint32, family byte) []byte {
	body := []byte{family, 0, 0, 0, 0, 4, 253, 1, 0, 0, 0, 0}
	body = append(body, nlU32(15, table)...)
	return append(body, nlU32(4, uint32(index))...)
}
func tunRule(table, priority, mark uint32, family byte) []byte {
	body := []byte{family, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}
	binary.NativeEndian.PutUint32(body[8:], 2)
	body = append(body, nlU32(15, table)...)
	body = append(body, nlU32(6, priority)...)
	body = append(body, nlU32(10, mark)...)
	return append(body, nlU32(16, 0xffffffff)...)
}
func openTUN(r *Runtime, in Inbound) (*tunTunnel, error) {
	if in.namespace != nil {
		return in.namespace.openTUN(r, in)
	}
	if in.InterfaceName == "" {
		in.InterfaceName = "lanboat%d"
	}
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open TUN: %w", err)
	}
	var request [40]byte
	copy(request[:16], in.InterfaceName)
	flags := uint16(0x1001)
	if in.exclusiveTUN {
		flags |= 0x8000 // IFF_TUN_EXCL: never attach to an existing interface.
	}
	if in.MultiQueue {
		flags |= 0x100
	}
	binary.NativeEndian.PutUint16(request[16:], flags)
	_, _, code := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x400454ca, uintptr(unsafe.Pointer(&request[0])))
	if code != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("create TUN (CAP_NET_ADMIN required): %w", code)
	}
	name := string(request[:16])
	for i, b := range []byte(name) {
		if b == 0 {
			name = name[:i]
			break
		}
	}
	device := os.NewFile(uintptr(fd), name)
	t := &tunTunnel{runtime: r, in: in, device: device, name: name, queues: []io.ReadWriteCloser{device}}
	success := false
	var rules [][]byte
	var routes [][]byte
	protected := false
	t.cleanup = func() {
		if t.routes != nil {
			_ = t.routes.replace(nil)
		}
		for i := len(routes) - 1; i >= 0; i-- {
			_ = netlinkChange(25, routes[i], false)
		}
		for i := len(rules) - 1; i >= 0; i-- {
			_ = netlinkChange(33, rules[i], false)
		}
		if protected {
			r.releaseTUNProtection()
		}
	}
	defer func() {
		if !success {
			t.cleanup()
			for _, q := range t.queues {
				q.Close()
			}
		}
	}()

	if in.MultiQueue {
		for range min(4, runtime.GOMAXPROCS(0)) - 1 {
			fd, e := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
			if e != nil {
				return nil, e
			}
			var req [40]byte
			copy(req[:16], name)
			binary.NativeEndian.PutUint16(req[16:], flags)
			_, _, code := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x400454ca, uintptr(unsafe.Pointer(&req[0])))
			if code != 0 {
				syscall.Close(fd)
				return nil, code
			}
			t.queues = append(t.queues, os.NewFile(uintptr(fd), name))
		}
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	mtu := in.MTU
	if mtu == 0 {
		mtu = 1500
	}
	if err = configureLink(iface.Index, mtu); err != nil {
		return nil, err
	}
	addresses := tunAddresses(in)
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address)
		if err != nil {
			return nil, err
		}
		if err = addTunAddress(iface.Index, prefix); err != nil {
			return nil, err
		}
		t.addLocal(prefix.Addr())
	}
	t.mark = 0x4c420000 | uint32(iface.Index&65535)
	if in.AutoRedirect {
		_, t.mark, _, _ = in.redirectMarks()
	}
	if in.AutoRoute {
		requestedMark := t.mark
		t.mark = r.retainTUNProtection(t.mark)
		protected = true
		if in.AutoRedirect && requestedMark != t.mark {
			return nil, errors.New("auto_redirect mark conflicts with another active system interface")
		}
	}
	table, priority := in.IPRoute2TableIndex, in.IPRoute2RuleIndex
	if table == 0 {
		table = 2022
	}
	if priority == 0 {
		priority = 9000
	}
	if in.endpointSystem {
		table = 30000 + uint32(iface.Index)
		priority = 20000 + 16*uint32(iface.Index)
	}
	bodyFor := func(p netip.Prefix) []byte {
		family := byte(syscall.AF_INET)
		local := t.local4
		if p.Addr().Is6() {
			family = syscall.AF_INET6
			local = t.local6
		}
		body := tunRoute(iface.Index, table, family)
		body[1] = byte(p.Bits())
		if !local.IsValid() {
			body = []byte{family, byte(p.Bits()), 0, 0, 0, 4, 0, 7, 0, 0, 0, 0}
			body = append(body, nlU32(15, table)...)
		}
		return append(body, nlAttribute(1, p.Masked().Addr().AsSlice())...)
	}
	if in.AutoRoute {

		routeFD, e := openTunNetlink()
		if e != nil {
			return nil, e
		}
		var sequence uint32
		previous := t.cleanup
		t.cleanup = func() { previous(); syscall.Close(routeFD) }
		change := func(p netip.Prefix, add bool) error {
			sequence++
			kind := uint16(25)
			if add {
				kind = 24
			}
			return tunNetlinkChange(routeFD, sequence, kind, bodyFor(p), add)
		}
		t.routes = &tunRouteState{add: func(p netip.Prefix) error { return change(p, true) }, remove: func(p netip.Prefix) error { return change(p, false) }}

		plan := t.routePlan(in)
		if in.AutoRedirect {
			base := in
			base.RouteAddress = nil
			base.RouteExcludeAddress = nil
			base.RouteAddressSet = nil
			base.RouteExcludeAddressSet = nil
			plan = t.routePlan(base)
		}
		if err = t.routes.replace(plan); err != nil {
			return nil, err
		}
		for _, family := range []byte{syscall.AF_INET, syscall.AF_INET6} {
			local := t.local4
			if family == syscall.AF_INET6 {
				local = t.local6
			}
			if !local.IsValid() && !in.StrictRoute {
				continue
			}
			bodies := tunPolicyRules(in, table, priority, t.mark, family, t.name)
			for _, body := range bodies {
				if err = netlinkChange(32, body, true); err != nil {
					return nil, err
				}
				rules = append(rules, body)
			}
		}
	}
	if in.AutoRedirect {
		if err = t.configureRedirect(); err != nil {
			return nil, err
		}
	}
	r.network.exclude(t.name, true)
	success = true
	return t, nil
}
