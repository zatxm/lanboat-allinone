//go:build darwin

package native

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"go.uber.org/zap"
)

func systemDNSBeforeTUN() []string {
	text, e := tunCommand("/usr/sbin/scutil", "", "--dns")
	if e != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || !strings.HasPrefix(key, "nameserver[") {
			continue
		}
		ip, e := netip.ParseAddr(strings.TrimSpace(value))
		if e == nil && !ip.IsLoopback() && !seen[ip.String()] {
			seen[ip.String()] = true
			out = append(out, net.JoinHostPort(ip.String(), "53"))
		}
	}
	return out
}

func validateTUNPlatform(in Inbound) error {
	if in.linuxTUNOptions() {
		return errors.New("Linux TUN options cannot be used on macOS")
	}
	if in.AutoRedirect {
		return errors.New("auto_redirect requires Linux nftables")
	}
	if in.InterfaceName != "" {
		n, e := strconv.ParseUint(strings.TrimPrefix(in.InterfaceName, "utun"), 10, 16)
		if e != nil || in.InterfaceName != "utun"+strconv.FormatUint(n, 10) {
			return errors.New("macOS TUN name must be utun followed by an integer")
		}
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
			optionErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, 125, int(index))
		} else {
			optionErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 25, int(index))
		}
	})
	if e != nil {
		return e
	}
	return optionErr
}

func (r *Runtime) prepareEndpointTUN() error {
	if err := r.refreshDarwinEgress(0); err != nil {
		return err
	}
	if r.tunEgress4.Load() == 0 && r.tunEgress6.Load() == 0 {
		return errors.New("no physical default route for TUN egress")
	}
	r.tunRouting.Store(true)
	return nil
}

func openTUN(r *Runtime, in Inbound) (*tunTunnel, error) {
	if in.AutoRoute {
		if e := r.refreshDarwinEgress(0); e != nil {
			return nil, e
		}
		if r.tunEgress4.Load() == 0 && r.tunEgress6.Load() == 0 {
			return nil, errors.New("no physical default route for TUN egress")
		}
		r.tunRouting.Store(true)
	}
	fd, e := syscall.Socket(32, syscall.SOCK_DGRAM, 2)
	if e != nil {
		return nil, fmt.Errorf("utun socket: %w", e)
	}
	success := false
	var file *os.File
	defer func() {
		if !success {
			if file != nil {
				file.Close()
			} else {
				syscall.Close(fd)
			}
			r.tunProtectMu.Lock()
			if r.tunProtectUsers == 0 {
				r.tunEgress4.Store(0)
				r.tunEgress6.Store(0)
				r.tunRouting.Store(false)
			}
			r.tunProtectMu.Unlock()
		}
	}()
	syscall.CloseOnExec(fd)
	var info [100]byte
	copy(info[4:], "com.apple.net.utun_control")
	if _, _, code := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0xc0644e03, uintptr(unsafe.Pointer(&info[0]))); code != 0 {
		return nil, fmt.Errorf("utun controller: %w", code)
	}
	var address [32]byte
	address[0], address[1] = 32, 32
	binary.NativeEndian.PutUint16(address[2:], 2)
	copy(address[4:8], info[:4])
	if in.InterfaceName != "" {
		n, _ := strconv.Atoi(in.InterfaceName[4:])
		binary.NativeEndian.PutUint32(address[8:], uint32(n+1))
	}
	if _, _, code := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&address[0])), 32); code != 0 {
		return nil, fmt.Errorf("create utun (root required): %w", code)
	}
	var name [64]byte
	length := uint32(len(name))
	if _, _, code := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), 2, 2, uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&length)), 0); code != 0 {
		return nil, code
	}
	ifaceName := strings.TrimRight(string(name[:min(length, uint32(len(name)))]), "\x00")
	if e = syscall.SetNonblock(fd, true); e != nil {
		return nil, e
	}
	file = os.NewFile(uintptr(fd), ifaceName)
	device := &framedTUN{ReadWriteCloser: file}
	t := &tunTunnel{runtime: r, in: in, name: ifaceName, device: device}
	if in.AutoRoute {
		r.retainTUNProtection(0)
	}
	t.cleanup = func() {
		if t.routes != nil {
			if e := t.routes.replace(nil); e != nil {
				r.logger.Warn("remove TUN routes", zap.Error(e))
			}
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
	for _, value := range tunAddresses(in) {
		p, _ := netip.ParsePrefix(value)
		args := []string{ifaceName, "inet6", p.String(), "alias"}
		if p.Addr().Is4() {
			args = []string{ifaceName, "inet", p.Addr().String(), p.Addr().String(), "netmask", net.IP(net.CIDRMask(p.Bits(), 32)).String(), "alias"}
		}
		if _, e := tunCommand("/sbin/ifconfig", "", args...); e != nil {
			return nil, e
		}
		t.addLocal(p.Addr())
	}
	mtu := in.MTU
	if mtu == 0 {
		mtu = 1500
	}
	if _, e := tunCommand("/sbin/ifconfig", "", ifaceName, "mtu", strconv.Itoa(mtu), "up"); e != nil {
		return nil, e
	}
	if in.AutoRoute {
		iface, e := net.InterfaceByName(ifaceName)
		if e != nil {
			return nil, e
		}
		t.routes = &tunRouteState{add: func(p netip.Prefix) error { return darwinChangeRoute(iface.Index, p, true) }, remove: func(p netip.Prefix) error { return darwinChangeRoute(iface.Index, p, false) }}
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
	key := fmt.Sprintf("State:/Network/Service/lanboat-%d-%s", os.Getpid(), t.name)
	var input strings.Builder
	for _, a := range []netip.Addr{t.local4, t.local6} {
		if !a.IsValid() {
			continue
		}
		family := "IPv4"
		if a.Is6() {
			family = "IPv6"
		}
		fmt.Fprintf(&input, "d.init\nd.add InterfaceName %s\nd.add Addresses * %s\nadd %s/%s temporary\n", t.name, a, key, family)
	}
	fmt.Fprintf(&input, "d.init\nd.add ServerAddresses * %s\nd.add SupplementalMatchDomains * \"\"\nd.add SupplementalMatchOrders # 1\nd.add InterfaceName %s\nadd %s/DNS temporary\n", strings.Join(t.dnsAddresses(), " "), t.name, key)
	// The dynamic-store session owns temporary keys. EOF also restores DNS after a parent crash.
	command := exec.Command("/usr/sbin/scutil")
	writer, e := command.StdinPipe()
	if e != nil {
		return e
	}
	if e = command.Start(); e != nil {
		writer.Close()
		return e
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	previous := t.cleanup
	t.cleanup = func() {
		writer.Close()
		select {
		case e := <-exited:
			if e != nil {
				t.runtime.logger.Debug("TUN DNS session ended", zap.Error(e))
			}
		case <-time.After(3 * time.Second):
			command.Process.Kill()
			<-exited
		}
		previous()
	}
	if _, e = io.WriteString(writer, input.String()); e != nil {
		return e
	}
	_, e = tunCommand("/usr/sbin/scutil", "", "-w", key+"/DNS", "-t", "3")
	return e
}
