//go:build darwin

package native

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"
)

var tunDarwinSequence atomic.Int32

func darwinRouteAddress(ip netip.Addr) []byte {
	b := make([]byte, 16)
	b[0], b[1] = 16, syscall.AF_INET
	offset := 4
	if ip.Is6() {
		b = make([]byte, 28)
		b[0], b[1] = 28, syscall.AF_INET6
		offset = 8
	}
	copy(b[offset:], ip.AsSlice())
	return b
}
func darwinRouteMessage(index int, p netip.Prefix, add bool) []byte {
	kind := uint8(syscall.RTM_DELETE)
	if add {
		kind = syscall.RTM_ADD
	}
	header := syscall.RtMsghdr{Version: syscall.RTM_VERSION, Type: kind, Index: uint16(index), Flags: syscall.RTF_UP | syscall.RTF_STATIC, Addrs: syscall.RTA_DST | syscall.RTA_GATEWAY | syscall.RTA_NETMASK, Pid: int32(os.Getpid()), Seq: tunDarwinSequence.Add(1)}
	gateway := make([]byte, 20)
	gateway[0], gateway[1] = 20, syscall.AF_LINK
	binary.NativeEndian.PutUint16(gateway[2:], uint16(index))
	mask := make([]byte, p.Addr().BitLen()/8)
	for i := 0; i < p.Bits(); i++ {
		mask[i/8] |= 1 << uint(7-i%8)
	}
	ip, _ := netip.AddrFromSlice(mask)
	body := append(darwinRouteAddress(p.Masked().Addr()), gateway...)
	body = append(body, darwinRouteAddress(ip)...)
	header.Msglen = uint16(int(unsafe.Sizeof(header)) + len(body))
	b := append([]byte{}, unsafe.Slice((*byte)(unsafe.Pointer(&header)), int(unsafe.Sizeof(header)))...)
	return append(b, body...)
}
func darwinChangeRoute(index int, p netip.Prefix, add bool) error {
	fd, e := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, 0)
	if e != nil {
		return e
	}
	defer syscall.Close(fd)
	syscall.CloseOnExec(fd)
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 3})
	request := darwinRouteMessage(index, p, add)
	if _, e = syscall.Write(fd, request); e != nil {
		return e
	}
	buffer := make([]byte, 4096)
	for {
		n, e := syscall.Read(fd, buffer)
		if e != nil {
			return e
		}

		for b := buffer[:n]; len(b) >= 92; {
			length := int(binary.NativeEndian.Uint16(b))
			if length < 92 || length > len(b) {
				break
			}
			if int32(binary.NativeEndian.Uint32(b[16:])) == int32(os.Getpid()) && binary.NativeEndian.Uint32(b[20:]) == binary.NativeEndian.Uint32(request[20:]) {
				code := int32(binary.NativeEndian.Uint32(b[24:]))
				if code != 0 {
					return syscall.Errno(code)
				}
				return nil
			}
			b = b[length:]
		}

	}
}
func (r *Runtime) refreshDarwinEgress(exclude int) error {
	b, e := syscall.RouteRIB(syscall.NET_RT_DUMP, 0)
	if e != nil {
		return e
	}
	messages, e := syscall.ParseRoutingMessage(b)
	if e != nil {
		return e
	}
	var ipv4, ipv6 int32
	var gateway4, gateway6 uint64
	for _, m := range messages {
		row, ok := m.(*syscall.RouteMessage)
		if !ok || int(row.Header.Index) == exclude || row.Header.Flags&syscall.RTF_UP == 0 || row.Header.Flags&(syscall.RTF_HOST|syscall.RTF_REJECT|syscall.RTF_BLACKHOLE|0x1000000) != 0 {
			continue
		}
		addresses, e := syscall.ParseRoutingSockaddr(row)
		if e != nil || len(addresses) <= syscall.RTAX_NETMASK {
			continue
		}
		zeroMask := false
		switch mask := addresses[syscall.RTAX_NETMASK].(type) {
		case nil:
			zeroMask = true
		case *syscall.SockaddrInet4:
			zeroMask = mask.Addr == [4]byte{}
		case *syscall.SockaddrInet6:
			zeroMask = mask.Addr == [16]byte{}
		}
		if !zeroMask {
			continue
		}
		switch dest := addresses[syscall.RTAX_DST].(type) {
		case *syscall.SockaddrInet4:
			if dest.Addr == [4]byte{} && ipv4 == 0 {
				ipv4 = int32(row.Header.Index)
				if gw, ok := addresses[syscall.RTAX_GATEWAY].(*syscall.SockaddrInet4); ok {
					gateway4 = tunGatewayKey(gw.Addr[:])
				}
			}
		case *syscall.SockaddrInet6:
			if dest.Addr == [16]byte{} && ipv6 == 0 {
				ipv6 = int32(row.Header.Index)
				if gw, ok := addresses[syscall.RTAX_GATEWAY].(*syscall.SockaddrInet6); ok {
					gateway6 = tunGatewayKey(gw.Addr[:])
				}
			}
		}
	}
	r.tunGateway4.Store(gateway4)
	r.tunGateway6.Store(gateway6)
	r.tunEgress4.Store(ipv4)
	r.tunEgress6.Store(ipv6)
	return nil
}
func (t *tunTunnel) configureMonitor() error {
	if !t.in.AutoRoute {
		return nil
	}
	fd, e := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, 0)
	if e != nil {
		return e
	}
	syscall.CloseOnExec(fd)
	if e = syscall.SetNonblock(fd, true); e != nil {
		syscall.Close(fd)
		return e
	}
	f := os.NewFile(uintptr(fd), "lanboat-network-events")
	previous := t.cleanup
	t.cleanup = func() { f.Close(); previous() }
	events := make(chan struct{}, 1)
	t.networkEvents = events
	t.monitor = func() { b := make([]byte, 65536); t.watchNetwork(func() error { _, e := f.Read(b); return e }, events) }
	iface, e := net.InterfaceByName(t.name)
	if e != nil {
		f.Close()
		return e
	}
	t.refreshEgress = func() error {
		if e := t.runtime.refreshDarwinEgress(iface.Index); e != nil {
			return e
		}
		t.refreshNetworkDNS()
		return nil
	}
	return nil
}
