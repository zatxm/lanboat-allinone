//go:build windows

package native

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"
)

type winRouteRow struct {
	LUID                                               uint64
	Index                                              uint32
	Destination                                        [28]byte
	PrefixLength                                       uint8
	_                                                  [3]byte
	NextHop                                            [28]byte
	SitePrefixLength                                   uint8
	_                                                  [3]byte
	ValidLifetime, PreferredLifetime, Metric, Protocol uint32
	Loopback, Autoconfigure, Publish, Immortal         uint8
	Age, Origin                                        uint32
}

func winRouteAddress(ip netip.Addr) (a [28]byte) {
	family := uint16(2)
	offset := 4
	if ip.Is6() {
		family = 23
		offset = 8
	}
	binary.NativeEndian.PutUint16(a[:], family)
	copy(a[offset:], ip.AsSlice())
	return
}
func winChangeRoute(luid uint64, p netip.Prefix, add bool) error {
	row := winRouteRow{}
	tunIPHelper.NewProc("InitializeIpForwardEntry").Call(uintptr(unsafe.Pointer(&row)))
	row.LUID = luid
	row.Destination = winRouteAddress(p.Masked().Addr())
	row.PrefixLength = uint8(p.Bits())
	row.NextHop = winRouteAddress(netip.IPv4Unspecified())
	if p.Addr().Is6() {
		row.NextHop = winRouteAddress(netip.IPv6Unspecified())
	}
	row.Protocol = 3
	name := "DeleteIpForwardEntry2"
	if add {
		name = "CreateIpForwardEntry2"
	}
	code, _, _ := tunIPHelper.NewProc(name).Call(uintptr(unsafe.Pointer(&row)))
	if code != 0 {
		return fmt.Errorf("%s %s: %w", name, p, syscall.Errno(code))
	}
	return nil
}
func (r *Runtime) refreshWindowsEgress(exclude uint64) error {
	var table uintptr
	code, _, _ := tunIPHelper.NewProc("GetIpForwardTable2").Call(0, uintptr(unsafe.Pointer(&table)))
	if code != 0 {
		return syscall.Errno(code)
	}
	defer tunIPHelper.NewProc("FreeMibTable").Call(table)
	count := binary.NativeEndian.Uint32(wintunPacket(table, 4))
	if count > 1<<20 {
		return fmt.Errorf("invalid Windows route count: %d", count)
	}
	rows := wintunPacket(table, 8+int(count)*104)[8:]
	var best4, best6 int32
	var gateway4, gateway6 uint64
	metric4, metric6 := uint64(^uint32(0)), uint64(^uint32(0))
	for i := 0; i < int(count); i++ {
		b := rows[i*104:]
		if b[40] != 0 || b[92] != 0 || binary.NativeEndian.Uint64(b) == exclude {
			continue
		}
		family := binary.NativeEndian.Uint16(b[12:])
		index := int32(binary.NativeEndian.Uint32(b[8:]))
		metric := uint64(binary.NativeEndian.Uint32(b[84:]))
		// GetIpInterfaceEntry adds the interface cost to the route's own metric.
		var storage [24]uint64
		iface := unsafe.Slice((*byte)(unsafe.Pointer(&storage[0])), 192)
		binary.NativeEndian.PutUint16(iface[:], family)
		copy(iface[8:16], b[:8])
		if c, _, _ := tunIPHelper.NewProc("GetIpInterfaceEntry").Call(uintptr(unsafe.Pointer(&iface[0]))); c == 0 {
			metric += uint64(binary.NativeEndian.Uint32(iface[148:]))
		}
		if family == 2 && metric < metric4 {
			best4, metric4 = index, metric
			gateway4 = tunGatewayKey(b[48:52])
		}
		if family == 23 && metric < metric6 {
			best6, metric6 = index, metric
			gateway6 = tunGatewayKey(b[52:72])
		}
	}
	r.tunGateway4.Store(gateway4)
	r.tunGateway6.Store(gateway6)
	r.tunEgress4.Store(best4)
	r.tunEgress6.Store(best6)
	return nil
}
