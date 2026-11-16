//go:build windows

package native

import (
	"context"
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"syscall"
	"unsafe"
)

func (*processFinder) lookup(ctx context.Context, origin socketOrigin) (string, string) {
	source, err := netip.ParseAddrPort(origin.source)
	if err != nil || ctx.Err() != nil {
		return "", ""
	}
	destination, err := netip.ParseAddrPort(origin.destination)
	if err != nil {
		return "", ""
	}
	ipv6 := source.Addr().Is6() && !source.Addr().Is4In6()
	family, rowSize, portOffset, pidOffset := uintptr(syscall.AF_INET), 24, 8, 20
	function, class := "GetExtendedTcpTable", uintptr(5)
	if ipv6 {
		family, rowSize, portOffset, pidOffset = syscall.AF_INET6, 56, 20, 52
	}
	if origin.network == "udp" {
		function, class = "GetExtendedUdpTable", 1
		rowSize, portOffset, pidOffset = 12, 4, 8
		if ipv6 {
			rowSize, portOffset, pidOffset = 28, 20, 24
		}
	} else if origin.network != "tcp" {
		return "", ""
	}
	get := tunIPHelper.NewProc(function)
	size := uint32(0)
	code, _, _ := get.Call(0, uintptr(unsafe.Pointer(&size)), 0, family, class, 0)
	if code != 122 || size < 4 || size > 16<<20 {
		return "", ""
	}
	var table []byte
	for range 3 {
		table = make([]byte, size)
		code, _, _ = get.Call(uintptr(unsafe.Pointer(&table[0])), uintptr(unsafe.Pointer(&size)), 0, family, class, 0)
		if code != 122 {
			break
		}
		if size > 16<<20 {
			return "", ""
		}
	}
	if code != 0 || ctx.Err() != nil || size > uint32(len(table)) {
		return "", ""
	}
	count := int(binary.LittleEndian.Uint32(table))
	if count > (int(size)-4)/rowSize {
		return "", ""
	}
	var pid uint32
	best, ambiguous := 0, false
	for i := range count {
		row := table[4+i*rowSize : 4+(i+1)*rowSize]
		if binary.BigEndian.Uint16(row[portOffset:]) != source.Port() {
			continue
		}
		offset := 4
		if ipv6 || origin.network != "tcp" {
			offset = 0
		}
		local := netip.AddrFrom4([4]byte(row[offset : offset+4]))
		if ipv6 {
			local = netip.AddrFrom16([16]byte(row[:16]))
		}
		score := 1
		if local.Unmap() == source.Addr().Unmap().WithZone("") {
			score = 2
		} else if !local.IsUnspecified() {
			continue
		}
		if origin.network == "tcp" {
			remoteOffset, remotePort := 12, 16
			if ipv6 {
				remoteOffset, remotePort = 24, 44
			}
			remote := netip.AddrFrom4([4]byte(row[remoteOffset : remoteOffset+4]))
			if ipv6 {
				remote = netip.AddrFrom16([16]byte(row[remoteOffset : remoteOffset+16]))
			}
			if remote.Unmap() != destination.Addr().Unmap().WithZone("") || binary.BigEndian.Uint16(row[remotePort:]) != destination.Port() {
				continue
			}
		}
		current := binary.LittleEndian.Uint32(row[pidOffset:])
		if current == 0 {
			continue
		}
		if score > best {
			pid, best, ambiguous = current, score, false
		} else if score == best && current != pid {
			ambiguous = true
		}
	}
	if pid == 0 || ambiguous || ctx.Err() != nil {
		return "", ""
	}
	handle, err := syscall.OpenProcess(0x1000, false, pid)
	if err != nil {
		return "", ""
	}
	defer syscall.CloseHandle(handle)
	buffer := make([]uint16, 32768)
	length := uint32(len(buffer))
	ok, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("QueryFullProcessImageNameW").Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&length)))
	if ok == 0 || length > uint32(len(buffer)) {
		return "", ""
	}
	path := syscall.UTF16ToString(buffer[:length])
	return filepath.Base(path), path
}
