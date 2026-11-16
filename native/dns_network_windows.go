//go:build windows

package native

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// IP_ADAPTER_ADDRESSES_LH prefix; only fields through OperStatus are read.
type dnsWindowsAdapter struct {
	Alignment              uint64
	Next                   *dnsWindowsAdapter
	Name                   *byte
	Unicast, Any, Multi    unsafe.Pointer
	DNS                    *dnsWindowsAddress
	Suffix, Desc, Friendly *uint16
	Physical               [8]byte
	PhysicalLength, Flags  uint32
	MTU, Type, Status      uint32
}
type dnsWindowsAddress struct {
	Alignment uint64
	Next      *dnsWindowsAddress
	Address   unsafe.Pointer
	Length    int32
}

func systemDNSNetwork() dnsNetworkState {
	var state dnsNetworkState
	addDomain := func(value string) {
		if len(state.domains) == 128 {
			return
		}
		value = canonicalDomain(value)
		if masqueDomain(value, false) && !slices.Contains(state.domains, value) {
			state.domains = append(state.domains, value)
		}
	}
	size := uint32(16384)
	get := tunIPHelper.NewProc("GetAdaptersAddresses")
	for range 3 {
		if size > 1<<20 {
			break
		}
		buffer := make([]byte, size)
		code, _, _ := get.Call(syscall.AF_UNSPEC, 0x27, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
		if code == 111 { // ERROR_BUFFER_OVERFLOW
			continue
		}
		if code != 0 {
			break
		}
		for adapter := (*dnsWindowsAdapter)(unsafe.Pointer(&buffer[0])); adapter != nil; adapter = adapter.Next {
			if adapter.Status != 1 { // IfOperStatusUp
				continue
			}
			if adapter.Suffix != nil {
				addDomain(syscall.UTF16ToString(unsafe.Slice(adapter.Suffix, 256)))
			}
			for item := adapter.DNS; item != nil; item = item.Next {
				if item.Address == nil || item.Length < 8 {
					continue
				}
				family := *(*uint16)(item.Address)
				var ip netip.Addr
				if family == syscall.AF_INET && item.Length >= 16 {
					ip = netip.AddrFrom4(*(*[4]byte)(unsafe.Add(item.Address, 4)))
				} else if family == syscall.AF_INET6 && item.Length >= 28 {
					ip = netip.AddrFrom16(*(*[16]byte)(unsafe.Add(item.Address, 8))).Unmap()
					if scope := *(*uint32)(unsafe.Add(item.Address, 24)); scope != 0 && ip.Is6() {
						ip = ip.WithZone(strconv.FormatUint(uint64(scope), 10))
					}
				}
				if len(state.servers) < 128 && ip.IsValid() && !ip.IsUnspecified() && !ip.IsMulticast() {
					if server := net.JoinHostPort(ip.String(), "53"); !slices.Contains(state.servers, server) {
						state.servers = append(state.servers, server)
					}
					if canonical := ip.WithZone(""); !slices.Contains(state.addresses, canonical) {
						state.addresses = append(state.addresses, canonical)
					}
				}
			}
		}
		break
	}
	path, _ := syscall.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`)
	var key syscall.Handle
	if syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, path, 0, syscall.KEY_QUERY_VALUE, &key) == nil {
		defer syscall.RegCloseKey(key)
		for _, name := range []string{"SearchList", "Domain", "NV Domain"} {
			n, _ := syscall.UTF16PtrFromString(name)
			value := make([]uint16, 32768)
			size, typ := uint32(len(value)*2), uint32(0)
			if syscall.RegQueryValueEx(key, n, nil, &typ, (*byte)(unsafe.Pointer(&value[0])), &size) == nil && typ == syscall.REG_SZ {
				for _, domain := range strings.FieldsFunc(syscall.UTF16ToString(value[:size/2]), func(c rune) bool { return c == ',' || c == ' ' }) {
					addDomain(domain)
				}
			}
		}
	}
	return state
}
