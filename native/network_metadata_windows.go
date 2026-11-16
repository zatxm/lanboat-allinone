//go:build windows

package native

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

func windowsDefaultIndex(ipv6 bool) uint32 {
	var address [28]byte
	address[0] = syscall.AF_INET
	copy(address[4:8], []byte{1, 1, 1, 1})
	if ipv6 {
		address[0] = syscall.AF_INET6
		copy(address[8:24], []byte{0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11})
	}
	var index uint32
	code, _, _ := tunIPHelper.NewProc("GetBestInterfaceEx").Call(uintptr(unsafe.Pointer(&address[0])), uintptr(unsafe.Pointer(&index)))
	if code != 0 {
		return 0
	}
	return index
}
func systemNetworkMetadata(ctx context.Context, r *Runtime) Metadata {
	result := Metadata{NetworkInterfaceAddress: map[string][]netip.Addr{}}
	selectedIndex := uint32(0)
	defaults := [2]uint32{windowsDefaultIndex(false), windowsDefaultIndex(true)}
	if defaults[0] != 0 || defaults[1] != 0 {
		result.DefaultInterfaceAddress = []netip.Addr{}
	}
	size := uint32(16384)
	for range 3 {
		if size > 1<<20 || ctx.Err() != nil {
			return Metadata{}
		}
		buffer := make([]byte, size)
		code, _, _ := tunIPHelper.NewProc("GetAdaptersAddresses").Call(syscall.AF_UNSPEC, 0x0e, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
		if code == 111 {
			continue
		}
		if code != 0 {
			return Metadata{}
		}
		for adapter := (*dnsWindowsAdapter)(unsafe.Pointer(&buffer[0])); adapter != nil; adapter = adapter.Next {
			if adapter.Status != 1 || adapter.Type == 24 {
				continue
			}
			kind := "other"
			switch adapter.Type {
			case 6:
				kind = "ethernet"
			case 71:
				kind = "wifi"
			case 243, 244:
				kind = "cellular"
			}
			index := uint32(adapter.Alignment >> 32)
			selected := index != 0 && (index == defaults[0] || index == defaults[1])
			if name := r.config.Route.DefaultInterface; name != "" && !r.config.Route.AutoDetectInterface {
				friendly := ""
				if adapter.Friendly != nil {
					friendly = syscall.UTF16ToString(unsafe.Slice(adapter.Friendly, 256))
				}
				selected = strings.EqualFold(name, friendly)
			}
			iface, _ := net.InterfaceByIndex(int(index))
			name := ""
			if iface != nil {
				name = iface.Name
			}
			choice := networkChoice{Name: name, Kind: kind}
			for item := (*dnsWindowsAddress)(adapter.Unicast); item != nil; item = item.Next {
				if item.Address == nil {
					continue
				}
				family := *(*uint16)(item.Address)
				var ip netip.Addr
				if family == syscall.AF_INET && item.Length >= 16 {
					ip = netip.AddrFrom4(*(*[4]byte)(unsafe.Add(item.Address, 4)))
				} else if family == syscall.AF_INET6 && item.Length >= 28 {
					ip = netip.AddrFrom16(*(*[16]byte)(unsafe.Add(item.Address, 8))).Unmap()
				}
				if !ip.IsValid() || ip.IsUnspecified() {
					continue
				}
				choice.Addresses = append(choice.Addresses, ip)
				if selected && r.config.Route.DefaultInterface != "" && !r.config.Route.AutoDetectInterface || ip.Is4() && index == defaults[0] || ip.Is6() && index == defaults[1] {
					if ip.Is4() {
						choice.Default4 = true
					} else {
						choice.Default6 = true
					}
				}
				result.NetworkInterfaceAddress[kind] = append(result.NetworkInterfaceAddress[kind], ip)
				if selected {
					result.DefaultInterfaceAddress = append(result.DefaultInterfaceAddress, ip)
				}
			}
			if choice.Name != "" {
				result.networkChoices = append(result.networkChoices, choice)
			}
			if selected && (result.NetworkType == "" || index == defaults[0]) {
				result.NetworkType = kind
				selectedIndex = index
			}
		}
		break
	}
	windowsWiFiMetadata(&result, selectedIndex)
	windowsCostMetadata(&result)
	return result
}

func windowsWiFiMetadata(m *Metadata, selectedIndex uint32) {
	if m.NetworkType != "wifi" || selectedIndex == 0 {
		return
	}
	library := syscall.NewLazyDLL("wlanapi.dll")
	if library.Load() != nil {
		return
	}
	var handle syscall.Handle
	var version uint32
	code, _, _ := library.NewProc("WlanOpenHandle").Call(2, 0, uintptr(unsafe.Pointer(&version)), uintptr(unsafe.Pointer(&handle)))
	if code != 0 {
		return
	}
	defer library.NewProc("WlanCloseHandle").Call(uintptr(handle), 0)
	var list unsafe.Pointer
	code, _, _ = library.NewProc("WlanEnumInterfaces").Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&list)))
	if code != 0 || list == nil {
		return
	}
	defer library.NewProc("WlanFreeMemory").Call(uintptr(list))
	count := *(*uint32)(list)
	if count > 128 {
		return
	}
	for i := uint32(0); i < count; i++ {
		info := unsafe.Add(list, 8+uintptr(i)*532)
		var luid uint64
		var index uint32
		converted, _, _ := tunIPHelper.NewProc("ConvertInterfaceGuidToLuid").Call(uintptr(info), uintptr(unsafe.Pointer(&luid)))
		if converted != 0 {
			continue
		}
		converted, _, _ = tunIPHelper.NewProc("ConvertInterfaceLuidToIndex").Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&index)))
		if converted != 0 || index != selectedIndex {
			continue
		}
		if *(*uint32)(unsafe.Add(info, 528)) != 1 {
			continue
		}
		var size, typ uint32
		var value unsafe.Pointer
		code, _, _ = library.NewProc("WlanQueryInterface").Call(uintptr(handle), uintptr(info), 7, 0, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&typ)))
		if code != 0 || value == nil {
			continue
		}
		if size >= 588 {
			length := *(*uint32)(unsafe.Add(value, 520))
			if length <= 32 {
				m.WiFiSSID = string(unsafe.Slice((*byte)(unsafe.Add(value, 524)), length))
				bssid := unsafe.Slice((*byte)(unsafe.Add(value, 560)), 6)
				var b strings.Builder
				for j, x := range bssid {
					if j > 0 {
						b.WriteByte(':')
					}
					if x < 16 {
						b.WriteByte('0')
					}
					b.WriteString(strconv.FormatUint(uint64(x), 16))
				}
				m.WiFiBSSID = b.String()
			}
		}
		library.NewProc("WlanFreeMemory").Call(uintptr(value))
		return
	}
}

func windowsCostMetadata(m *Metadata) {
	// COM initialization is thread-local, so keep all interface calls on one thread.
	windowsNetworkCost(m)
}
