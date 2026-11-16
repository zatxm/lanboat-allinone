package native

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"time"
)

func systemNeighbors(ctx context.Context) map[netip.Addr]neighborEntry {
	if ctx.Err() != nil {
		return nil
	}
	data, err := syscall.RouteRIB(syscall.NET_RT_FLAGS, syscall.RTF_LLINFO)
	if err != nil || len(data) > neighborLeaseBytes {
		return nil
	}
	messages, err := syscall.ParseRoutingMessage(data)
	if err != nil {
		return nil
	}
	result := map[netip.Addr]neighborEntry{}
	for _, msg := range messages {
		route, ok := msg.(*syscall.RouteMessage)
		if !ok || route.Header.Flags&syscall.RTF_REJECT != 0 || route.Header.Rmx.Expire > 0 && int64(route.Header.Rmx.Expire) <= time.Now().Unix() {
			continue
		}
		addresses, err := syscall.ParseRoutingSockaddr(route)
		if err != nil || len(addresses) <= syscall.RTAX_GATEWAY {
			continue
		}
		link, ok := addresses[syscall.RTAX_GATEWAY].(*syscall.SockaddrDatalink)
		if !ok || link.Alen != 6 || int(link.Nlen)+6 > len(link.Data) {
			continue
		}
		var hw [6]byte
		for i := range hw {
			hw[i] = byte(link.Data[int(link.Nlen)+i])
		}
		mac := normalizedMAC(net.HardwareAddr(hw[:]).String())
		var ip netip.Addr
		switch addr := addresses[syscall.RTAX_DST].(type) {
		case *syscall.SockaddrInet4:
			ip = netip.AddrFrom4(addr.Addr)
		case *syscall.SockaddrInet6:
			if netip.AddrFrom16(addr.Addr).IsLinkLocalUnicast() {
				addr.Addr[2], addr.Addr[3] = 0, 0 // BSD embeds the interface scope in link-local addresses.
			}
			ip = netip.AddrFrom16(addr.Addr)
		}
		if !ip.IsValid() || mac == "" || !ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() {
			continue
		}
		entry := neighborEntry{mac: mac}
		if old, ok := result[ip]; ok && (old.ambiguous || old.mac != mac) {
			entry = neighborEntry{ambiguous: true}
		}
		if len(result) >= neighborLimit {
			return nil
		}
		result[ip] = entry
		if ip.Is6() && ip.IsLinkLocalUnicast() {
			if iface, err := net.InterfaceByIndex(int(route.Header.Index)); err == nil {
				result[ip.WithZone(iface.Name)] = neighborEntry{mac: mac}
			}
		}
	}
	return result
}
