package native

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

func systemNeighbors(ctx context.Context) map[netip.Addr]neighborEntry {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil
	}
	defer syscall.Close(fd)
	query := make([]byte, 28)
	binary.NativeEndian.PutUint32(query, uint32(len(query)))
	binary.NativeEndian.PutUint16(query[4:], 30) // RTM_GETNEIGH
	binary.NativeEndian.PutUint16(query[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(query[8:], 1)
	if err := syscall.Sendto(fd, query, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil
	}
	result, err := readLinuxNeighbors(ctx, fd)
	if err != nil {
		return nil
	}
	return result
}

func readLinuxNeighbors(ctx context.Context, fd int) (map[netip.Addr]neighborEntry, error) {
	result := map[netip.Addr]neighborEntry{}
	buffer := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(buffer)
	deadline := time.Now().Add(250 * time.Millisecond)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	for received := 0; received < neighborLeaseBytes; {
		left := time.Until(deadline)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if left <= 0 {
			return nil, context.DeadlineExceeded
		}
		wait := syscall.NsecToTimeval(left.Nanoseconds())
		if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &wait); err != nil {
			return nil, err
		}
		n, from, err := syscall.Recvfrom(fd, buffer, 0)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		received += n
		peer, ok := from.(*syscall.SockaddrNetlink)
		if !ok || peer.Pid != 0 || n == len(buffer) {
			return nil, errors.New("invalid or truncated neighbor snapshot")
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range messages {
			if m.Header.Seq != 1 || m.Header.Flags&0x10 != 0 {
				return nil, errors.New("interrupted neighbor snapshot")
			}
			switch m.Header.Type {
			case syscall.NLMSG_DONE:
				if len(m.Data) >= 4 && int32(binary.NativeEndian.Uint32(m.Data)) != 0 {
					return nil, errors.New("incomplete neighbor snapshot")
				}
				return result, nil
			case syscall.NLMSG_ERROR:
				return nil, errors.New("neighbor snapshot rejected")
			case 28: // RTM_NEWNEIGH
				ip, mac, index := linuxNeighborEntry(m.Data)
				if !ip.IsValid() || mac == "" {
					continue
				}
				if len(result) >= neighborLimit {
					return nil, errors.New("neighbor snapshot exceeds capacity")
				}
				entry := neighborEntry{mac: mac}
				if old, ok := result[ip]; ok && (old.ambiguous || old.mac != mac) {
					entry = neighborEntry{ambiguous: true}
				}
				result[ip] = entry
				if ip.Is6() && ip.IsLinkLocalUnicast() {
					if iface, err := net.InterfaceByIndex(index); err == nil {
						result[ip.WithZone(iface.Name)] = neighborEntry{mac: mac}
					}
				}
			}
		}
	}
	return nil, errors.New("neighbor snapshot exceeds byte limit")
}

func linuxNeighborEntry(body []byte) (netip.Addr, string, int) {
	if len(body) < 12 || body[0] != syscall.AF_INET && body[0] != syscall.AF_INET6 || binary.NativeEndian.Uint16(body[8:])&0xde == 0 {
		return netip.Addr{}, "", 0
	}
	// INCOMPLETE/FAILED and proxy entries cannot identify a source device.
	if binary.NativeEndian.Uint16(body[8:])&0x21 != 0 || body[10]&8 != 0 {
		return netip.Addr{}, "", 0
	}
	index := int(int32(binary.NativeEndian.Uint32(body[4:])))
	var ip netip.Addr
	mac := ""
	for data := body[12:]; len(data) > 0; {
		if len(data) < 4 {
			return netip.Addr{}, "", 0
		}
		n, typ := int(binary.NativeEndian.Uint16(data)), binary.NativeEndian.Uint16(data[2:])
		if n < 4 || n > len(data) {
			return netip.Addr{}, "", 0
		}
		switch typ & 0x3fff {
		case 1: // NDA_DST
			if body[0] == syscall.AF_INET && n == 8 || body[0] == syscall.AF_INET6 && n == 20 {
				ip, _ = netip.AddrFromSlice(data[4:n])
			}
		case 2: // NDA_LLADDR
			mac = normalizedMAC(net.HardwareAddr(data[4:n]).String())
		}
		aligned := (n + 3) &^ 3
		if aligned > len(data) {
			if n == len(data) {
				break
			}
			return netip.Addr{}, "", 0
		}
		data = data[aligned:]
	}
	if index <= 0 || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLoopback() {
		return netip.Addr{}, "", 0
	}
	return ip, mac, index
}
