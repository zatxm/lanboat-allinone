package native

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

type icmpResponse struct {
	source netip.Addr
	data   []byte
}
type wgICMPRequest struct {
	destination, local netip.Addr
	sequence           uint16
	reply              chan icmpResponse
}

func icmpError(kind byte, ipv6 bool) bool {
	if ipv6 {
		return kind >= 1 && kind <= 4
	}
	return kind == 3 || kind == 11 || kind == 12
}

// ICMP quotations are intentionally truncated; their IP total length describes
// the original datagram, not the quotation. Only normalize a private parser copy.
func parseICMPQuote(b []byte) (tunPacket, error) {
	if len(b) < 20 {
		return tunPacket{}, errors.New("short ICMP quotation")
	}
	b = append([]byte{}, b...)
	if b[0]>>4 == 4 {
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	} else if b[0]>>4 == 6 && len(b) >= 40 {
		binary.BigEndian.PutUint16(b[4:], uint16(len(b)-40))
	}
	return parseTunPacket(b)
}
func matchICMPResponse(b []byte, source, destination netip.Addr, id, sequence uint16) bool {
	if len(b) < 8 {
		return false
	}
	reply := byte(0)
	if destination.Is6() {
		reply = 129
	}
	if b[0] == reply && b[1] == 0 {
		return source == destination && binary.BigEndian.Uint16(b[4:]) == id && binary.BigEndian.Uint16(b[6:]) == sequence
	}
	if !icmpError(b[0], destination.Is6()) {
		return false
	}
	quote, e := parseICMPQuote(b[8:])
	if e != nil || quote.destination != destination || len(quote.data) < quote.header+8 {
		return false
	}
	kind := byte(1)
	if destination.Is6() {
		kind = 58
	}
	segment := quote.data[quote.header:]
	return quote.protocol == kind && binary.BigEndian.Uint16(segment[4:]) == id && binary.BigEndian.Uint16(segment[6:]) == sequence
}
func (s *wgIPStack) exchangeICMP(ctx context.Context, destination netip.Addr, request []byte, ttl byte) (icmpResponse, error) {
	var local netip.Addr
	for _, a := range s.peer.addresses() {
		if a.Is4() == destination.Is4() {
			local = a
			break
		}
	}
	if !local.IsValid() {
		return icmpResponse{}, errors.New("WireGuard has no local address for ICMP family")
	}
	if e := s.peer.ensure(ctx); e != nil {
		return icmpResponse{}, e
	}
	pending := &wgICMPRequest{destination: destination, local: local, sequence: binary.BigEndian.Uint16(request[6:]), reply: make(chan icmpResponse, 1)}
	s.mu.Lock()
	if s.closed || len(s.icmpPending) >= 64 {
		s.mu.Unlock()
		return icmpResponse{}, errors.New("ICMP exchange capacity reached")
	}
	if s.icmpPending == nil {
		s.icmpPending = map[uint16]*wgICMPRequest{}
	}
	for {
		s.next++
		if s.icmpPending[s.next] == nil {
			break
		}
	}
	id := s.next
	s.icmpPending[id] = pending
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.icmpPending, id); s.mu.Unlock() }()
	segment := append([]byte{}, request...)
	binary.BigEndian.PutUint16(segment[4:], id)
	clear(segment[2:4])
	protocol := byte(1)
	if destination.Is6() {
		protocol = 58
	}
	packet := makeWGIP(local, destination, protocol, segment)
	p, _ := parseTunPacket(packet)
	if destination.Is6() {
		packet[7] = ttl
	} else {
		packet[8] = ttl
		clear(packet[10:12])
		binary.BigEndian.PutUint16(packet[10:], checksum(packet[:p.header], 0))
	}
	sum := checksum(segment, 0)
	if destination.Is6() {
		sum = transportChecksum(p, segment)
	}
	binary.BigEndian.PutUint16(packet[p.header+2:], sum)
	if e := s.peer.sendIP(packet); e != nil {
		return icmpResponse{}, e
	}
	select {
	case response := <-pending.reply:
		if !icmpError(response.data[0], destination.Is6()) {
			copy(response.data[4:6], request[4:6])
		}
		return response, nil
	case <-ctx.Done():
		return icmpResponse{}, ctx.Err()
	case <-s.peer.done:
		return icmpResponse{}, net.ErrClosed
	}
}
func (s *wgIPStack) receiveICMPResponse(p tunPacket, b []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, pending := range s.icmpPending {
		if p.destination == pending.local && matchICMPResponse(b, p.source, pending.destination, id, pending.sequence) {
			select {
			case pending.reply <- icmpResponse{source: p.source, data: append([]byte{}, b...)}:
			default:
			}
			return true
		}
	}
	return false
}
func (s *wgIPStack) relayICMPError(original tunPacket, response icmpResponse) {
	if response.source.Is4() != original.source.Is4() {
		s.sendICMPError(original, false, false)
		return
	}
	if len(response.data) < 8 || !icmpError(response.data[0], original.source.Is6()) {
		return
	}
	limit := min(len(response.data)-8, len(original.data))
	if original.source.Is6() {
		limit = min(limit, 1232)
	} else {
		limit = min(limit, 548)
	}
	segment := make([]byte, 8+limit)
	copy(segment, response.data[:8])
	clear(segment[2:4])
	copy(segment[8:], original.data[:limit])
	packet := makeWGIP(response.source, original.source, original.protocol, segment)
	p, _ := parseTunPacket(packet)
	sum := checksum(segment, 0)
	if p.protocol == 58 {
		sum = transportChecksum(p, segment)
	}
	binary.BigEndian.PutUint16(packet[p.header+2:], sum)
	s.peer.sendIP(packet)
}
