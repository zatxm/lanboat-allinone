package native

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"slices"
	"time"
)

// MasquePathStatus describes an end-to-end check of this CONNECT-IP request,
// rather than the QUIC MTU of its first HTTP hop.
type MasquePathStatus struct {
	HTTPVersion       int        `json:"http_version"`
	MTU               int        `json:"mtu"`
	Peer              netip.Addr `json:"peer"`
	DatagramVerified  bool       `json:"datagram_verified"`
	ReliableVerified  bool       `json:"reliable_verified"`
	ReliableRTTMillis float64    `json:"reliable_rtt_ms"`
	DatagramRTTMillis float64    `json:"datagram_rtt_ms,omitempty"`
}

type masqueMTUProbe struct {
	datagram bool
	local    netip.Addr
	target   netip.Addr
	data     []byte
	reply    chan netip.Addr
}

var masqueAllNodes = netip.MustParseAddr("ff02::1")

// ProbeMasquePath verifies 1280-byte delivery using RFC9484 ICMPv6 Echo.
// It keeps this flow on capsules unless its datagram path is also verified.
// Calling it is explicit; it does not add startup traffic to existing profiles.
func (r *Runtime) ProbeMasquePath(ctx context.Context, tag string, targets ...netip.Addr) (MasquePathStatus, error) {
	var result MasquePathStatus
	if err := ctx.Err(); err != nil {
		return result, err
	}
	target := masqueAllNodes
	if len(targets) > 1 {
		return result, errors.New("MASQUE path probe accepts at most one IPv6 peer")
	}
	if len(targets) == 1 {
		target = targets[0]
		if !target.Is6() || target.Is4In6() || target.Zone() != "" || target.IsUnspecified() || target.IsMulticast() && target != masqueAllNodes {
			return result, errors.New("MASQUE path probe peer must be an IPv6 unicast address or ff02::1")
		}
	}
	c := r.masqueClients[tag]
	if c == nil || c.outbound.mode() != "ip" {
		return result, errors.New("MASQUE path probe requires a CONNECT-IP client tag")
	}
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	p, err := c.ipSession(ctx)
	if err != nil {
		return result, err
	}
	p.mu.Lock()
	if p.pathGate == nil {
		p.pathGate = make(chan struct{}, 1)
	}
	gate := p.pathGate
	p.mu.Unlock()
	select {
	case gate <- struct{}{}:
		defer func() { <-gate }()
	case <-ctx.Done():
		return result, ctx.Err()
	case <-p.flow.done:
		return result, net.ErrClosed
	}
	var local netip.Addr
	for _, address := range p.addresses() {
		if address.Is6() && !address.IsUnspecified() && !address.IsMulticast() && !address.Is4In6() {
			local = address
			break
		}
	}
	if !local.IsValid() {
		return result, errors.New("MASQUE MTU probe requires an assigned IPv6 address")
	}
	p.flow.reliableOnly.Store(true)
	result.HTTPVersion = p.flow.session.version
	deadline, _ := ctx.Deadline()
	m := p.flow.session
	m.mu.Lock()
	canDatagram := m.q != nil && m.datagrams && !p.flow.via && m.datagramLimit() >= 1289
	m.mu.Unlock()
	if canDatagram {
		datagram, stop := context.WithTimeout(ctx, min(time.Until(deadline)/3, time.Second))
		start := time.Now()
		result.Peer, err = p.probeMTU(datagram, local, target, true)
		stop()
		if err == nil {
			result.MTU, result.DatagramVerified = 1280, true
			result.DatagramRTTMillis = float64(time.Since(start)) / float64(time.Millisecond)
			p.flow.reliableOnly.Store(false)
			return result, nil
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if p.flow.isClosed() {
			return result, net.ErrClosed
		}
	}
	// Only switch to reliable transport after proving that path also works.
	reliable, stop := context.WithTimeout(ctx, time.Until(deadline)*2/3)
	defer stop()
	start := time.Now()
	result.Peer, err = p.probeMTU(reliable, local, target, false)
	if err != nil {
		// A cancelled read does not prove the authenticated tunnel is broken.
		if ctx.Err() == nil {
			p.flow.Close()
		}
		return result, err
	}
	result.MTU, result.ReliableVerified = 1280, true
	result.ReliableRTTMillis = float64(time.Since(start)) / float64(time.Millisecond)
	return result, nil
}

func (p *masqueIP) probeMTU(ctx context.Context, local, target netip.Addr, datagram bool) (netip.Addr, error) {
	segment := make([]byte, 8+1232)
	segment[0] = 128
	if _, err := rand.Read(segment[4:40]); err != nil {
		return netip.Addr{}, err
	}
	packet := makeWGIP(local, target, 58, segment)
	ip, _ := parseTunPacket(packet)
	binary.BigEndian.PutUint16(packet[42:], transportChecksum(ip, packet[40:]))
	probe := &masqueMTUProbe{datagram: datagram, local: local, target: target, data: packet[44:], reply: make(chan netip.Addr, 1)}
	p.mu.Lock()
	p.pathProbe = probe
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.pathProbe = nil
		p.mu.Unlock()
	}()
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, err
	}
	var err error
	var retry *time.Timer
	var retryC <-chan time.Time
	var send func() error
	if datagram {
		m := p.flow.session
		data := quicVar(nil, p.flow.id/4)
		data = append(data, 0)
		data = append(data, packet...)
		send = func() error {
			op := newQUICOperation('d', nil)
			op.data = data
			return m.q.do(ctx, op, p.flow.stream.(*quicStream)).err
		}
		err = send()
		retry = time.NewTimer(150 * time.Millisecond)
		defer retry.Stop()
		retryC = retry.C
	} else {
		// A cancelled partial capsule cannot be resumed safely on a shared stream.
		stop := context.AfterFunc(ctx, func() { p.flow.Close() })
		err = p.flow.capsule(0, append([]byte{0}, packet...))
		stop()
	}
	if ctx.Err() != nil {
		return netip.Addr{}, ctx.Err()
	}
	if err != nil {
		return netip.Addr{}, err
	}
	delay := 150 * time.Millisecond
	for {
		select {
		case peer := <-probe.reply:
			return peer, nil
		case <-retryC:
			if err := send(); err != nil {
				return netip.Addr{}, err
			}
			delay = min(2*delay, 500*time.Millisecond)
			retry.Reset(delay)
		case <-ctx.Done():
			return netip.Addr{}, ctx.Err()
		case <-p.flow.done:
			return netip.Addr{}, net.ErrClosed
		}
	}
}

// Link-local control terminates here and must not reach an outbound socket or
// system interface. Echo replies are accepted only for a live random challenge.
func (p *masqueIP) linkPacket(packet tunPacket, reliable bool) bool {
	if packet.protocol == 58 && packet.header == 40 && len(packet.data) >= 48 && packet.data[6] == 58 {
		segment := packet.data[40:]
		if segment[0] == 129 && segment[1] == 0 && len(packet.data) == 1280 && transportChecksum(packet, segment) == 0 && !packet.source.IsUnspecified() && !packet.source.IsMulticast() {
			p.mu.Lock()
			probe := p.pathProbe
			match := probe != nil && probe.datagram != reliable && probe.local == packet.destination && (probe.target == masqueAllNodes || probe.target == packet.source) && bytes.Equal(segment[4:], probe.data)
			if match {
				select {
				case probe.reply <- packet.source:
				default:
				}
			}
			p.mu.Unlock()
			if match {
				return true
			}
		}
		if packet.destination == masqueAllNodes || segment[0] == 128 && len(packet.data) <= 1280 && slices.Contains(p.addresses(), packet.destination) {
			if segment[0] != 128 || segment[1] != 0 || len(packet.data) > 1280 || packet.source.IsUnspecified() || packet.source.IsMulticast() || transportChecksum(packet, segment) != 0 || p.server && !p.allowed(packet.source) {
				return true
			}
			local := packet.destination
			if local == masqueAllNodes {
				local = netip.MustParseAddr("fe80::1")
				for _, address := range p.addresses() {
					if address.Is6() && !address.IsUnspecified() && !address.IsMulticast() {
						local = address
						break
					}
				}
			}
			// Keep subsequent replies on the path the peer just checked.
			if len(packet.data) == 1280 {
				p.flow.reliableOnly.Store(reliable)
			}
			reply := append([]byte{}, segment...)
			reply[0] = 129
			clear(reply[2:4])
			response := makeWGIP(local, packet.source, 58, reply)
			rp, _ := parseTunPacket(response)
			binary.BigEndian.PutUint16(response[42:], transportChecksum(rp, response[40:]))
			// Probe replies must retain their uncompressed wire size for path-MTU validation.
			if err := p.flow.sendDatagram(0, response, reliable); err != nil {
				p.flow.Close()
			}
			return true
		}
	}
	local := slices.Contains(p.addresses(), packet.destination)
	return !local && (packet.source.IsLinkLocalUnicast() || packet.source.IsLinkLocalMulticast() || packet.destination.IsLinkLocalUnicast() || packet.destination.IsLinkLocalMulticast())
}
