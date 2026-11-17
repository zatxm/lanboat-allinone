package native

import (
	"bytes"
	"crypto/rand"
	"net"
	"time"
)

type quicDatagram struct {
	data   []byte
	remote net.Addr
}

type quicPath struct {
	remote         net.Addr
	token          [8]byte
	received, sent int
	attempts       int
	next, expires  time.Time
}

func sameQUICIP(a, b net.Addr) bool {
	x, ok := a.(*net.UDPAddr)
	y, yes := b.(*net.UDPAddr)
	return ok && yes && x.IP.Equal(y.IP) && x.Zone == y.Zone
}

func sameQUICAddress(a, b net.Addr) bool {
	x, ok := a.(*net.UDPAddr)
	y, yes := b.(*net.UDPAddr)
	return ok && yes && x.Port == y.Port && x.Zone == y.Zone && x.IP.Equal(y.IP)
}

// Only same-IP port rebinding is accepted. Full active IP migration remains
// disabled in transport parameters. The original public remote address is
// immutable: stream/logging goroutines never race with the connection loop.
func (c *quicConn) observePath(remote net.Addr, size int, now time.Time) {
	if c.sendTo == nil || remote == nil || sameQUICAddress(remote, c.pathRemote) || !sameQUICIP(remote, c.pathRemote) {
		return
	}
	if c.path != nil && !now.Before(c.path.expires) {
		c.path = nil
	}
	// observePath only sees authenticated packets advancing the packet-number
	// high-water mark. A subsequent NAT hop supersedes a stale candidate; waiting
	// for its expiry can strand traffic while the client keeps changing ports.
	if c.path == nil || !sameQUICAddress(c.path.remote, remote) {
		c.path = &quicPath{remote: remote, expires: now.Add(max(3*time.Second, 3*c.srtt))}
		rand.Read(c.path.token[:])
	}
	c.path.received = min(1<<20, c.path.received+size)
	c.servicePath(now)
}

func (c *quicConn) servicePath(now time.Time) {
	p := c.path
	if p == nil {
		return
	}
	if !now.Before(p.expires) {
		c.path = nil
		return
	}
	if p.attempts >= 3 || now.Before(p.next) || p.received*3-p.sent < 40 {
		return
	}
	p.attempts++
	p.next = now.Add(max(200*time.Millisecond, 3*c.srtt))
	_ = c.sendPathFrame(p.remote, append([]byte{26}, p.token[:]...))
}

// Path validation has its own bounded budget and retransmission. It does not
// queue application data onto an unvalidated address. Datagram accounting uses
// the encrypted wire size and caps replies at three times authenticated input.
func (c *quicConn) sendPathFrame(remote net.Addr, frame []byte) error {
	space := &c.spaces[2]
	if space.write == nil || space.nextPN >= 1<<62 {
		return nil
	}
	budget := 1200
	p := c.path
	if !sameQUICAddress(remote, c.pathRemote) {
		if p == nil || !sameQUICAddress(p.remote, remote) {
			return nil
		}
		budget = min(budget, p.received*3-p.sent)
	}
	overhead := 1 + len(c.dcid) + 4 + 16
	if budget < overhead+len(frame) {
		return nil
	}
	payload := make([]byte, budget-overhead)
	copy(payload, frame)
	packet := sealQUICPacket(payload, c.dcid, c.cid, nil, 2, space.nextPN, c.phase, space.write)
	space.nextPN++
	if p != nil && sameQUICAddress(p.remote, remote) {
		p.sent += len(packet)
	}
	return c.sendTo(packet, remote)
}

func (c *quicConn) pathResponse(body []byte) {
	p := c.path
	if p != nil && c.packetRemote != nil && sameQUICAddress(p.remote, c.packetRemote) && quicNow().Before(p.expires) && bytes.Equal(p.token[:], body) {
		c.pathRemote = p.remote
		c.path = nil
		c.resetPMTU(quicNow())
	}
}
