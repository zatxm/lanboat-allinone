package native

import (
	"errors"
	"syscall"
	"time"
)

var errQUICDatagramSize = errors.New("QUIC datagram exceeds current path or peer limit")

// Only the connection loop mutates discovery state. Readers use sendMTU.
// A single PING/PADDING probe is in flight, with no application retransmission.
type quicPMTU struct {
	upper, target, tries int
	largeLoss            int
	pn                   uint64
	active               bool
	next, expires        time.Time
}

func (c *quicConn) pmtuDeadline() time.Time {
	if c.pmtu == nil || !c.confirmed || c.path != nil {
		return time.Time{}
	}
	if c.pmtu.active {
		return c.pmtu.expires
	}
	return c.pmtu.next
}

func (c *quicConn) servicePMTU(now time.Time) error {
	m := c.pmtu
	if m == nil || !c.confirmed || c.path != nil {
		return nil
	}
	if m.active {
		if !now.Before(m.expires) {
			if packet, ok := c.spaces[2].sent[m.pn]; ok {
				c.losePacket(2, m.pn, packet, now)
			}
		}
		return nil
	}
	if now.Before(m.next) {
		return nil
	}
	limit := min(1472, int(c.peer.maxUDPPayload))
	m.upper = min(m.upper, limit)
	current := int(c.sendMTU.Load())
	if m.upper-current < 16 {
		// Revisit a previously constrained route without continuously probing
		// idle connections. The confirmed packet size is retained.
		m.upper, m.target, m.tries = limit, 0, 0
		m.next = now.Add(10 * time.Minute)
		return nil
	}
	if m.target == 0 {
		m.target = m.upper
	}
	if c.inFlight+m.target > c.cwnd || c.rateNext.After(now) {
		m.next = now.Add(max(10*time.Millisecond, c.srtt))
		return nil
	}
	s := &c.spaces[2]
	if s.nextPN >= 1<<62 {
		return errors.New("QUIC packet number exhausted")
	}
	payload := make([]byte, m.target-(1+len(c.dcid)+4+s.write.aead.Overhead()))
	payload[0] = 1
	pn := s.nextPN
	s.nextPN++
	packet := sealQUICPacket(payload, c.dcid, c.cid, nil, 2, pn, c.phase, s.write)
	if err := c.send(packet); err != nil {
		if !quicMessageTooLarge(err) {
			return err
		}
		m.tries = 2
		c.losePMTU(now)
		return nil
	}
	m.pn, m.active = pn, true
	m.expires = now.Add(max(200*time.Millisecond, 3*c.pto()))
	c.lastSend = now
	s.sent[pn] = quicSent{at: now, size: len(packet), eliciting: true, mtuProbe: true}
	c.inFlight += len(packet)
	return nil
}

func (c *quicConn) ackPMTU(pn uint64, size int, now time.Time) {
	m := c.pmtu
	if m == nil || !m.active || m.pn != pn {
		return
	}
	c.sendMTU.Store(int64(size))
	m.active, m.target, m.tries = false, 0, 0
	m.largeLoss = 0
	m.next = now.Add(max(10*time.Millisecond, c.srtt))
}

func (c *quicConn) lostPMTUData(size int, now time.Time) {
	if c.pmtu == nil || size <= 1200 || c.sendMTU.Load() <= 1200 {
		return
	}
	c.pmtu.largeLoss++
	if c.pmtu.largeLoss >= 3 {
		c.resetPMTU(now)
	}
}

func (c *quicConn) losePMTU(now time.Time) {
	m := c.pmtu
	m.active = false
	m.tries++
	if m.tries == 3 {
		m.upper = m.target - 1
		m.target = (int(c.sendMTU.Load()) + m.upper) / 2
		m.tries = 0
	}
	m.next = now.Add(max(20*time.Millisecond, c.srtt))
}

func (c *quicConn) resetPMTU(now time.Time) {
	m := c.pmtu
	if m == nil {
		return
	}
	if m.active {
		if packet, ok := c.spaces[2].sent[m.pn]; ok {
			delete(c.spaces[2].sent, m.pn)
			c.inFlight -= packet.size
		}
	}
	c.sendMTU.Store(1200)
	*m = quicPMTU{upper: min(1472, int(c.peer.maxUDPPayload)), next: now.Add(time.Second)}
}

func quicDontFragment(socket any) error {
	for {
		switch c := socket.(type) {
		case *controllerConn:
			socket = c.Conn
		case *controllerWireConn:
			socket = c.Conn
		case *ownedConn:
			socket = c.Conn
		case *groupConn:
			socket = c.Conn
		default:
			return quicSetSocketDF(socket)
		}
	}
}

func quicSetSocketDF(socket any) error {
	conn, ok := socket.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		// Detours expose logical datagrams; their outer socket belongs to the
		// carrier. End-to-end probes still bound the usable datagram size.
		return nil
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	if err = raw.Control(func(fd uintptr) { optionErr = quicSocketDF(fd) }); err != nil {
		return err
	}
	return optionErr
}

func quicMessageTooLarge(err error) bool { return errors.Is(err, syscall.EMSGSIZE) }
