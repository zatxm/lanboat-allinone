package native

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
)

type icmpFlowError struct {
	response   icmpResponse
	kind, code byte
	mtu        uint32
}

func (e *icmpFlowError) Error() string {
	if e.mtu > 0 {
		return fmt.Sprintf("ICMP type%d/code%d: path MTU%d", e.kind, e.code, e.mtu)
	}
	return fmt.Sprintf("ICMP type%d/code%d: destination unreachable", e.kind, e.code)
}
func (s *wgIPStack) receiveICMPFlowError(p tunPacket, b []byte) {
	if len(b) < 8 {
		return
	}
	quote, e := parseICMPQuote(b[8:])
	if e != nil || len(quote.data) < quote.header+8 || quote.protocol != 6 && quote.protocol != 17 {
		return
	}
	segment := quote.data[quote.header:]
	key := tunFlowKey{source: quote.source, destination: quote.destination, sport: binary.BigEndian.Uint16(segment), dport: binary.BigEndian.Uint16(segment[2:])}
	cause := &icmpFlowError{kind: b[0], code: b[1], response: icmpResponse{source: p.source, data: append([]byte{}, b[:min(len(b), 1240)]...)}}
	if p.protocol == 58 && b[0] == 2 {
		cause.mtu = binary.BigEndian.Uint32(b[4:])
	}
	if p.protocol == 1 && b[0] == 3 && b[1] == 4 {
		cause.mtu = uint32(binary.BigEndian.Uint16(b[6:]))
	}
	s.mu.Lock()
	udp, tcp := s.udp[key], s.tcp[key]
	s.mu.Unlock()
	if udp != nil {
		udp.mu.Lock()
		udp.failure = &net.OpError{Op: "read", Net: "udp", Source: udp.LocalAddr(), Addr: udp.RemoteAddr(), Err: cause}
		udp.mu.Unlock()
		udp.Close()
	}
	if tcp != nil {
		sequence := binary.BigEndian.Uint32(segment[4:])
		tcp.mu.Lock()
		valid := !tcpBefore(sequence, tcp.sendUna) && tcpBefore(sequence, tcp.sendNext)
		tcp.mu.Unlock()
		if valid {
			tcp.abort(&net.OpError{Op: "read", Net: "tcp", Source: tcp.LocalAddr(), Addr: tcp.RemoteAddr(), Err: cause})
		}
	}
}

// Retain real WireGuard ICMP errors when a TUN flow is represented by net.Conn.
type icmpErrorConn struct {
	net.Conn
	notify func(*icmpFlowError)
	once   sync.Once
}

func (c *icmpErrorConn) report(e error) {
	var cause *icmpFlowError
	if errors.As(e, &cause) {
		c.once.Do(func() { c.notify(cause) })
	}
}
func (c *icmpErrorConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	if e != nil {
		c.report(e)
	}
	return n, e
}
func (c *icmpErrorConn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	if e != nil {
		c.report(e)
	}
	return n, e
}
func (c *icmpErrorConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Conn.Close()
}
