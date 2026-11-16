package native

import "net"

// Only protocols that carry a destination in every datagram implement this.
// The enclosing net.Conn still owns deadlines, group registration and closure.
type addressedUDP interface {
	readPacket([]byte) (int, string, error)
	writePacket([]byte, string) (int, error)
}

func udpCarrier(c net.Conn) addressedUDP {
	for {
		switch v := c.(type) {
		case *controllerConn:
			if p := udpCarrier(v.Conn); p != nil {
				return &controllerUDP{owner: v, inner: p}
			}
			return nil
		case *ownedConn:
			c = v.Conn
		case *groupConn:
			c = v.Conn
		case *icmpErrorConn:
			c = v.Conn
		case *streamPacketConn:
			if v.trojan {
				return v
			}
			return nil
		default:
			p, _ := c.(addressedUDP)
			return p
		}
	}
}

func multiTargetUDP(o Outbound) bool {
	switch o.Type {
	case "socks", "shadowsocks", "shadowsocksr", "trojan", "hysteria", "hysteria2", "tuic", "sudoku":
		return true
	case "snell":
		return snellVersion(o.Version) == 3 || snellVersion(o.Version) == 4
	}
	return false
}
