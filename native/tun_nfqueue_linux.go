//go:build linux

package native

import (
	"encoding/binary"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

type tunQueue struct {
	file   *os.File
	number uint16
	tunnel *tunTunnel
}

func nfQueueMessage(kind uint16, queue uint16, flags uint16, seq uint32, attrs ...[]byte) []byte {
	b := make([]byte, 20)
	binary.NativeEndian.PutUint16(b[4:], 0x300|kind)
	binary.NativeEndian.PutUint16(b[6:], flags)
	binary.NativeEndian.PutUint32(b[8:], seq)
	binary.BigEndian.PutUint16(b[18:], queue)
	for _, a := range attrs {
		b = append(b, a...)
	}
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	return b
}
func nfQueueU32(kind uint16, value uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, value)
	return nlAttribute(kind, b)
}
func openTunQueue(t *tunTunnel) (*tunQueue, error) {
	fd, e := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, 12)
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			syscall.Close(fd)
		}
	}()
	if e = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); e != nil {
		return nil, e
	}
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1<<20)
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 3})
	queue := t.in.queueNumber()
	params := []byte{0, 0, 0xff, 0xff, 2}
	request := nfQueueMessage(2, queue, 5, 1, nlAttribute(1, []byte{1, 0, 0, 0}), nlAttribute(2, params), nfQueueU32(3, 1024), nfQueueU32(4, 4), nfQueueU32(5, 4))
	if e = syscall.Sendto(fd, request, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); e != nil {
		return nil, e
	}
	buffer := make([]byte, 4096)
	n, _, e := syscall.Recvfrom(fd, buffer, 0)
	if e != nil {
		return nil, e
	}
	aligned := (n + 3) &^ 3
	clear(buffer[n:aligned])
	messages, e := syscall.ParseNetlinkMessage(buffer[:aligned])
	if e != nil {
		return nil, e
	}
	ack := false
	for _, m := range messages {
		if m.Header.Type == syscall.NLMSG_ERROR && len(m.Data) >= 4 {
			code := int32(binary.NativeEndian.Uint32(m.Data))
			if code != 0 {
				return nil, fmt.Errorf("bind NFQUEUE%d: %w", queue, syscall.Errno(-code))
			}
			ack = true
		}
	}
	if !ack {
		return nil, errors.New("missing NFQUEUE acknowledgement")
	}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{})
	if e = syscall.SetNonblock(fd, true); e != nil {
		return nil, e
	}
	if e = syscall.Connect(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); e != nil {
		return nil, e
	}
	success = true
	return &tunQueue{file: os.NewFile(uintptr(fd), "lanboat-nfqueue"), number: queue, tunnel: t}, nil
}
func (q *tunQueue) run() {
	buffer := make([]byte, 128<<10)
	for {
		n, e := q.file.Read(buffer)
		if e != nil {
			if !errors.Is(e, os.ErrClosed) {
				q.tunnel.runtime.logger.Warn("read TUN pre-match queue", zap.Error(e))
			}
			return
		}
		// NFQUEUE may omit the final alignment bytes for an odd-sized payload.
		aligned := (n + 3) &^ 3
		clear(buffer[n:aligned])
		messages, e := syscall.ParseNetlinkMessage(buffer[:aligned])
		if e != nil {
			q.tunnel.runtime.logger.Warn("parse TUN pre-match queue", zap.Error(e))
			continue
		}
		for _, m := range messages {
			if m.Header.Type != 0x300 || len(m.Data) < 4 {
				continue
			}
			var id uint32
			found := false
			var payload []byte
			for b := m.Data[4:]; len(b) >= 4; {
				length := int(binary.NativeEndian.Uint16(b))
				if length < 4 || length > len(b) {
					break
				}
				kind := binary.NativeEndian.Uint16(b[2:]) & 0x3fff
				v := b[4:length]
				if kind == 1 && len(v) >= 7 {
					id = binary.BigEndian.Uint32(v)
					found = true
				}
				if kind == 10 {
					payload = v
				}
				next := (length + 3) &^ 3
				if next > len(b) {
					break
				}
				b = b[next:]
			}
			if !found {
				continue
			}
			mark, drop := q.tunnel.preMatchPacket(payload)
			a, b, c, _ := q.tunnel.in.redirectMarks()
			vi, vo, vr := q.tunnel.in.redirectVerdictMarks()
			switch mark {
			case a:
				mark = vi
			case b:
				mark = vo
			case c:
				mark = vr
			}
			verdict := uint32(1)
			if drop {
				verdict = 0
			}
			header := make([]byte, 8)
			binary.BigEndian.PutUint32(header, verdict)
			binary.BigEndian.PutUint32(header[4:], id)
			packet := nfQueueMessage(1, q.number, 1, 0, nlAttribute(2, header), nfQueueU32(3, mark))
			if _, e = q.file.Write(packet); e != nil {
				if !errors.Is(e, os.ErrClosed) {
					q.tunnel.runtime.logger.Warn("send TUN pre-match verdict", zap.Error(e))
				}
				return
			}
		}
	}
}
func (t *tunTunnel) preMatchPacket(b []byte) (uint32, bool) {
	input, output, reset, _ := t.in.redirectMarks()
	p, e := parseTunPacket(b)
	if e != nil || p.protocol == 44 || p.source.Is4() && binary.BigEndian.Uint16(p.data[6:])&0x1fff != 0 {
		return input, false
	}
	if p.protocol != 6 && p.protocol != 17 && p.protocol != 1 && p.protocol != 58 {
		return input, false
	}
	segment := p.data[p.header:]
	if p.protocol == 6 && tcpHasMPTCP(segment) {
		if t.in.ExcludeMPTCP {
			return output, false
		}
		return reset, false
	}
	q := request{preMatch: true, inbound: t.in.Tag, network: "icmp", source: net.JoinHostPort(p.source.String(), "0"), address: net.JoinHostPort(p.destination.String(), "0"), metadata: Metadata{Protocol: "icmp"}}
	if p.protocol == 6 || p.protocol == 17 {
		if p.protocol == 6 && len(segment) < 20 {
			return input, false
		}
		if len(segment) < 8 {
			return input, false
		}
		q.network = "tcp"
		if p.protocol == 17 {
			q.network = "udp"
		}
		q.metadata.Protocol = ""
		q.source = net.JoinHostPort(p.source.String(), strconv.Itoa(int(binary.BigEndian.Uint16(segment))))
		q.address = net.JoinHostPort(p.destination.String(), strconv.Itoa(int(binary.BigEndian.Uint16(segment[2:]))))
		if p.protocol == 17 {
			q.payload = segment[8:]
		} else {
			header := int(segment[12]>>4) * 4
			if header >= 20 && header <= len(segment) {
				q.payload = segment[header:]
			}
		}
	} else {
		q.payload = segment
	}
	if t.runtime.resolver.isFake(p.destination) {
		return input, false
	}
	if t.runtime.config.DNS.ReverseMapping {
		t.runtime.resolver.mu.Lock()
		entry, ok := t.runtime.resolver.reverse[p.destination]
		t.runtime.resolver.mu.Unlock()
		if ok && time.Now().Before(entry.until) {
			q.metadata.Domain = entry.host
		}
	}
	t.runtime.enrichNetworkMetadata(t.runtime.ctx, &q.metadata)
	t.runtime.resolver.enrichDNSNetworkMetadata(&q.metadata)
	t.runtime.enrichProcess(t.runtime.ctx, &q)
	t.runtime.enrichNeighbor(t.runtime.ctx, &q)
	for i := range t.runtime.rules {
		rule := &t.runtime.rules[i]
		if rule.preMatchNeedsData(q) {
			return input, false
		}
		m := rule.evaluate(q)
		if m == matchUnknown {
			return input, false
		}
		if m != matchYes {
			continue
		}
		if rule.networkOptions != nil {
			return input, false
		}
		o := rule.rule
		switch o.Action {
		case "bypass":
			return output, false
		case "reject":
			if q.network == "icmp" || o.Method == "reply" {
				return input, false
			}
			if rule.reject.drop(o.Method, o.NoDrop) {
				return reset, true
			}
			return reset, false
		case "sniff":
			protocol, domain, client := sniffPacketInfo(q.network, q.payload, o.Sniffer)
			if client != "" {
				q.metadata.Client = client
			}
			if protocol != "" {
				q.metadata.Protocol = protocol
			}
			if domain != "" {
				q.metadata.Domain = domain
			}
			continue
		case "resolve", "route-options":
			if o.OverrideAddress != "" || o.OverridePort != 0 {
				return input, false
			}
			continue
		default:
			return input, false
		}
	}
	return input, false
}
func tcpHasMPTCP(segment []byte) bool {
	if len(segment) < 20 {
		return false
	}
	end := int(segment[12]>>4) * 4
	if end < 20 || end > len(segment) {
		return false
	}
	for i := 20; i < end; {
		kind := segment[i]
		if kind == 0 {
			return false
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= end {
			return false
		}
		n := int(segment[i+1])
		if n < 2 || i+n > end {
			return false
		}
		if kind == 30 {
			return true
		}
		i += n
	}
	return false
}
