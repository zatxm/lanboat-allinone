package native

import (
	"net"
	"sync"
)

// The kernel accepts at most 64 segments in one UDP GSO send, and the whole
// buffer must still fit one maximum-size UDP datagram.
const quicBatchSegments = 64
const quicBatchBytes = 65000

var quicBatchBuffers = sync.Pool{New: func() any { return new([quicBatchBytes]byte) }}

// quicBatch coalesces the equal-sized packets written during one flush into
// a single segmentation-offload send. Only the last segment may be shorter.
// It is owned by the connection's run goroutine. A lone packet waits in first;
// the large buffer is borrowed only once a second packet joins, so idle
// connections and single-packet flushes hold no batch memory.
type quicBatch struct {
	write          func(buffer, control []byte) error
	single         func([]byte) error
	owner          *[quicBatchBytes]byte
	buffer         []byte
	control        []byte
	first          [quicPacketBufferSize]byte
	firstLen       int
	segment, count int
	disabled       bool
}

func (b *quicBatch) add(packet []byte) error {
	if b.disabled || len(packet) > quicBatchBytes {
		if err := b.flush(); err != nil {
			return err
		}
		return b.single(packet)
	}
	if b.count > 0 && (len(packet) > b.segment || b.firstLen+len(b.buffer)+len(packet) > quicBatchBytes || b.count == quicBatchSegments) {
		if err := b.flush(); err != nil {
			return err
		}
	}
	if b.count == 0 {
		b.segment = len(packet)
		if len(packet) <= len(b.first) {
			b.firstLen = copy(b.first[:], packet)
			b.count = 1
			return nil
		}
	}
	if b.owner == nil {
		b.owner = quicBatchBuffers.Get().(*[quicBatchBytes]byte)
		b.buffer = append(b.owner[:0], b.first[:b.firstLen]...)
		b.firstLen = 0
	}
	b.buffer = append(b.buffer, packet...)
	b.count++
	if len(packet) < b.segment {
		return b.flush()
	}
	return nil
}

func (b *quicBatch) flush() error {
	if b.count == 0 {
		return nil
	}
	if b.owner == nil {
		n := b.firstLen
		b.count, b.firstLen = 0, 0
		return b.single(b.first[:n])
	}
	buffer, segment, count := b.buffer, b.segment, b.count
	defer func() {
		quicBatchBuffers.Put(b.owner)
		b.owner, b.buffer, b.count = nil, nil, 0
	}()
	if count > 1 && !b.disabled {
		b.control = appendQUICGSOControl(b.control[:0], segment)
		if b.write(buffer, b.control) == nil {
			return nil
		}
		// Some devices reject segmentation offload; send individually from now on.
		b.disabled = true
	}
	for len(buffer) > 0 {
		n := min(len(buffer), segment)
		if err := b.single(buffer[:n]); err != nil {
			return err
		}
		buffer = buffer[n:]
	}
	return nil
}

// quicUDPConn returns the plain UDP socket under c, if any, so packets can
// be sent with segmentation offload.
func quicUDPConn(c any) *net.UDPConn {
	if owned, ok := c.(*ownedConn); ok {
		c = owned.Conn
	}
	udp, _ := c.(*net.UDPConn)
	return udp
}

// enableBatch turns on segmentation offload when the socket supports it.
// Path MTU discovery needs per-packet send errors, so it keeps single sends.
func (c *quicConn) enableBatch(udp *net.UDPConn, write func(buffer, control []byte) error) {
	if udp == nil || c.pmtu != nil || !quicGSOSupported(udp) {
		return
	}
	c.batch = &quicBatch{write: write, single: func(b []byte) error { return c.send(b) }}
}
