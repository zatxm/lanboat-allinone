package native

import (
	"crypto/tls"
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// HTTP framing and flow control remain in net/http. This observer only tracks
// stream lifetime and PING acknowledgements, so idle gRPC pools need no pings.
type httpHealthConn struct {
	net.Conn
	writeMu           sync.Mutex
	mu                sync.Mutex
	read, write       httpFrameObserver
	streams           map[uint32]byte
	idle, timeout     time.Duration
	permit            bool
	lastRead          time.Time
	sequence, pending uint64
	pingWriting       bool
	watchdog          *time.Timer
	wake              chan struct{}
	done              chan struct{}
	once              sync.Once
}

func httpHealthConnection(conn net.Conn, transport Transport) net.Conn {
	idle, _ := time.ParseDuration(transport.IdleTimeout)
	if idle <= 0 {
		return conn
	}
	timeout, _ := time.ParseDuration(transport.PingTimeout)
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	c := &httpHealthConn{Conn: conn, idle: idle, timeout: timeout,
		permit:   transport.Type != "grpc" || transport.PermitWithoutStream,
		lastRead: time.Now(),
		wake:     make(chan struct{}, 1), done: make(chan struct{})}
	if !c.permit {
		c.streams = make(map[uint32]byte)
	}
	c.write.preface = 24 // The client connection preface precedes HTTP/2 frames.
	go c.run()
	return c
}

func (c *httpHealthConn) ConnectionState() tls.ConnectionState {
	if s, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return s.ConnectionState()
	}
	return tls.ConnectionState{}
}

func (c *httpHealthConn) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *httpHealthConn) observe(p []byte, outgoing bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	watch := &c.read
	if outgoing {
		watch = &c.write
	}
	watch.feed(p, func(kind, flags byte, id uint32, ping uint64) {
		if !outgoing {
			c.lastRead = time.Now()
			if kind == 6 && flags&1 != 0 && c.pending != 0 && ping == c.pending {
				c.pending = 0
				c.watchdog.Stop()
				c.signal()
			}
		}
		if c.permit || id == 0 || id&1 == 0 {
			return
		}
		if kind == 3 { // RST_STREAM ends both directions.
			c.endStream(id)
			return
		}
		if outgoing && kind == 1 {
			if c.streams[id] == 0 {
				c.signal()
			}
			c.streams[id] |= 1
		}
		if flags&1 != 0 && (kind == 0 || kind == 1) && c.streams[id] != 0 {
			if outgoing {
				c.streams[id] |= 2
			} else {
				c.streams[id] |= 4
			}
			if c.streams[id] == 7 {
				c.endStream(id)
			}
		}
	})
}

// Called under mu. Once the final stream ends, even an outstanding probe is
// irrelevant to gRPC's permit_without_stream:false idle pool.
func (c *httpHealthConn) endStream(id uint32) {
	delete(c.streams, id)
	if len(c.streams) == 0 && c.pending != 0 && !c.pingWriting {
		c.pending = 0
		c.watchdog.Stop()
		c.signal()
	}
}

func (c *httpHealthConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.observe(p[:n], false)
	}
	if err != nil {
		c.Close()
	}
	return n, err
}

func (c *httpHealthConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	// Publish the stream before the peer can send its response. A loopback
	// response can otherwise reach Read before the underlying Write returns.
	c.observe(p, true)
	n, err := c.Conn.Write(p)
	if err != nil {
		c.Close()
	}
	return n, err
}

func (c *httpHealthConn) Close() error {
	var err error
	c.once.Do(func() {
		close(c.done)
		c.mu.Lock()
		if c.watchdog != nil {
			c.watchdog.Stop()
		}
		c.mu.Unlock()
		err = c.Conn.Close()
	})
	return err
}

func (c *httpHealthConn) run() {
	timer := time.NewTimer(c.idle)
	defer timer.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-c.wake:
		case <-timer.C:
		}
		c.mu.Lock()
		wait := time.Until(c.lastRead.Add(c.idle))
		eligible := c.pending == 0 && (c.permit || len(c.streams) != 0)
		c.mu.Unlock()
		if !eligible {
			timer.Stop()
			continue
		}
		if wait <= 0 {
			c.ping()
		}
		if wait <= 0 {
			wait = c.idle
		}
		timer.Reset(wait)
	}
}

func (c *httpHealthConn) ping() {
	// net/http may split a large DATA frame across writes. Never insert a
	// health check into the middle of a frame (or into the client preface).
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	select {
	case <-c.done:
		c.mu.Unlock()
		return
	default:
	}
	if c.pending != 0 || c.write.preface != 0 || c.write.have != 0 || c.write.remaining != 0 || (!c.permit && len(c.streams) == 0) || time.Since(c.lastRead) < c.idle {
		c.mu.Unlock()
		return
	}
	c.sequence++
	id := c.sequence
	c.pending = id
	c.pingWriting = true
	c.watchdog = time.AfterFunc(c.timeout, func() {
		c.mu.Lock()
		expired := c.pending == id
		c.mu.Unlock()
		if expired {
			c.Close()
		}
	})
	c.mu.Unlock()
	var frame [17]byte
	frame[2], frame[3] = 8, 6
	binary.BigEndian.PutUint64(frame[9:], id)
	err := writeAll(c.Conn, frame[:])
	c.mu.Lock()
	c.pingWriting = false
	if !c.permit && len(c.streams) == 0 && c.pending == id {
		c.pending = 0
		c.watchdog.Stop()
		c.signal()
	}
	c.mu.Unlock()
	if err != nil {
		c.Close()
	}
}

// A streaming observer stores only a frame header and a PING's eight bytes.
// Payloads, including large DATA and compressed headers, are never copied.
type httpFrameObserver struct {
	header                         [9]byte
	ping                           [8]byte
	preface, have, remaining, used int
}

func (o *httpFrameObserver) feed(p []byte, frame func(byte, byte, uint32, uint64)) {
	if o.preface > 0 {
		n := min(o.preface, len(p))
		o.preface -= n
		p = p[n:]
	}
	for len(p) > 0 {
		if o.have < 9 {
			n := copy(o.header[o.have:], p)
			o.have += n
			p = p[n:]
			if o.have < 9 {
				return
			}
			o.remaining = int(o.header[0])<<16 | int(o.header[1])<<8 | int(o.header[2])
			o.used = 0
		}
		n := min(o.remaining, len(p))
		if o.header[3] == 6 && o.header[2] == 8 && o.header[0] == 0 && o.header[1] == 0 {
			copy(o.ping[o.used:], p[:n])
		}
		o.used += n
		o.remaining -= n
		p = p[n:]
		if o.remaining == 0 {
			var ping uint64
			if o.used == 8 {
				ping = binary.BigEndian.Uint64(o.ping[:])
			}
			frame(o.header[3], o.header[4], binary.BigEndian.Uint32(o.header[5:])&0x7fffffff, ping)
			o.have = 0
		}
	}
}
