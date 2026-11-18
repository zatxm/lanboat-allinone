package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const udpTimeout = 30 * time.Second

var packetBuffers = sync.Pool{New: func() any { return make([]byte, 65535) }}

type streamPacketConn struct {
	net.Conn
	address         string
	trojan          bool
	readMu, writeMu sync.Mutex
}

func (c *streamPacketConn) Read(b []byte) (int, error) {
	n, _, err := c.readPacket(b)
	return n, err
}
func (c *streamPacketConn) readPacket(b []byte) (int, string, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	address := c.address
	if c.trojan {
		var err error
		address, err = readAddress(c.Conn)
		if err != nil {
			return 0, "", err
		}
	}
	var size [2]byte
	if _, err := io.ReadFull(c.Conn, size[:]); err != nil {
		return 0, "", err
	}
	if c.trojan {
		if err := readCRLF(c.Conn); err != nil {
			return 0, "", err
		}
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n > len(b) {
		_, err := io.CopyN(io.Discard, c.Conn, int64(n))
		if err != nil {
			return 0, "", err
		}
		return 0, "", io.ErrShortBuffer
	}
	count, err := io.ReadFull(c.Conn, b[:n])
	return count, address, err
}
func (c *streamPacketConn) Write(b []byte) (int, error) {
	return c.writePacket(b, c.address)
}
func (c *streamPacketConn) writePacket(b []byte, address string) (int, error) {
	if len(b) > 65507 {
		return 0, errors.New("UDP payload exceeds 65507 bytes")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	var header []byte
	var err error
	if c.trojan {
		header, err = encodeAddress(address)
		if err != nil {
			return 0, err
		}
	}
	header = binary.BigEndian.AppendUint16(header, uint16(len(b)))
	if c.trojan {
		header = append(header, 13, 10)
	}
	if err := writeAll(c.Conn, header); err != nil {
		return 0, err
	}
	if err := writeAll(c.Conn, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

type socksUDPConn struct {
	net.Conn
	control net.Conn
	address []byte
	done    chan struct{}
	once    sync.Once
}

func (c *socksUDPConn) Read(b []byte) (int, error) {
	n, _, err := c.readPacket(b)
	return n, err
}
func (c *socksUDPConn) readPacket(b []byte) (int, string, error) {
	packet := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(packet)
	for {
		n, err := c.Conn.Read(packet)
		if err != nil {
			return 0, "", err
		}
		if n < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
			continue
		}
		reader := bytes.NewReader(packet[3:n])
		address, err := readAddress(reader)
		if err != nil {
			continue
		}
		if reader.Len() > len(b) {
			return 0, "", io.ErrShortBuffer
		}
		count, err := io.ReadFull(reader, b[:reader.Len()])
		return count, address, err
	}
}
func (c *socksUDPConn) Write(b []byte) (int, error) {
	return c.writeEncoded(b, c.address)
}
func (c *socksUDPConn) writePacket(b []byte, address string) (int, error) {
	encoded, err := encodeAddress(address)
	if err != nil {
		return 0, err
	}
	return c.writeEncoded(b, encoded)
}
func (c *socksUDPConn) writeEncoded(b, address []byte) (int, error) {
	if len(b)+len(address)+3 > 65507 {
		return 0, errors.New("SOCKS UDP packet is too large")
	}
	owner := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(owner)
	packet := append(append(append(owner[:0], 0, 0, 0), address...), b...)
	_, err := c.Conn.Write(packet)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
func (c *socksUDPConn) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close(); c.control.Close(); <-c.done })
	return err
}

func (r *Runtime) socksPacketClient(ctx context.Context, o Outbound, address string) (net.Conn, error) {
	encoded, err := encodeAddress(address)
	if err != nil {
		return nil, err
	}
	control, err := r.endpoint(ctx, o, "tcp")
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			control.Close()
		}
	}()
	rawControl := control
	stop := context.AfterFunc(ctx, func() { rawControl.Close() })
	defer stop()
	if d, ok := ctx.Deadline(); ok {
		_ = control.SetDeadline(d)
	}
	if cfg := r.clientTLS[o.Tag]; cfg != nil {
		cfg, err = r.outboundTLS(ctx, o)
		if err != nil {
			return nil, err
		}
		c, err := handshakeTLS(ctx, control, cfg, o.TLS)
		if err != nil {
			return nil, err
		}
		control = c
	}
	if err := socksAuthenticate(control, o.Username, o.Password); err != nil {
		return nil, err
	}
	relay, err := socksRequest(control, 3, "")
	if err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(relay)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		relay = net.JoinHostPort(o.Server, port)
	}
	var packets net.Conn
	if o.Detour != "" {
		packets, err = r.dialOutbound(ctx, o.Detour, "udp", relay)
	} else {
		packets, err = r.direct(ctx, "udp", relay)
	}
	if err != nil {
		return nil, err
	}
	_ = control.SetDeadline(time.Time{})
	c := &socksUDPConn{Conn: packets, control: control, address: encoded, done: make(chan struct{})}
	go func() { _, _ = io.Copy(io.Discard, control); packets.Close(); close(c.done) }()
	success = true
	return r.own(c)
}

type ssPacketConn struct {
	net.Conn
	key     *ssKey
	replay  *replayWindow
	address []byte
}

func (c *ssPacketConn) Read(b []byte) (int, error) {
	n, _, err := c.readPacket(b)
	return n, err
}
func (c *ssPacketConn) readPacket(b []byte) (int, string, error) {
	packet := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(packet)
	for {
		n, err := c.Conn.Read(packet)
		if err != nil {
			return 0, "", err
		}
		plain, err := c.key.openPacket(packet[:n], c.replay)
		if err != nil {
			continue
		}
		reader := bytes.NewReader(plain)
		address, err := readAddress(reader)
		if err != nil {
			continue
		}
		if reader.Len() > len(b) {
			return 0, "", io.ErrShortBuffer
		}
		count, err := io.ReadFull(reader, b[:reader.Len()])
		return count, address, err
	}
}
func (c *ssPacketConn) Write(b []byte) (int, error) {
	return c.writeEncoded(b, c.address)
}
func (c *ssPacketConn) writePacket(b []byte, address string) (int, error) {
	encoded, err := encodeAddress(address)
	if err != nil {
		return 0, err
	}
	return c.writeEncoded(b, encoded)
}
func (c *ssPacketConn) writeEncoded(b, address []byte) (int, error) {
	if len(b)+len(address)+len(c.key.master)+16 > 65507 {
		return 0, errors.New("Shadowsocks UDP packet is too large")
	}
	owner := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(owner)
	packet, err := c.key.appendSealPacket(owner[:0], address, b, c.replay)
	if err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write(packet); err != nil {
		return 0, err
	}
	return len(b), nil
}
func (r *Runtime) ssPacketClient(ctx context.Context, o Outbound, address string) (net.Conn, error) {
	if o.OTA {
		o.Protocol = "verify_sha1"
		return r.ssrPacketClient(ctx, o, address)
	}
	if isSS2022(o.Method) {
		return r.ss2022PacketClient(ctx, o, address)
	}
	encoded, err := encodeAddress(address)
	if err != nil {
		return nil, err
	}
	c, err := r.endpoint(ctx, o, "udp")
	if err != nil {
		return nil, err
	}
	return r.own(&ssPacketConn{Conn: c, key: r.keys["out:"+o.Tag], replay: &r.replay, address: encoded})
}

// Each association has bounded destination state and releases idle sockets.
type udpFlows struct {
	ctx     context.Context
	direct  bool
	runtime *Runtime
	timeout time.Duration
	mu      sync.Mutex
	flows   map[string]net.Conn
	closed  bool
	workers sync.WaitGroup
}

func newUDPFlows(r *Runtime) *udpFlows {
	return &udpFlows{ctx: r.ctx, runtime: r, timeout: udpTimeout, flows: map[string]net.Conn{}}
}
func (f *udpFlows) closePrefix(prefix string) {
	f.mu.Lock()
	var conns []net.Conn
	for key, c := range f.flows {
		if strings.HasPrefix(key, prefix) {
			conns = append(conns, c)
			delete(f.flows, key)
		}
	}
	f.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}
func (f *udpFlows) Close() {
	f.mu.Lock()
	f.closed = true
	conns := make([]net.Conn, 0, len(f.flows))
	for _, c := range f.flows {
		conns = append(conns, c)
	}
	f.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	f.workers.Wait()
}
func (f *udpFlows) send(key string, q request, payload []byte, reply func([]byte, string) error) error {
	timeout := f.runtime.udpTimeoutFor(q.inbound, f.timeout)
	q.network = "udp"
	if f.runtime.needsMetadata(processFields) {
		f.runtime.enrichProcess(f.ctx, &q)
		owner := "?"
		if q.metadata.UserID != nil {
			owner = strconv.FormatUint(uint64(*q.metadata.UserID), 10)
		}
		// A reused UDP port must not inherit another local user's routed session.
		key += "\x00" + q.metadata.ProcessName + "\x00" + q.metadata.ProcessPath + "\x00" + q.metadata.User + "\x00uid:" + owner
	}

	if f.runtime.needsMetadata(neighborFields) {
		f.runtime.enrichNeighbor(f.ctx, &q)
		key += "\x00mac:" + q.metadata.SourceMACAddress + "\x00host:" + q.metadata.SourceHostname
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return net.ErrClosed
	}
	c := f.flows[key]
	if c == nil && len(f.flows) >= 256 {
		f.mu.Unlock()
		return errors.New("UDP destination limit reached")
	}
	f.mu.Unlock()
	if c == nil {
		var err error
		if f.direct {
			c, err = f.runtime.direct(f.ctx, "udp", q.address)
		} else {
			c, err = f.runtime.routeDial(f.ctx, q)
		}
		if err != nil {
			return err
		}
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			c.Close()
			return net.ErrClosed
		}
		if existing := f.flows[key]; existing != nil {
			f.mu.Unlock()
			c.Close()
			c = existing
		} else {
			f.flows[key] = c
			f.workers.Add(1)
			f.mu.Unlock()
			go func(c net.Conn) {
				defer f.workers.Done()
				defer func() {
					c.Close()
					f.mu.Lock()
					if f.flows[key] == c {
						delete(f.flows, key)
					}
					f.mu.Unlock()
				}()
				buffer := packetBuffers.Get().([]byte)
				defer packetBuffers.Put(buffer)
				for {
					_ = c.SetReadDeadline(time.Now().Add(timeout))
					n, err := c.Read(buffer)
					if err != nil {
						return
					}
					f.runtime.down.Add(int64(n))
					if err := reply(buffer[:n], q.address); err != nil {
						return
					}
				}
			}(c)
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	_ = c.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	n, err := c.Write(payload)
	f.runtime.up.Add(int64(n))
	return err
}

func (r *Runtime) serveStreamPackets(c net.Conn, q request, trojan bool) error {
	flows := newUDPFlows(r)
	defer flows.Close()
	var sendMu sync.Mutex
	var buffer []byte
	for {
		address := q.address
		var err error
		if trojan {
			address, err = readAddress(c)
			if err != nil {
				return err
			}
		}
		var size [2]byte
		if _, err := io.ReadFull(c, size[:]); err != nil {
			return err
		}
		if trojan {
			if err := readCRLF(c); err != nil {
				return err
			}
		}
		n := int(binary.BigEndian.Uint16(size[:]))
		if cap(buffer) < n {
			buffer = make([]byte, n)
		}
		// UDP flow writes do not retain the payload, so the buffer is reused.
		payload := buffer[:n]
		if _, err := io.ReadFull(c, payload); err != nil {
			return err
		}
		q.address = address
		if err := validAddress(address); err != nil {
			return err
		}
		err = flows.send(address, q, payload, func(b []byte, from string) error {
			sendMu.Lock()
			defer sendMu.Unlock()
			_ = c.SetWriteDeadline(time.Now().Add(handshakeTimeout))
			packet := &streamPacketConn{Conn: c, address: from, trojan: trojan}
			_, err := packet.Write(b)
			return err
		})
		if err != nil {
			return err
		}
	}
}

func (r *Runtime) serveSOCKSPackets(control net.Conn, q request) error {
	host, _, _ := net.SplitHostPort(control.LocalAddr().String())
	var options ListenOptions
	for _, in := range r.config.Inbounds {
		if in.Tag == q.inbound {
			options = in.ListenOptions
			break
		}
	}
	packets, err := options.listenPacket(r.ctx, "udp", net.JoinHostPort(host, "0"))
	if err != nil {
		return err
	}
	defer packets.Close()
	bound, err := encodeAddress(packets.LocalAddr().String())
	if err != nil {
		return err
	}
	if err := writeAll(control, append([]byte{5, 0, 0}, bound...)); err != nil {
		return err
	}
	_ = control.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, control); packets.Close(); close(done) }()
	defer func() { control.Close(); <-done }()
	peerHost, _, _ := net.SplitHostPort(control.RemoteAddr().String())
	flows := newUDPFlows(r)
	defer flows.Close()
	buffer := make([]byte, 65535)
	var peer string
	for {
		n, from, err := packets.ReadFrom(buffer)
		if err != nil {
			return err
		}
		fromText := from.String()
		fromHost, _, _ := net.SplitHostPort(fromText)
		if fromHost != peerHost || peer != "" && peer != fromText || n < 4 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 {
			continue
		}
		reader := bytes.NewReader(buffer[3:n])
		address, err := readAddress(reader)
		if err != nil {
			continue
		}
		if err := validAddress(address); err != nil {
			continue
		}
		if peer == "" {
			peer = fromText
		}
		payload := buffer[n-reader.Len() : n]
		q.address = address
		q.origin = r.socketOrigin(from, packets.LocalAddr())
		err = flows.send(address, q, payload, func(b []byte, address string) error {
			owner := packetBuffers.Get().([]byte)
			defer packetBuffers.Put(owner)
			response, err := appendAddress(append(owner[:0], 0, 0, 0), address)
			if err != nil {
				return err
			}
			_, err = packets.WriteTo(append(response, b...), from)
			return err
		})
		if err != nil && r.ctx.Err() != nil {
			return err
		}
	}
}

func (r *Runtime) serveSSPackets(in Inbound, packets net.PacketConn) {
	if isSS2022(in.Method) {
		r.serveSS2022Packets(in, packets)
		return
	}
	key := r.keys["in:"+in.Tag]
	var ssr *ssrDatagrams
	if in.Type == "shadowsocksr" {
		ssr, _ = newSSRDatagrams(key, in.Protocol, in.ProtocolParam)
	} else if in.OTA {
		ssr, _ = newSSRDatagrams(key, "verify_sha1", "")
	}
	flows := newUDPFlows(r)
	defer flows.Close()
	buffer := make([]byte, 65535)
	for {
		n, from, err := packets.ReadFrom(buffer)
		if err != nil {
			return
		}
		var plain []byte
		if ssr != nil {
			plain, err = ssr.open(buffer[:n], true)
		} else {
			plain, err = key.openPacket(buffer[:n], &r.replay)
		}
		if err != nil {
			continue
		}
		reader := bytes.NewReader(plain)
		address, err := readAddress(reader)
		if err != nil {
			continue
		}
		if err := validAddress(address); err != nil {
			continue
		}
		payload := plain[len(plain)-reader.Len():]
		source := from.String()
		q := request{origin: r.socketOrigin(from, packets.LocalAddr()), network: "udp", address: address, inbound: in.Tag, source: source}
		_ = flows.send(strconv.Itoa(len(source))+":"+source+address, q, payload, func(b []byte, address string) error {
			var header [1 + 1 + 255 + 2]byte
			encoded, err := appendAddress(header[:0], address)
			if err != nil {
				return err
			}
			owner := packetBuffers.Get().([]byte)
			defer packetBuffers.Put(owner)
			var packet []byte
			if ssr != nil {
				packet, err = ssr.seal(append(append(owner[:0], encoded...), b...), true)
			} else {
				packet, err = key.appendSealPacket(owner[:0], encoded, b, &r.replay)
			}
			if err != nil {
				return err
			}
			_, err = packets.WriteTo(packet, from)
			return err
		})
	}
}

func (r *Runtime) udpTimeoutFor(tag string, fallback time.Duration) time.Duration {
	if timeout := r.udpTimeouts[tag]; timeout != 0 {
		return timeout
	}
	return fallback
}
