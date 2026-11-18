package native

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

func quicALPN(kind string) []string {
	if kind == "dns-quic" {
		return []string{"doq"}
	}
	if kind == "hysteria" {
		return []string{"hysteria"}
	}
	return []string{"h3"}
}
func (s *quicProxySession) authenticateTUIC4(ctx context.Context, token string) error {
	h := blake3Sum([]byte(token))
	stream, e := s.conn.OpenStream(ctx, true)
	if e != nil {
		return e
	}
	defer stream.Close()
	if d, ok := ctx.Deadline(); ok {
		stream.SetWriteDeadline(d)
	}
	if e = writeAll(stream, append([]byte{4, 0}, h[:]...)); e != nil {
		return e
	}
	return stream.finishUni()
}
func (s *quicProxySession) serveTUIC4Auth(in Inbound, stream *quicStream, auth chan struct{}, once *sync.Once) error {
	var h [32]byte
	if _, e := io.ReadFull(stream, h[:]); e != nil {
		return e
	}
	valid := 0
	for _, u := range in.Users {
		token := u.Token
		if token == "" {
			token = u.Password
		}
		expected := blake3Sum([]byte(token))
		valid |= subtle.ConstantTimeCompare(h[:], expected[:])
	}
	if valid != 1 {
		s.conn.cancel()
		return errors.New("TUIC4 authentication rejected")
	}
	once.Do(func() { close(auth) })
	return nil
}
func decodeTUIC4Packet(b []byte) (id uint32, pid uint16, index, count byte, address string, payload []byte, err error) {
	if len(b) == 2 && b[0] == 4 && b[1] == 4 {
		return
	}
	if len(b) < 9 || b[0] != 4 || b[1] != 2 {
		err = errors.New("invalid TUIC4 datagram")
		return
	}
	id = binary.BigEndian.Uint32(b[2:])
	size := int(quicU16(b[6:]))
	r := &sliceReader{data: b[8:]}
	address, err = readTUICAddress(r)
	payload = r.data
	if err == nil && (address == "" || len(payload) != size) {
		err = errors.New("invalid TUIC4 packet length or address")
	}
	count = 1
	return
}
func (s *quicProxySession) sendTUIC4Packet(id uint32, address string, payload []byte, stream bool) error {
	addr, e := tuicAddress(address)
	if e != nil {
		return e
	}
	b := binary.BigEndian.AppendUint32(append(make([]byte, 0, 8+len(addr)+len(payload)), 4, 2), id)
	b = binary.BigEndian.AppendUint16(b, uint16(len(payload)))
	b = append(b, addr...)
	b = append(b, payload...)
	// TUIC4 binds each association to its chosen relay mode; modes cannot be mixed.
	if !stream && len(b) > 1100 {
		return errors.New("TUIC4 native datagram exceeds transport MTU; select udp_relay_mode quic")
	}
	if stream {
		q, e := s.conn.OpenStream(s.conn.ctx, true)
		if e != nil {
			return e
		}
		defer q.Close()
		if e = writeAll(q, b); e != nil {
			return e
		}
		return q.finishUni()
	}
	return s.conn.sendDatagramOwned(s.conn.ctx, b)
}
func hy1Rates(up, down int) (uint64, uint64) {
	if up == 0 {
		up = 100
	}
	if down == 0 {
		down = 100
	}
	return uint64(up) * 125000, uint64(down) * 125000
}
func hy1Text(b []byte, text string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(text)))
	return append(b, text...)
}
func readHY1Text(r io.Reader, maxSize int) (string, error) {
	var n [2]byte
	if _, e := io.ReadFull(r, n[:]); e != nil {
		return "", e
	}
	size := int(quicU16(n[:]))
	if size > maxSize {
		return "", errors.New("HY1 field too long")
	}
	b := make([]byte, size)
	_, e := io.ReadFull(r, b)
	return string(b), e
}
func (s *quicProxySession) authenticateHY1(ctx context.Context, o Outbound) error {
	q, e := s.conn.OpenStream(ctx, false)
	if e != nil {
		return e
	}
	if q.id != 0 {
		q.Close()
		return errors.New("HY1 control stream must be first")
	}
	if d, ok := ctx.Deadline(); ok {
		q.SetDeadline(d)
	}
	up, down := hy1Rates(o.UpMbps, o.DownMbps)
	b := binary.BigEndian.AppendUint64([]byte{3}, up)
	b = binary.BigEndian.AppendUint64(b, down)
	b = hy1Text(b, o.Password)
	if e = writeAll(q, b); e != nil {
		q.Close()
		return e
	}
	var response [17]byte
	if _, e = io.ReadFull(q, response[:]); e != nil {
		q.Close()
		return e
	}
	message, e := readHY1Text(q, 4096)
	if response[0] == 1 && (binary.BigEndian.Uint64(response[1:]) == 0 || binary.BigEndian.Uint64(response[9:]) == 0) {
		q.Close()
		return errors.New("invalid HY1 server bandwidth")
	}
	if e != nil {
		q.Close()
		return e
	}
	if response[0] != 1 {
		q.Close()
		return fmt.Errorf("HY1 authentication rejected: %s", message)
	}
	s.conn.setHY1Rate(o.CongestionControl, min(up, binary.BigEndian.Uint64(response[9:])))
	q.SetDeadline(time.Time{})
	s.hy1Control = q
	go func() { io.Copy(io.Discard, q); s.conn.cancel() }()
	return nil
}
func hy1Request(address string, udp bool) ([]byte, error) {
	h, p, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	port, e := strconv.ParseUint(p, 10, 16)
	if e != nil || port == 0 || len(h) > 255 {
		return nil, errors.New("invalid HY1 address")
	}
	b := []byte{0}
	if udp {
		b[0] = 1
	}
	return binary.BigEndian.AppendUint16(hy1Text(b, h), uint16(port)), nil
}
func hy1Response(q io.Writer, ok bool, id uint32, message string) error {
	b := byte(0)
	if ok {
		b = 1
	}
	return writeAll(q, hy1Text(binary.BigEndian.AppendUint32([]byte{b}, id), message))
}
func (s *quicProxySession) hy1Connect(q *quicStream, address string, udp bool) error {
	b, e := hy1Request(address, udp)
	if e != nil {
		return e
	}
	if e = writeAll(q, b); e != nil {
		return e
	}
	var response [5]byte
	if _, e = io.ReadFull(q, response[:]); e != nil {
		return e
	}
	message, e := readHY1Text(q, 4096)
	if e != nil {
		return e
	}
	if response[0] != 1 {
		return fmt.Errorf("HY1 connect rejected: %s", message)
	}
	return nil
}
func (r *Runtime) ownHY1Packet(ctx context.Context, s *quicProxySession, address string) (net.Conn, error) {
	q, e := s.conn.OpenStream(ctx, false)
	if e != nil {
		return nil, e
	}
	good := false
	defer func() {
		if !good {
			q.Close()
		}
	}()
	if d, ok := ctx.Deadline(); ok {
		q.SetDeadline(d)
	}
	b, e := hy1Request(address, true)
	if e != nil {
		return nil, e
	}
	if e = writeAll(q, b); e != nil {
		return nil, e
	}
	var response [5]byte
	if _, e = io.ReadFull(q, response[:]); e != nil {
		return nil, e
	}
	message, e := readHY1Text(q, 4096)
	if e != nil {
		return nil, e
	}
	if response[0] != 1 {
		return nil, fmt.Errorf("HY1 UDP rejected: %s", message)
	}
	id := binary.BigEndian.Uint32(response[1:])
	s.mu.Lock()
	if len(s.packets) >= 256 {
		s.mu.Unlock()
		return nil, errors.New("HY1 UDP session capacity reached")
	}
	p := &quicProxyPacket{session: s, id: id, address: address, incoming: make(chan quicProxyDatagram, 64), closed: make(chan struct{}), wake: make(chan struct{}, 1)}
	if s.packets[id] != nil {
		s.mu.Unlock()
		return nil, errors.New("duplicate HY1 UDP session")
	}
	s.packets[id] = p
	s.mu.Unlock()
	q.SetDeadline(time.Time{})
	good = true
	c := &hy1PacketControl{quicProxyPacket: p, control: q}
	go func() { io.Copy(io.Discard, q); c.Close() }()
	return r.own(c)
}

type hy1PacketControl struct {
	*quicProxyPacket
	control *quicStream
}

func (c *hy1PacketControl) Close() error { c.quicProxyPacket.Close(); return c.control.Close() }
func (s *quicProxySession) serveHY1Stream(r *Runtime, in Inbound, q *quicStream, auth chan struct{}, once *sync.Once) error {
	if q.id&2 != 0 {
		return errors.New("HY1 requires bidirectional streams")
	}
	if q.id == 0 {
		var hello [17]byte
		if _, e := io.ReadFull(q, hello[:]); e != nil {
			return e
		}
		password, e := readHY1Text(q, 4096)
		if e != nil {
			return e
		}
		valid := 0
		for _, u := range in.Users {
			valid |= subtle.ConstantTimeCompare([]byte(password), []byte(u.Password))
		}
		if in.Password != "" {
			valid |= subtle.ConstantTimeCompare([]byte(password), []byte(in.Password))
		}
		if hello[0] != 3 || binary.BigEndian.Uint64(hello[1:]) == 0 || binary.BigEndian.Uint64(hello[9:]) == 0 || valid != 1 {
			writeAll(q, hy1Text(make([]byte, 17), "authentication rejected"))
			s.conn.cancel()
			return errors.New("HY1 authentication rejected")
		}
		up, down := hy1Rates(in.UpMbps, in.DownMbps)
		s.conn.setHY1Rate(in.CongestionControl, min(up, binary.BigEndian.Uint64(hello[9:])))
		b := binary.BigEndian.AppendUint64([]byte{1}, up)
		b = binary.BigEndian.AppendUint64(b, down)
		if e = writeAll(q, hy1Text(b, "")); e != nil {
			return e
		}
		once.Do(func() { close(auth) })
		q.SetDeadline(time.Time{})
		io.Copy(io.Discard, q)
		s.conn.cancel()
		return nil
	}
	if e := waitQUICAuth(s.conn.ctx, auth); e != nil {
		return e
	}
	var udp [1]byte
	if _, e := io.ReadFull(q, udp[:]); e != nil {
		return e
	}
	host, e := readHY1Text(q, 255)
	if e != nil {
		return e
	}
	var port [2]byte
	if _, e = io.ReadFull(q, port[:]); e != nil {
		return e
	}
	address := net.JoinHostPort(host, strconv.Itoa(int(quicU16(port[:]))))
	if udp[0] == 1 {
		s.mu.Lock()
		if len(s.hy1Associations) >= 256 {
			s.mu.Unlock()
			return errors.New("HY1 UDP session capacity reached")
		}
		for {
			s.next++
			if !s.hy1Associations[s.next] {
				break
			}
		}
		id := s.next
		s.hy1Associations[id] = true
		s.mu.Unlock()
		defer func() { s.mu.Lock(); delete(s.hy1Associations, id); s.mu.Unlock(); s.closeAssociation(id) }()
		if e = hy1Response(q, true, id, ""); e != nil {
			return e
		}
		q.SetDeadline(time.Time{})
		_, e = io.Copy(io.Discard, q)
		return e
	}
	if udp[0] != 0 {
		return errors.New("invalid HY1 network")
	}
	remote, e := r.routeDial(s.conn.ctx, request{origin: r.socketOrigin(s.conn.remote, s.conn.local), network: "tcp", inbound: in.Tag, source: s.conn.remote.String(), address: address})
	if e != nil {
		hy1Response(q, false, 0, "connection failed")
		return e
	}
	if e = hy1Response(q, true, 0, ""); e != nil {
		remote.Close()
		return e
	}
	q.SetDeadline(time.Time{})
	r.relay(q, remote)
	return nil
}
func decodeHY1Packet(b []byte) (id uint32, pid uint16, index, count byte, address string, payload []byte, err error) {
	if len(b) < 14 {
		err = io.ErrUnexpectedEOF
		return
	}
	id = binary.BigEndian.Uint32(b)
	n := int(quicU16(b[4:]))
	if n > 255 || len(b) < 14+n {
		err = errors.New("invalid HY1 UDP header")
		return
	}
	host := string(b[6 : 6+n])
	b = b[6+n:]
	address = net.JoinHostPort(host, strconv.Itoa(int(quicU16(b))))
	pid = quicU16(b[2:])
	index, count = b[4], b[5]
	size := int(quicU16(b[6:]))
	payload = b[8:]
	if size != len(payload) || count == 0 || index >= count {
		err = errors.New("invalid HY1 UDP payload")
	}
	return
}
func encodeHY1Packet(id uint32, pid uint16, index, count byte, address string, payload []byte) []byte {
	h, p, e := net.SplitHostPort(address)
	if e != nil || len(h) > 255 {
		return nil
	}
	port, e := strconv.ParseUint(p, 10, 16)
	if e != nil {
		return nil
	}
	b := hy1Text(binary.BigEndian.AppendUint32(make([]byte, 0, 16+len(h)+len(payload)), id), h)
	b = binary.BigEndian.AppendUint16(b, uint16(port))
	b = binary.BigEndian.AppendUint16(b, pid)
	b = append(b, index, count)
	b = binary.BigEndian.AppendUint16(b, uint16(len(payload)))
	return append(b, payload...)
}
func xplusSeal(b []byte, password string) []byte {
	salt := make([]byte, 16)
	rand.Read(salt)
	out := append(salt, b...)
	key := sha256.Sum256(append([]byte(password), salt...))
	for i := 16; i < len(out); i++ {
		out[i] ^= key[(i-16)%32]
	}
	return out
}
func xplusOpen(b []byte, password string) ([]byte, error) {
	if len(b) < 16 {
		return nil, errors.New("invalid XPlus datagram")
	}
	key := sha256.Sum256(append([]byte(password), b[:16]...))
	p := b[16:]
	for i := range p {
		p[i] ^= key[i%32]
	}
	return p, nil
}

type xplusConn struct {
	net.Conn
	password string
}

func (c *xplusConn) Read(b []byte) (int, error) {
	raw := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(raw)
	n, e := c.Conn.Read(raw)
	if e != nil {
		return 0, e
	}
	p, e := xplusOpen(raw[:n], c.password)
	if e != nil {
		return 0, e
	}
	return copy(b, p), nil
}
func (c *xplusConn) Write(b []byte) (int, error) {
	_, e := c.Conn.Write(xplusSeal(b, c.password))
	if e != nil {
		return 0, e
	}
	return len(b), nil
}

type xplusPacket struct {
	net.PacketConn
	password string
}

func (c *xplusPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	raw := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(raw)
	for {
		n, a, e := c.PacketConn.ReadFrom(raw)
		if e != nil {
			return 0, a, e
		}
		p, e := xplusOpen(raw[:n], c.password)
		if e == nil {
			return copy(b, p), a, nil
		}
	}
}
func (c *xplusPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	_, e := c.PacketConn.WriteTo(xplusSeal(b, c.password), a)
	if e != nil {
		return 0, e
	}
	return len(b), nil
}

func (s *quicProxySession) dissociate(id uint32) {
	ctx, cancel := context.WithTimeout(s.conn.ctx, 250*time.Millisecond)
	defer cancel()
	q, e := s.conn.OpenStream(ctx, true)
	if e != nil {
		return
	}
	defer q.Close()
	if d, ok := ctx.Deadline(); ok {
		q.SetWriteDeadline(d)
	}
	b := []byte{s.version, 3}
	if s.version == 4 {
		b = binary.BigEndian.AppendUint32(b, id)
	} else {
		b = binary.BigEndian.AppendUint16(b, uint16(id))
	}
	if writeAll(q, b) == nil {
		q.CloseWrite()
	}
}
