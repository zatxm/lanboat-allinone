package native

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type quicProxyClient struct {
	runtime  *Runtime
	outbound Outbound
	mu       sync.Mutex
	current  *quicProxySession
}
type quicProxySession struct {
	version         byte
	hy1Control      *quicStream
	hy1Associations map[uint32]bool
	flows           *udpFlows
	streamUDP       bool
	conn            *quicConn
	kind            string
	udp             bool
	mu              sync.Mutex
	packets         map[uint32]*quicProxyPacket
	next            uint32
	packetID        atomic.Uint32
	fragments       map[uint64]*quicProxyFragments
}
type quicProxyFragments struct {
	at      time.Time
	count   byte
	address string
	pieces  map[byte][]byte
	size    int
}

func isQUICProxy(kind string) bool {
	return kind == "hysteria" || kind == "hysteria2" || kind == "tuic" || kind == "juicity"
}
func (p *quicProxyClient) close() {
	p.mu.Lock()
	s := p.current
	p.current = nil
	p.mu.Unlock()
	if s != nil {
		s.conn.Close()
	}
}
func (p *quicProxyClient) session(ctx context.Context) (*quicProxySession, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s := p.current; s != nil {
		select {
		case <-s.conn.done:
			p.current = nil
		default:
			return s, nil
		}
	}
	raw, e := p.runtime.hysteriaEndpoint(ctx, p.outbound)
	if e != nil {
		return nil, e
	}
	if p.outbound.Type == "hysteria" && p.outbound.Protocol == "wechat-video" {
		raw = newWechatConn(raw)
	}
	obfs, _ := p.outbound.Obfs.quicSettings()
	if obfs.Type == "gecko" {
		raw = &geckoConn{Conn: raw, codec: newGecko(obfs)}
	} else if obfs.Password != "" {
		raw = &salamanderConn{Conn: raw, password: obfs.Password}
	}
	if p.outbound.Type == "hysteria" && p.outbound.Obfs != "" {
		raw = &xplusConn{Conn: raw, password: string(p.outbound.Obfs)}
	}
	cfg, e := p.runtime.outboundTLS(ctx, p.outbound)
	if e != nil {
		raw.Close()
		return nil, e
	}
	cfg = cloneTLSConfig(cfg)
	if p.outbound.PinnedCertchainSHA256 != "" {
		configureJuicityPin(cfg, p.outbound.PinnedCertchainSHA256, p.outbound.TLS)
	}
	if len(cfg.NextProtos) == 0 {
		cfg.NextProtos = quicALPN(p.outbound.Type)
	}
	options := proxyQUICOptions(p.outbound.Type, p.outbound.CongestionControl)
	if p.outbound.BBRProfile != "" {
		options.bbrProfile = p.outbound.BBRProfile
	}
	options.disableLossCompensation = p.outbound.DisableLossCompensation
	if p.outbound.Type == "hysteria" && p.outbound.Protocol == "faketcp" {
		options.receiveMTU = 1200
	}
	c, e := dialQUIC(ctx, p.runtime.ctx, raw, cfg, p.outbound.QUICReceiveWindows.apply(options))
	if e != nil {
		return nil, e
	}
	s := newQUICProxySession(c, p.outbound.Type)
	if p.outbound.Version == "4" {
		s.version = 4
	}
	s.streamUDP = p.outbound.UDPRelayMode == "quic"
	go s.clientStreams()
	if s.kind == "hysteria" {
		e = s.authenticateHY1(ctx, p.outbound)
	} else if s.kind == "tuic" && s.version == 4 {
		token := p.outbound.Token
		if token == "" {
			token = p.outbound.Password
		}
		e = s.authenticateTUIC4(ctx, token)
	} else if s.kind == "hysteria2" {
		e = s.authenticateHY2(ctx, p.outbound)
	} else {
		e = s.authenticateTUIC(ctx, p.outbound.UUID, p.outbound.Password)
	}
	if e != nil {
		c.Close()
		return nil, e
	}
	p.current = s
	if s.kind != "juicity" {
		go s.receivePackets(nil, Inbound{})
	}
	return s, nil
}
func newQUICProxySession(c *quicConn, kind string) *quicProxySession {
	s := &quicProxySession{conn: c, kind: kind, version: 5, hy1Associations: map[uint32]bool{}, udp: true, packets: map[uint32]*quicProxyPacket{}, fragments: map[uint64]*quicProxyFragments{}}
	if kind == "juicity" {
		s.version = 0
	}
	return s
}
func (s *quicProxySession) clientStreams() {
	for {
		stream, e := s.conn.AcceptStream(s.conn.ctx)
		if e != nil {
			return
		}
		go func() {
			defer stream.Close()
			if s.kind == "tuic" && stream.id&2 != 0 {
				body, e := io.ReadAll(io.LimitReader(stream, 65536))
				if e == nil {
					s.handlePacketFlows(nil, Inbound{}, nil, body, true)
				}
				return
			}
			if s.kind == "hysteria2" && stream.id&2 != 0 {
				if e := h3Uni(stream); e != nil && s.conn.ctx.Err() == nil {
					s.conn.cancel()
				}
			}
		}()
	}
}
func (s *quicProxySession) authenticateHY2(ctx context.Context, out Outbound) error {
	if e := h3Start(ctx, s.conn); e != nil {
		return e
	}
	stream, e := s.conn.OpenStream(ctx, false)
	if e != nil {
		return e
	}
	defer stream.Close()
	if d, ok := ctx.Deadline(); ok {
		stream.SetDeadline(d)
	}
	headers := [][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", "hysteria"}, {":path", "/auth"}, {"hysteria-auth", out.Password}, {"hysteria-cc-rx", strconv.FormatUint(uint64(out.DownMbps)*125000, 10)}, {"hysteria-padding", fmt.Sprintf("%x", quicPadding())}}
	// Header padding uses a printable alphabet so it remains a valid field value.
	if e = h3WriteFrame(stream, 1, h3Encode(headers)); e == nil {
		e = h3FinishRequest(stream)
	}
	if e != nil {
		return e
	}
	h, e := h3Status(stream)
	if e != nil {
		return e
	}
	if h[":status"] != "233" {
		return errors.New("HY2 authentication rejected")
	}
	s.udp = h["hysteria-udp"] == "true"
	rate, err := hy2ClientRate(out.UpMbps, h["hysteria-cc-rx"])
	if err != nil {
		return err
	}
	s.conn.setBrutalRate(rate)
	return nil
}
func (s *quicProxySession) authenticateTUIC(ctx context.Context, uuid, password string) error {
	u, e := parseUUID(uuid)
	if e != nil {
		return e
	}
	token, e := s.conn.state.ExportKeyingMaterial(string(u[:]), []byte(password), 32)
	if e != nil {
		return e
	}
	stream, e := s.conn.OpenStream(ctx, true)
	if e != nil {
		return e
	}
	if d, ok := ctx.Deadline(); ok {
		stream.SetWriteDeadline(d)
	}
	if e = writeAll(stream, append(append([]byte{s.version, 0}, u[:]...), token...)); e != nil {
		stream.Close()
		return e
	}
	if e = stream.finishUni(); e != nil {
		stream.Close()
		return e
	}
	return stream.Close()
}
func (p *quicProxyClient) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if _, _, e := net.SplitHostPort(address); e != nil {
		return nil, e
	}
	s, e := p.session(ctx)
	if e != nil {
		return nil, e
	}
	if s.kind == "juicity" {
		return p.dialJuicity(ctx, s, network, address)
	}
	if network == "udp" {
		if !s.udp {
			return nil, errors.New("server disabled UDP relay")
		}
		if s.kind == "hysteria" {
			return p.runtime.ownHY1Packet(ctx, s, address)
		}
		return p.runtime.own(s.packet(address))
	}
	stream, e := s.conn.OpenStream(ctx, false)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			stream.Close()
		}
	}()
	if d, yes := ctx.Deadline(); yes {
		stream.SetDeadline(d)
	}
	if s.kind == "hysteria" {
		if e = s.hy1Connect(stream, address, false); e != nil {
			return nil, e
		}
	} else if s.kind == "hysteria2" {
		header := quicString(quicVar(nil, 0x401), address)
		header = quicString(header, "")
		if e = writeAll(stream, header); e != nil {
			return nil, e
		}
		var status [1]byte
		if _, e = io.ReadFull(stream, status[:]); e != nil {
			return nil, e
		}
		message, e := readQUICString(stream, 4096)
		if e != nil {
			return nil, e
		}
		if _, e = readQUICString(stream, 4096); e != nil {
			return nil, e
		}
		if status[0] != 0 {
			return nil, fmt.Errorf("HY2 connect: %s", message)
		}
	} else {
		addr, e := tuicAddress(address)
		if e != nil {
			return nil, e
		}
		if e = writeAll(stream, append([]byte{s.version, 1}, addr...)); e != nil {
			return nil, e
		}
		if s.version == 4 {
			var status [3]byte
			if _, e = io.ReadFull(stream, status[:]); e != nil {
				return nil, e
			}
			if status != [3]byte{4, 255, 0} {
				return nil, errors.New("TUIC4 connection rejected")
			}
		}
	}
	stream.SetDeadline(time.Time{})
	ok = true
	return p.runtime.own(stream)
}
func (r *Runtime) acceptQUIC(in Inbound, l *quicEndpoint) {
	defer r.workers.Done()
	for {
		c, e := l.Accept(r.ctx)
		if e != nil {
			return
		}
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			c.Close()
			return
		}
		r.workers.Add(1)
		r.mu.Unlock()
		go func() {
			defer r.workers.Done()
			var e error
			if in.Transport.Type == "xhttp" {
				e = r.serveXHTTPQUIC(in, c)
			} else if in.Transport.Type == "quic" {
				e = r.serveQUICTransport(in, c)
			} else if in.Type == "masque" {
				e = r.serveMasque(in, c)
			} else if in.Type == "trusttunnel" || in.Type == "naive" {
				e = r.serveTrustQUIC(in, c)
			} else if isDNSQUIC(in.Type) {
				e = r.serveDNSQUIC(in, c)
			} else {
				e = r.serveQUICProxy(in, c)
			}
			if e != nil && r.ctx.Err() == nil {
				logDebug(r.logger, e, r.inboundLabel(in.Tag), ": QUIC session ended")
			}
		}()
	}
}
func (r *Runtime) serveQUICProxy(in Inbound, c *quicConn) error {
	s := newQUICProxySession(c, in.Type)
	if in.Version == "4" {
		s.version = 4
	}
	s.flows = newUDPFlows(r)
	defer s.flows.Close()
	defer c.Close()
	authenticated := make(chan struct{})
	var authOnce sync.Once
	var active sync.WaitGroup
	defer func() { c.cancel(); active.Wait() }()
	if in.Type == "hysteria2" {
		ctx, cancel := context.WithTimeout(c.ctx, handshakeTimeout)
		e := h3Start(ctx, c)
		cancel()
		if e != nil {
			return e
		}
	}
	active.Add(1)
	go func() {
		defer active.Done()
		timer := time.NewTimer(handshakeTimeout)
		defer timer.Stop()
		select {
		case <-authenticated:
			if s.kind == "juicity" {
				<-c.ctx.Done()
			} else {
				s.receivePackets(r, in)
			}
		case <-timer.C:
			c.cancel()
		case <-c.ctx.Done():
		}
	}()
	for {
		stream, e := c.AcceptStream(c.ctx)
		if e != nil {
			return e
		}
		active.Add(1)
		go func() {
			defer active.Done()
			defer stream.Close()
			stream.SetDeadline(time.Now().Add(handshakeTimeout))
			e := s.serveStream(r, in, stream, authenticated, &authOnce)
			if e != nil && c.ctx.Err() == nil {
				logDebug(r.logger, e, r.inboundLabel(in.Tag), ": QUIC request failed")
			}
		}()
	}
}
func (s *quicProxySession) serveStream(r *Runtime, in Inbound, stream *quicStream, auth chan struct{}, once *sync.Once) error {
	if s.kind == "juicity" {
		return s.serveJuicityStream(r, in, stream, auth, once)
	}
	if s.kind == "hysteria" {
		return s.serveHY1Stream(r, in, stream, auth, once)
	}
	if s.kind == "hysteria2" && stream.id&2 != 0 {
		stream.SetDeadline(time.Time{})
		return h3Uni(stream)
	}
	if s.kind == "hysteria2" {
		kind, e := readQUICVar(stream)
		if e != nil {
			return e
		}
		if kind == 1 {
			return serveHY2Auth(s.conn, in, stream, auth, once, false)
		}
		if kind != 0x401 {
			return errors.New("invalid HY2 request")
		}
		if e = waitQUICAuth(s.conn.ctx, auth); e != nil {
			return e
		}
		address, e := readQUICString(stream, 512)
		if e != nil {
			return e
		}
		if _, e = readQUICString(stream, 4096); e != nil {
			return e
		}
		return s.relayTCP(r, in, stream, address, true)
	}
	var header [2]byte
	if _, e := io.ReadFull(stream, header[:]); e != nil {
		return e
	}
	if header[0] != s.version {
		return errors.New("invalid TUIC version")
	}
	if header[1] == 0 && stream.id&2 != 0 {
		if s.version == 4 {
			return s.serveTUIC4Auth(in, stream, auth, once)
		}
		var body [48]byte
		if _, e := io.ReadFull(stream, body[:]); e != nil {
			return e
		}
		valid := 0
		for _, u := range in.Users {
			uuid, _ := parseUUID(u.UUID)
			expected, e := s.conn.state.ExportKeyingMaterial(string(uuid[:]), []byte(u.Password), 32)
			if e != nil {
				return e
			}
			valid |= subtle.ConstantTimeCompare(uuid[:], body[:16]) & subtle.ConstantTimeCompare(expected, body[16:])
		}
		if valid != 1 {
			s.conn.cancel()
			return errors.New("TUIC authentication rejected")
		}
		once.Do(func() { close(auth) })
		return nil
	}
	if e := waitQUICAuth(s.conn.ctx, auth); e != nil {
		return e
	}
	switch header[1] {
	case 1:
		if stream.id&2 != 0 {
			return errors.New("TUIC CONNECT requires bidirectional stream")
		}
		address, e := readTUICAddress(stream)
		if e != nil {
			return e
		}
		return s.relayTCP(r, in, stream, address, false)
	case 2:
		if stream.id&2 == 0 {
			return errors.New("TUIC UDP requires unidirectional stream")
		}
		body, e := io.ReadAll(io.LimitReader(stream, 65536))
		if e != nil {
			return e
		}
		return s.handlePacket(r, in, append(header[:], body...), true)
	case 3:
		id := make([]byte, 2)
		if s.version == 4 {
			id = make([]byte, 4)
		}
		if _, e := io.ReadFull(stream, id); e != nil {
			return e
		}
		n := uint32(quicU16(id))
		if s.version == 4 {
			n = binary.BigEndian.Uint32(id)
		}
		s.closeAssociation(n)
		return nil
	default:
		return errors.New("invalid TUIC command")
	}
}
func waitQUICAuth(ctx context.Context, ch <-chan struct{}) error {
	timer := time.NewTimer(handshakeTimeout)
	defer timer.Stop()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("QUIC authentication timeout")
	}
}
func (s *quicProxySession) relayTCP(r *Runtime, in Inbound, stream *quicStream, address string, respond bool) error {
	remote, e := r.routeDial(s.conn.ctx, request{origin: r.socketOrigin(s.conn.remote, s.conn.local), network: "tcp", inbound: in.Tag, source: s.conn.remote.String(), address: address})
	if respond {
		status, message := byte(0), ""
		if e != nil {
			status, message = 1, "connection failed"
		}
		if writeErr := writeAll(stream, quicString(quicString([]byte{status}, message), "")); writeErr != nil {
			if remote != nil {
				remote.Close()
			}
			return writeErr
		}
	}
	if s.kind == "tuic" && s.version == 4 {
		status := byte(0)
		if e != nil {
			status = 1
		}
		if we := writeAll(stream, []byte{4, 255, status}); we != nil {
			if remote != nil {
				remote.Close()
			}
			return we
		}
	}
	if e != nil {
		return e
	}
	stream.SetDeadline(time.Time{})
	r.relay(stream, remote)
	return nil
}
func tuicAddress(address string) ([]byte, error) {
	b, e := encodeAddress(address)
	if e != nil {
		return nil, e
	}
	switch b[0] {
	case 1:
		b[0] = 1
	case 3:
		b[0] = 0
	case 4:
		b[0] = 2
	}
	return b, nil
}
func readTUICAddress(r io.Reader) (string, error) {
	var kind [1]byte
	if _, e := io.ReadFull(r, kind[:]); e != nil {
		return "", e
	}
	if kind[0] == 255 {
		return "", nil
	}
	switch kind[0] {
	case 0:
		kind[0] = 3
	case 1:
		kind[0] = 1
	case 2:
		kind[0] = 4
	default:
		return "", errors.New("invalid TUIC address type")
	}
	return readAddress(io.MultiReader(&oneByteReader{value: kind[0]}, r))
}

type oneByteReader struct {
	value byte
	read  bool
}

func (r *oneByteReader) Read(b []byte) (int, error) {
	if r.read {
		return 0, io.EOF
	}
	if len(b) == 0 {
		return 0, nil
	}
	b[0] = r.value
	r.read = true
	return 1, nil
}

func (s *quicProxySession) packet(address string) *quicProxyPacket {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.packets) >= 256 {
		return &quicProxyPacket{session: s, address: address, closed: make(chan struct{}), incoming: make(chan quicProxyDatagram), err: errors.New("QUIC UDP session capacity reached")}
	}
	for {
		s.next++
		if s.kind == "tuic" && s.version != 4 {
			s.next = uint32(uint16(s.next))
		}
		if s.packets[s.next] == nil {
			break
		}
	}
	p := &quicProxyPacket{session: s, id: s.next, address: address, incoming: make(chan quicProxyDatagram, 64), closed: make(chan struct{}), wake: make(chan struct{}, 1)}
	s.packets[p.id] = p
	return p
}
func (s *quicProxySession) receivePackets(r *Runtime, in Inbound) {
	var flows *udpFlows
	if r != nil {
		flows = s.flows
	}
	for {
		b, e := s.conn.ReceiveDatagram(s.conn.ctx)
		if e != nil {
			return
		}
		_ = s.handlePacketFlows(r, in, flows, b, false)
	}
}
func (s *quicProxySession) handlePacket(r *Runtime, in Inbound, b []byte, stream bool) error {
	return s.handlePacketFlows(r, in, s.flows, b, stream)
}
func (s *quicProxySession) handlePacketFlows(r *Runtime, in Inbound, flows *udpFlows, b []byte, stream bool) error {
	id, pid, index, count, address, payload, e := s.decodePacket(b)
	if e != nil {
		return e
	}
	if count == 0 {
		return nil
	}
	s.mu.Lock()
	if count > 1 {
		key := uint64(id)<<16 | uint64(pid)
		now := time.Now()
		for k, f := range s.fragments {
			if now.Sub(f.at) > 5*time.Second {
				delete(s.fragments, k)
			}
		}
		f := s.fragments[key]
		if f == nil {
			if len(s.fragments) >= 64 {
				s.mu.Unlock()
				return errors.New("QUIC UDP fragment capacity reached")
			}
			f = &quicProxyFragments{at: now, count: count, pieces: map[byte][]byte{}}
			s.fragments[key] = f
		}
		if f.count != count || index >= count {
			delete(s.fragments, key)
			s.mu.Unlock()
			return errors.New("inconsistent QUIC UDP fragments")
		}
		if index == 0 {
			f.address = address
		}
		if _, ok := f.pieces[index]; !ok {
			f.size += len(payload)
			// payload belongs to a freshly allocated datagram, so keep it as is.
			f.pieces[index] = payload
		}
		if f.size > 65507 {
			delete(s.fragments, key)
			s.mu.Unlock()
			return errors.New("UDP payload too large")
		}
		if len(f.pieces) != int(count) {
			s.mu.Unlock()
			return nil
		}
		address = f.address
		payload = make([]byte, 0, f.size)
		for i := byte(0); i < count; i++ {
			payload = append(payload, f.pieces[i]...)
		}
		delete(s.fragments, key)
	}
	p := s.packets[id]
	s.mu.Unlock()
	if r == nil {
		if p != nil {
			// Callers pass freshly allocated buffers, so payload can be handed off.
			if payload == nil {
				payload = []byte{}
			}
			select {
			case p.incoming <- quicProxyDatagram{address: address, payload: payload}:
			default:
			}
		}
		return nil
	}
	if _, _, e := net.SplitHostPort(address); e != nil {
		return e
	}
	if s.kind == "hysteria" {
		s.mu.Lock()
		allowed := s.hy1Associations[id]
		s.mu.Unlock()
		if !allowed {
			return errors.New("unknown HY1 UDP association")
		}
	}
	q := request{origin: r.socketOrigin(s.conn.remote, s.conn.local), network: "udp", inbound: in.Tag, source: s.conn.remote.String(), address: address}
	return flows.send(strconv.FormatUint(uint64(id), 10)+"/"+address, q, payload, func(data []byte, source string) error { return s.sendPacket(id, source, data, stream) })
}
func (s *quicProxySession) decodePacket(b []byte) (id uint32, pid uint16, index, count byte, address string, payload []byte, err error) {
	if s.kind == "hysteria" {
		return decodeHY1Packet(b)
	}
	if s.kind == "tuic" && s.version == 4 {
		return decodeTUIC4Packet(b)
	}
	if s.kind == "hysteria2" {
		if len(b) < 9 {
			err = io.ErrUnexpectedEOF
			return
		}
		id = binary.BigEndian.Uint32(b)
		pid = quicU16(b[4:])
		index, count = b[6], b[7]
		q := quicReader(b[8:])
		address, err = q.text(512)
		payload = q
		return
	}
	if len(b) < 2 || b[0] != 5 {
		err = errors.New("invalid TUIC UDP version")
		return
	}
	if b[1] == 4 {
		return
	}
	if b[1] != 2 || len(b) < 11 {
		err = errors.New("invalid TUIC UDP command")
		return
	}
	id = uint32(quicU16(b[2:]))
	pid = quicU16(b[4:])
	count, index = b[6], b[7]
	size := int(quicU16(b[8:]))
	reader := &sliceReader{data: b[10:]}
	address, err = readTUICAddress(reader)
	payload = reader.data
	if len(payload) != size {
		err = errors.New("invalid TUIC packet length")
	}
	return
}

type sliceReader struct{ data []byte }

func (r *sliceReader) Read(b []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(b, r.data)
	r.data = r.data[n:]
	return n, nil
}
func (s *quicProxySession) sendPacket(id uint32, address string, payload []byte, stream bool) error {
	if len(payload) > 65507 {
		return errors.New("UDP payload too large")
	}
	if s.kind == "tuic" && s.version == 4 {
		return s.sendTUIC4Packet(id, address, payload, stream)
	}
	chunk := min(900, 1000-len(address)-16)
	if stream {
		chunk = 65507
	}
	count := max(1, (len(payload)+chunk-1)/chunk)
	pid := uint16(s.packetID.Add(1))
	for i := 0; i < count; i++ {
		start, end := i*chunk, min(len(payload), (i+1)*chunk)
		var b []byte
		if s.kind == "hysteria" {
			b = encodeHY1Packet(id, pid, byte(i), byte(count), address, payload[start:end])
			if b == nil {
				return errors.New("invalid HY1 address")
			}
		} else if s.kind == "hysteria2" {
			b = binary.BigEndian.AppendUint32(make([]byte, 0, 8+8+len(address)+end-start), id)
			b = binary.BigEndian.AppendUint16(b, pid)
			b = append(b, byte(i), byte(count))
			b = quicString(b, address)
		} else {
			b = append(make([]byte, 0, 10+len(address)+4+end-start), 5, 2)
			b = binary.BigEndian.AppendUint16(b, uint16(id))
			b = binary.BigEndian.AppendUint16(b, pid)
			b = append(b, byte(count), byte(i))
			b = binary.BigEndian.AppendUint16(b, uint16(end-start))
			if i == 0 {
				a, e := tuicAddress(address)
				if e != nil {
					return e
				}
				b = append(b, a...)
			} else {
				b = append(b, 255)
			}
		}
		if s.kind != "hysteria" {
			b = append(b, payload[start:end]...)
		}
		if stream {
			s, e := s.conn.OpenStream(s.conn.ctx, true)
			if e != nil {
				return e
			}
			if e = writeAll(s, b); e != nil {
				s.Close()
				return e
			}
			e = s.finishUni()
			s.Close()
			if e != nil {
				return e
			}
		} else {
			// b is freshly built for this datagram, so the connection may own it.
			if e := s.conn.sendDatagramOwned(s.conn.ctx, b); e != nil {
				return e
			}
		}
	}
	return nil
}
func (s *quicProxySession) closeAssociation(id uint32) {
	if s.flows != nil {
		s.flows.closePrefix(strconv.FormatUint(uint64(id), 10) + "/")
	}
	s.mu.Lock()
	p := s.packets[id]
	s.mu.Unlock()
	if p != nil {
		p.Close()
	}
}

type quicProxyDatagram struct {
	address string
	payload []byte
}

type quicProxyPacket struct {
	session                     *quicProxySession
	id                          uint32
	address                     string
	incoming                    chan quicProxyDatagram
	closed, wake                chan struct{}
	once                        sync.Once
	mu                          sync.Mutex
	readDeadline, writeDeadline time.Time
	err                         error
}

func (p *quicProxyPacket) Read(b []byte) (int, error) {
	n, _, err := p.readPacket(b)
	return n, err
}
func (p *quicProxyPacket) readPacket(b []byte) (int, string, error) {
	if p.err != nil {
		return 0, "", p.err
	}
	for {
		p.mu.Lock()
		d := p.readDeadline
		p.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !d.IsZero() {
			timer = time.NewTimer(max(0, time.Until(d)))
			timeout = timer.C
		}
		var data quicProxyDatagram
		var e error
		select {
		case data = <-p.incoming:
		case <-p.closed:
			e = net.ErrClosed
		case <-p.session.conn.done:
			e = p.session.conn.err()
		case <-timeout:
			e = fmt.Errorf("UDP read: %w", context.DeadlineExceeded)
		case <-p.wake:
		}
		if timer != nil {
			timer.Stop()
		}
		if e != nil {
			return 0, "", e
		}
		if data.payload != nil {
			if len(data.payload) > len(b) {
				return 0, "", io.ErrShortBuffer
			}
			return copy(b, data.payload), data.address, nil
		}
	}
}
func (p *quicProxyPacket) Write(b []byte) (int, error) {
	return p.writePacket(b, p.address)
}
func (p *quicProxyPacket) writePacket(b []byte, address string) (int, error) {
	if p.err != nil {
		return 0, p.err
	}
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	p.mu.Lock()
	d := p.writeDeadline
	p.mu.Unlock()
	if !d.IsZero() && time.Now().After(d) {
		return 0, context.DeadlineExceeded
	}
	if e := p.session.sendPacket(p.id, address, b, p.session.streamUDP); e != nil {
		return 0, e
	}
	return len(b), nil
}
func (p *quicProxyPacket) Close() error {
	p.once.Do(func() {
		close(p.closed)
		p.session.mu.Lock()
		if p.session.packets[p.id] == p {
			delete(p.session.packets, p.id)
		}
		p.session.mu.Unlock()
		if p.err == nil && p.session.kind == "tuic" && p.session.flows == nil {
			p.session.dissociate(p.id)
		}
	})
	return nil
}
func (p *quicProxyPacket) LocalAddr() net.Addr  { return p.session.conn.local }
func (p *quicProxyPacket) RemoteAddr() net.Addr { return p.session.conn.remote }
func (p *quicProxyPacket) SetDeadline(t time.Time) error {
	p.SetWriteDeadline(t)
	return p.SetReadDeadline(t)
}
func (p *quicProxyPacket) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.readDeadline = t
	p.mu.Unlock()
	signalQUIC(p.wake)
	return nil
}
func (p *quicProxyPacket) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	p.writeDeadline = t
	p.mu.Unlock()
	return nil
}

func quicPadding() []byte { b := make([]byte, 32); rand.Read(b); return b }
