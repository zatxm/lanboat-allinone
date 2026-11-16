package native

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// BrookOptions belongs to the Brook extension; the other protocols keep their
// sing-box field names. Both directions default to the published "brook" info.
type BrookOptions struct {
	WithoutBrookProtocol bool   `json:"without_brook_protocol,omitempty"`
	ClientHKDFInfo       string `json:"client_hkdf_info,omitempty"`
	ServerHKDFInfo       string `json:"server_hkdf_info,omitempty"`
	UDPOverTCP           bool   `json:"udp_over_tcp,omitempty"`
	UDPOverStream        bool   `json:"udp_over_stream,omitempty"`
	Tengo                string `json:"tengo,omitempty"`
	TengoFile            string `json:"tengo_file,omitempty"`
	tengoProgram         *TengoProgram
}

func (o BrookOptions) validate(kind, password string, transport Transport, tls bool) error {
	if kind != "brook" {
		if o.WithoutBrookProtocol || o.ClientHKDFInfo != "" || o.ServerHKDFInfo != "" || o.UDPOverStream || o.UDPOverTCP && kind != "naive" || o.Tengo != "" || o.TengoFile != "" {
			return errors.New("Brook options require brook type")
		}
		return nil
	}
	if len(password) == 0 || len(password) > 4096 || len(o.ClientHKDFInfo) > 1024 || len(o.ServerHKDFInfo) > 1024 {
		return errors.New("Brook requires a password of 1-4096 bytes and HKDF info of at most 1024 bytes")
	}
	if transport.Type != "" && transport.Type != "ws" && transport.Type != "quic" || tls && transport.Type == "" {
		return errors.New("Brook transport must be TCP, WebSocket, TLS WebSocket or QUIC")
	}
	if o.WithoutBrookProtocol {
		if transport.Type != "ws" && transport.Type != "quic" {
			return errors.New("Brook simple protocol requires WebSocket or QUIC")
		}
		if o.ClientHKDFInfo != "" || o.ServerHKDFInfo != "" {
			return errors.New("Brook simple protocol does not use HKDF options")
		}
	}
	if o.UDPOverStream && transport.Type != "quic" || o.UDPOverTCP && transport.Type == "quic" {
		return errors.New("Brook QUIC uses udp_over_stream; udp_over_tcp is for TCP")
	}
	return nil
}

func brookInfo(info string) string {
	if info == "" {
		return "brook"
	}
	return info
}

func brookAEAD(password, info string, nonce []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, []byte(password), nonce, brookInfo(info), 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func brookClaim(replay *replayWindow, password, info string, nonce []byte) error {
	// A common namespace for both directions also rejects reflected initial
	// nonces when the client and server use the same HKDF info.
	scope := sha256.Sum256([]byte(password + "\x00" + brookInfo(info)))
	return replay.claim("brook\x00" + string(scope[:]) + string(nonce))
}

type brookNonce struct {
	value, current [12]byte
	spent          bool
}

func (n *brookNonce) take() ([]byte, error) {
	if n.spent {
		return nil, errors.New("Brook nonce exhausted")
	}
	n.current = n.value
	counter := binary.LittleEndian.Uint64(n.value[:8])
	n.spent = counter == ^uint64(0)
	binary.LittleEndian.PutUint64(n.value[:8], counter+1)
	return n.current[:], nil
}

const brookTCPChunk = 2048 - 18 - 16
const brookUDPChunk = 65507 - 18 - 16

type brookConn struct {
	net.Conn
	password, readInfo, writeInfo string
	replay                        *replayWindow
	packets                       bool
	readMu, writeMu               sync.Mutex
	reader, writer                cipher.AEAD
	readNonce, writeNonce         brookNonce
	readHeader                    [18]byte
	writeLength                   [2]byte
	readBuffer, writeBuffer       []byte
	pending                       []byte
	readErr, writeErr             error
}

func newBrookConn(raw net.Conn, password string, o BrookOptions, client bool, replay *replayWindow) *brookConn {
	readInfo, writeInfo := o.ClientHKDFInfo, o.ServerHKDFInfo
	if client {
		readInfo, writeInfo = writeInfo, readInfo
	}
	return &brookConn{Conn: raw, password: password, readInfo: readInfo, writeInfo: writeInfo, replay: replay}
}

func (c *brookConn) readFrame() ([]byte, error) {
	if c.readErr != nil {
		return nil, c.readErr
	}
	b, err := c.readRecord()
	if err != nil {
		c.readErr = err
	}
	return b, err
}

func (c *brookConn) readRecord() ([]byte, error) {
	var firstNonce []byte
	if c.reader == nil {
		if _, err := io.ReadFull(c.Conn, c.readNonce.value[:]); err != nil {
			return nil, err
		}
		var err error
		c.reader, err = brookAEAD(c.password, c.readInfo, c.readNonce.value[:])
		if err != nil {
			return nil, err
		}
		firstNonce = append([]byte(nil), c.readNonce.value[:]...)
	}
	if _, err := io.ReadFull(c.Conn, c.readHeader[:]); err != nil {
		return nil, err
	}
	nonce, err := c.readNonce.take()
	if err != nil {
		return nil, err
	}
	length, err := c.reader.Open(c.readHeader[:0], nonce, c.readHeader[:], nil)
	if err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(length))
	limit := brookTCPChunk
	if c.packets {
		limit = brookUDPChunk
	}
	if size > limit {
		return nil, errors.New("Brook record exceeds limit")
	}
	if cap(c.readBuffer) < size+16 {
		c.readBuffer = make([]byte, size+16)
	}
	frame := c.readBuffer[:size+16]
	if _, err := io.ReadFull(c.Conn, frame); err != nil {
		return nil, err
	}
	nonce, err = c.readNonce.take()
	if err != nil {
		return nil, err
	}
	plain, err := c.reader.Open(frame[:0], nonce, frame, nil)
	if err == nil && firstNonce != nil {
		err = brookClaim(c.replay, c.password, c.readInfo, firstNonce)
	}
	return plain, err
}

func (c *brookConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(b) == 0 && !c.packets {
		return 0, nil
	}
	for empty := 0; len(c.pending) == 0; empty++ {
		if empty == 16 {
			c.readErr = errors.New("too many empty Brook records")
			return 0, c.readErr
		}
		frame, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		if c.packets {
			if len(frame) > len(b) {
				return 0, io.ErrShortBuffer
			}
			return copy(b, frame), nil
		}
		c.pending = frame
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *brookConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.packets && len(b) > brookUDPChunk {
		return 0, errors.New("Brook UDP over TCP payload exceeds 65473 bytes")
	}
	if len(b) == 0 && !c.packets {
		return 0, nil
	}
	written := 0
	for {
		size := min(len(b), brookTCPChunk)
		if c.packets {
			size = len(b)
		}
		if err := c.writeRecord(b[:size]); err != nil {
			c.writeErr = err
			return written, err
		}
		written += size
		b = b[size:]
		if len(b) == 0 {
			return written, nil
		}
	}
}

func (c *brookConn) initWrite() error {
	if c.writer != nil {
		return nil
	}
	if _, err := rand.Read(c.writeNonce.value[:]); err != nil {
		return err
	}
	if err := brookClaim(c.replay, c.password, c.writeInfo, c.writeNonce.value[:]); err != nil {
		return err
	}
	var err error
	c.writer, err = brookAEAD(c.password, c.writeInfo, c.writeNonce.value[:])
	if err != nil {
		return err
	}
	return writeAll(c.Conn, c.writeNonce.value[:])
}

func (c *brookConn) writeRecord(b []byte) error {
	if err := c.initWrite(); err != nil {
		return err
	}
	if cap(c.writeBuffer) < 34+len(b) {
		c.writeBuffer = make([]byte, 0, 34+max(len(b), brookTCPChunk))
	}
	frame := c.writeBuffer[:0]
	binary.BigEndian.PutUint16(c.writeLength[:], uint16(len(b)))
	nonce, err := c.writeNonce.take()
	if err != nil {
		return err
	}
	frame = c.writer.Seal(frame, nonce, c.writeLength[:], nil)
	nonce, err = c.writeNonce.take()
	if err != nil {
		return err
	}
	frame = c.writer.Seal(frame, nonce, b, nil)
	return writeAll(c.Conn, frame)
}

func (c *brookConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func brookClient(raw net.Conn, o Outbound, address string, udp bool, replay *replayWindow) (net.Conn, error) {
	target, err := encodeAddress(address)
	if err != nil {
		return nil, err
	}
	if o.WithoutBrookProtocol {
		return brookSimpleClient(raw, o, target, udp)
	}
	stamp := uint32(time.Now().Unix())
	stamp += stamp & 1 // TCP uses even timestamps, UDP over TCP uses odd timestamps.
	if udp {
		stamp++
	}
	c := newBrookConn(raw, o.Password, o.BrookOptions, true, replay)
	if _, err := c.Write(append(binary.BigEndian.AppendUint32(nil, stamp), target...)); err != nil {
		return nil, err
	}
	c.packets = udp
	return c, nil
}

func brookTimestamp(b []byte) error {
	if len(b) < 4 {
		return errors.New("short Brook timestamp")
	}
	delta := time.Now().Unix() - int64(binary.BigEndian.Uint32(b))
	if delta < -120 || delta > 120 {
		return errors.New("Brook timestamp outside 120-second window")
	}
	return nil
}

func (r *Runtime) serveBrook(in Inbound, raw net.Conn, q request) error {
	if in.WithoutBrookProtocol {
		return r.serveBrookSimple(in, raw, q)
	}
	c := newBrookConn(raw, in.Password, in.BrookOptions, false, &r.replay)
	header, err := c.readFrame()
	if err != nil {
		return err
	}
	if err := brookTimestamp(header); err != nil {
		return err
	}
	reader := bytes.NewReader(header[4:])
	q.address, err = readAddress(reader)
	if err != nil || reader.Len() != 0 {
		return errors.New("invalid Brook destination header")
	}
	if _, err := encodeAddress(q.address); err != nil {
		return err
	}
	c.packets = header[3]&1 == 1
	if c.packets {
		q.network = "udp"
	}
	remote, err := r.routeDial(r.ctx, q)
	if err != nil {
		return err
	}
	// Official clients wait for the server nonce before forwarding application
	// bytes. Send it now, including for targets that wait for a client greeting.
	if err := c.initWrite(); err != nil {
		remote.Close()
		return err
	}
	if c.packets {
		defer remote.Close()
		_ = c.SetDeadline(time.Time{})
		return r.relayDatagrams(c, remote, r.udpTimeoutFor(in.Tag, udpTimeout))
	}
	r.relay(c, remote)
	return nil
}

func brookSeal(password, info string, plain []byte, replay *replayWindow) ([]byte, error) {
	if len(plain)+28 > 65507 {
		return nil, errors.New("Brook UDP packet exceeds 65507 bytes")
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	if err := brookClaim(replay, password, info, nonce[:]); err != nil {
		return nil, err
	}
	aead, err := brookAEAD(password, info, nonce[:])
	if err != nil {
		return nil, err
	}
	return aead.Seal(append(make([]byte, 0, len(plain)+28), nonce[:]...), nonce[:], plain, nil), nil
}

func brookOpen(password, info string, packet []byte, replay *replayWindow) ([]byte, error) {
	if len(packet) < 28 || len(packet) > 65507 {
		return nil, errors.New("invalid Brook UDP packet length")
	}
	aead, err := brookAEAD(password, info, packet[:12])
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, packet[:12], packet[12:], nil)
	if err == nil {
		err = brookClaim(replay, password, info, packet[:12])
	}
	return plain, err
}

type brookPacketConn struct {
	net.Conn
	password string
	options  BrookOptions
	address  []byte
	replay   *replayWindow
}

func (c *brookPacketConn) Read(b []byte) (int, error) {
	packet := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(packet)
	for {
		n, err := c.Conn.Read(packet)
		if err != nil {
			return 0, err
		}
		plain := packet[:n]
		if !c.options.WithoutBrookProtocol {
			plain, err = brookOpen(c.password, c.options.ServerHKDFInfo, plain, c.replay)
		}
		if err != nil {
			continue
		}
		reader := bytes.NewReader(plain)
		address, err := readAddress(reader)
		if err != nil {
			continue
		}
		_, err = encodeAddress(address)
		if err != nil {
			continue
		}
		if reader.Len() > len(b) {
			return 0, io.ErrShortBuffer
		}
		return copy(b, plain[len(plain)-reader.Len():]), nil
	}
}

func (c *brookPacketConn) Write(b []byte) (int, error) {
	overhead := 32
	if c.options.WithoutBrookProtocol {
		overhead = 36
	}
	if len(b)+len(c.address)+overhead > 65507 {
		return 0, errors.New("Brook UDP packet exceeds 65507 bytes")
	}
	plain := binary.BigEndian.AppendUint32(nil, uint32(time.Now().Unix()))
	plain = append(plain, c.address...)
	plain = append(plain, b...)
	var packet []byte
	var err error
	if c.options.WithoutBrookProtocol {
		passwordHash := sha256.Sum256([]byte(c.password))
		packet = append(append(make([]byte, 0, 32+len(plain)), passwordHash[:]...), plain...)
	} else {
		packet, err = brookSeal(c.password, c.options.ClientHKDFInfo, plain, c.replay)
		if err != nil {
			return 0, err
		}
	}
	if _, err := c.Conn.Write(packet); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (r *Runtime) brookPacketClient(ctx context.Context, o Outbound, address string) (net.Conn, error) {
	encoded, err := encodeAddress(address)
	if err != nil {
		return nil, err
	}
	c, err := r.endpoint(ctx, o, "udp")
	if err != nil {
		return nil, err
	}
	return r.own(&brookPacketConn{Conn: c, password: o.Password, options: o.BrookOptions, address: encoded, replay: &r.replay})
}

func (r *Runtime) serveBrookPackets(in Inbound, packets net.PacketConn) {
	flows := newUDPFlows(r)
	defer flows.Close()
	buffer := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(buffer)
	for {
		n, from, err := packets.ReadFrom(buffer)
		if err != nil {
			return
		}
		r.brookDatagram(in, flows, buffer[:n], from, packets.LocalAddr(), func(packet []byte) error {
			_, err := packets.WriteTo(packet, from)
			return err
		})
	}
}

func (r *Runtime) brookDatagram(in Inbound, flows *udpFlows, packet []byte, peer, local net.Addr, reply func([]byte) error) {
	var plain []byte
	var err error
	if in.WithoutBrookProtocol {
		plain, err = brookOpenSimpleDatagram(in.Password, packet)
	} else {
		plain, err = brookOpen(in.Password, in.ClientHKDFInfo, packet, &r.replay)
		if err == nil {
			err = brookTimestamp(plain)
		}
	}
	if err != nil {
		return
	}
	reader := bytes.NewReader(plain[4:])
	address, err := readAddress(reader)
	if err != nil {
		return
	}
	if _, err := encodeAddress(address); err != nil {
		return
	}
	source := peer.String()
	q := request{origin: r.socketOrigin(peer, local), network: "udp", address: address, inbound: in.Tag, source: source}
	_ = flows.send(strconv.Itoa(len(source))+":"+source+address, q, plain[len(plain)-reader.Len():], func(b []byte, address string) error {
		encoded, err := encodeAddress(address)
		if err != nil {
			return err
		}
		packet := append(encoded, b...)
		if !in.WithoutBrookProtocol {
			packet, err = brookSeal(in.Password, in.ServerHKDFInfo, packet, &r.replay)
		}
		if err != nil {
			return err
		}
		return reply(packet)
	})
}
