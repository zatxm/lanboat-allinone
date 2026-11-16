package native

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type ss2022Packet struct {
	key          *ssKey
	id, clientID [8]byte
	packetID     uint64
	address      string
	payload      []byte
	cipher       cipher.AEAD
}

func ss2022PacketBody(key *ssKey, id [8]byte) (cipher.AEAD, error) {
	if key.method == "2022-blake3-chacha20-poly1305" {
		return key.udpAEAD, nil
	}
	return key.ss2022AEAD(id[:])
}

func openSS2022Packet(key *ssKey, b []byte, server bool, cached func(*ssKey, [8]byte) cipher.AEAD) (ss2022Packet, error) {
	var m ss2022Packet
	if len(b) > 65507 {
		return m, errors.New("oversize Shadowsocks2022 UDP packet")
	}
	var plain []byte
	var header [16]byte
	if key.method == "2022-blake3-chacha20-poly1305" {
		if len(b) < 24+16+16+11+7 {
			return m, io.ErrUnexpectedEOF
		}
		var err error
		plain, err = key.udpAEAD.Open(nil, b[:24], b[24:], nil)
		if err != nil {
			return m, err
		}
		copy(header[:], plain[:16])
		plain = plain[16:]
		m.cipher = key.udpAEAD
	} else {
		if len(b) < 16+16+11+7 {
			return m, io.ErrUnexpectedEOF
		}
		key.udpBlock.Decrypt(header[:], b[:16])
		pos := 16
		if server && key.users != nil {
			if len(b) < 16+16+16+11+7 {
				return m, io.ErrUnexpectedEOF
			}
			var hash [16]byte
			key.udpBlock.Decrypt(hash[:], b[pos:pos+16])
			for i := range hash {
				hash[i] ^= header[i]
			}
			key = key.users[hash]
			if key == nil {
				return m, errors.New("unknown Shadowsocks2022 UDP user")
			}
			pos += 16
		}
		copy(m.id[:], header[:8])
		if cached != nil {
			m.cipher = cached(key, m.id)
		}
		var err error
		if m.cipher == nil {
			m.cipher, err = ss2022PacketBody(key, m.id)
			if err != nil {
				return m, err
			}
		}
		plain, err = m.cipher.Open(nil, header[4:], b[pos:], nil)
		if err != nil {
			return m, err
		}
	}
	m.key = key
	copy(m.id[:], header[:8])
	m.packetID = binary.BigEndian.Uint64(header[8:])
	typ := byte(1)
	if server {
		typ = 0
	}
	if err := ss2022Stamp(plain, typ); err != nil {
		return m, err
	}
	pos := 9
	if !server {
		if len(plain) < pos+8 {
			return m, io.ErrUnexpectedEOF
		}
		copy(m.clientID[:], plain[pos:pos+8])
		pos += 8
	}
	if len(plain) < pos+2 {
		return m, io.ErrUnexpectedEOF
	}
	padding := int(binary.BigEndian.Uint16(plain[pos:]))
	pos += 2
	if padding > len(plain)-pos {
		return m, errors.New("invalid Shadowsocks2022 UDP padding")
	}
	pos += padding
	reader := bytes.NewReader(plain[pos:])
	var err error
	m.address, err = readAddress(reader)
	if err != nil {
		return m, err
	}
	if _, err := encodeAddress(m.address); err != nil {
		return m, err
	}
	m.payload = plain[len(plain)-reader.Len():]
	return m, nil
}

type ss2022Sender struct {
	key          *ssKey
	id, clientID [8]byte
	next         uint64
	spent        bool
	cipher       cipher.AEAD
}

func newSS2022Sender(key *ssKey, clientID [8]byte) (*ss2022Sender, error) {
	s := &ss2022Sender{key: key, clientID: clientID}
	for {
		if _, err := rand.Read(s.id[:]); err != nil {
			return nil, err
		}
		if s.id != clientID {
			break
		}
	}
	var err error
	s.cipher, err = ss2022PacketBody(key, s.id)
	return s, err
}

func (s *ss2022Sender) seal(address string, data []byte, server bool) ([]byte, error) {
	if s.spent {
		return nil, errors.New("Shadowsocks2022 UDP packet counter exhausted")
	}
	target, err := encodeAddress(address)
	if err != nil {
		return nil, err
	}
	overhead := 43
	if server {
		overhead += 8
	} else {
		overhead += 16 * len(s.key.identities)
	}
	chacha := s.key.method == "2022-blake3-chacha20-poly1305"
	if chacha {
		overhead += 24
	}
	if len(data)+len(target)+overhead > 65507 {
		return nil, errors.New("Shadowsocks2022 UDP packet exceeds65507 bytes")
	}
	var separate [16]byte
	copy(separate[:8], s.id[:])
	binary.BigEndian.PutUint64(separate[8:], s.next)
	s.spent = s.next == ^uint64(0)
	s.next++
	typ := byte(0)
	if server {
		typ = 1
	}
	plain := make([]byte, 0, len(data)+len(target)+35)
	if chacha {
		plain = append(plain, separate[:]...)
	}
	plain = append(plain, ss2022Header(typ)...)
	if server {
		plain = append(plain, s.clientID[:]...)
	}
	plain = append(plain, 0, 0) // Optional UDP padding is empty.
	plain = append(plain, target...)
	plain = append(plain, data...)
	if chacha {
		var nonce [24]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		return s.cipher.Seal(append(make([]byte, 0, 24+len(plain)+16), nonce[:]...), nonce[:], plain, nil), nil
	}
	packet := make([]byte, 16, len(plain)+32+16*len(s.key.identities))
	block := s.key.udpBlock
	if !server && len(s.key.identities) > 0 {
		block = s.key.identityBlocks[0]
	}
	block.Encrypt(packet, separate[:])
	if !server {
		for i, identity := range s.key.identityBlocks {
			next := s.key.master
			if i+1 < len(s.key.identities) {
				next = s.key.identities[i+1]
			}
			hash := blake3Sum(next)
			var b [16]byte
			for j := range b {
				b[j] = hash[j] ^ separate[j]
			}
			identity.Encrypt(b[:], b[:])
			packet = append(packet, b[:]...)
		}
	}
	return s.cipher.Seal(packet, separate[4:], plain, nil), nil
}

type ss2022Receiver struct {
	window packetWindow
	cipher cipher.AEAD
	seenAt time.Time
}

type ss2022PacketConn struct {
	net.Conn
	key             *ssKey
	address         string
	sender          *ss2022Sender
	readMu, writeMu sync.Mutex
	receivers       map[[8]byte]*ss2022Receiver
}

func (c *ss2022PacketConn) Write(b []byte) (int, error) {
	return c.writePacket(b, c.address)
}
func (c *ss2022PacketConn) writePacket(b []byte, address string) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	packet, err := c.sender.seal(address, b, false)
	if err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write(packet); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *ss2022PacketConn) Read(b []byte) (int, error) {
	n, _, err := c.readPacket(b)
	return n, err
}
func (c *ss2022PacketConn) readPacket(b []byte) (int, string, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	buffer := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(buffer)
	for {
		n, err := c.Conn.Read(buffer)
		if err != nil {
			return 0, "", err
		}
		m, err := openSS2022Packet(c.key, buffer[:n], false, func(_ *ssKey, id [8]byte) cipher.AEAD {
			if r := c.receivers[id]; r != nil {
				return r.cipher
			}
			return nil
		})
		if err != nil || m.clientID != c.sender.id || m.id == c.sender.id {
			continue
		}
		now := time.Now()
		r := c.receivers[m.id]
		if r == nil {
			for id, old := range c.receivers {
				if now.Sub(old.seenAt) > time.Minute {
					delete(c.receivers, id)
				}
			}
			if len(c.receivers) >= 64 {
				continue
			}
			r = &ss2022Receiver{cipher: m.cipher}
			c.receivers[m.id] = r
		}
		if !r.window.accept(m.packetID) {
			continue
		}
		r.seenAt = now
		if len(m.payload) > len(b) {
			return 0, "", io.ErrShortBuffer
		}
		return copy(b, m.payload), m.address, nil
	}
}

func (r *Runtime) ss2022PacketClient(ctx context.Context, o Outbound, address string) (net.Conn, error) {
	key := r.keys["out:"+o.Tag]
	sender, err := newSS2022Sender(key, [8]byte{})
	if err != nil {
		return nil, err
	}
	raw, err := r.endpoint(ctx, o, "udp")
	if err != nil {
		return nil, err
	}
	return r.own(&ss2022PacketConn{Conn: raw, key: key, address: address, sender: sender, receivers: map[[8]byte]*ss2022Receiver{}})
}

type ss2022ServerSession struct {
	mu       sync.Mutex
	receiver ss2022Receiver
	sender   *ss2022Sender
	peer     net.Addr
	direct   map[string]*ss2022Direct
}

type ss2022SessionID struct {
	key *ssKey
	id  [8]byte
}

func (r *Runtime) serveSS2022Packets(in Inbound, packets net.PacketConn) {
	if len(in.Destinations) > 0 {
		r.serveSS2022RelayPackets(in, packets)
		return
	}
	key := r.keys["in:"+in.Tag]
	flows := newUDPFlows(r)
	flows.timeout = time.Minute
	sessions := make(map[ss2022SessionID]*ss2022ServerSession)
	var directWorkers sync.WaitGroup
	directCount := 0
	defer func() {
		for _, s := range sessions {
			s.mu.Lock()
			for _, d := range s.direct {
				d.conn.Close()
			}
			s.mu.Unlock()
		}
		directWorkers.Wait()
		flows.Close()
	}()
	buffer := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(buffer)
	for {
		n, peer, err := packets.ReadFrom(buffer)
		if err != nil {
			return
		}
		m, err := openSS2022Packet(key, buffer[:n], true, func(k *ssKey, id [8]byte) cipher.AEAD {
			if s := sessions[ss2022SessionID{k, id}]; s != nil {
				return s.receiver.cipher
			}
			return nil
		})
		if err != nil {
			continue
		}
		id := ss2022SessionID{m.key, m.id}
		s := sessions[id]
		if s == nil {
			now := time.Now()
			for oldID, old := range sessions {
				old.mu.Lock()
				expired := now.Sub(old.receiver.seenAt) > time.Minute
				old.mu.Unlock()
				if expired {
					delete(sessions, oldID)
					flows.closePrefix(string(oldID.key.master) + string(oldID.id[:]))
					old.mu.Lock()
					for _, d := range old.direct {
						d.conn.Close()
						directCount--
					}
					old.mu.Unlock()
				}
			}
			if len(sessions) >= 1024 {
				continue
			}
			sender, err := newSS2022Sender(m.key, m.id)
			if err != nil {
				continue
			}
			s = &ss2022ServerSession{sender: sender, receiver: ss2022Receiver{cipher: m.cipher}}
			sessions[id] = s
		}
		s.mu.Lock()
		if !s.receiver.window.accept(m.packetID) {
			s.mu.Unlock()
			continue
		}
		s.peer, s.receiver.seenAt = peer, time.Now()
		s.mu.Unlock()
		q := request{origin: r.socketOrigin(peer, packets.LocalAddr()), network: "udp", address: m.address, inbound: in.Tag, source: peer.String(), payload: m.payload, metadata: Metadata{AuthUser: m.key.userName}}
		target, tag, routeErr := r.routeTarget(r.ctx, q)
		if routeErr == nil && r.outbounds[tag].Type == "direct" {
			_ = r.ss2022SendDirect(s, r.outbounds[tag], target, m.payload, packets, &directWorkers, &directCount)
			continue
		}
		if routeErr != nil && !errors.Is(routeErr, errDNSRoute) {
			continue
		}
		flowKey := string(m.key.master) + string(m.id[:]) + m.address
		_ = flows.send(flowKey, q, m.payload, func(b []byte, address string) error {
			return s.reply(packets, address, b)
		})
	}
}

func (s *ss2022ServerSession) reply(packets net.PacketConn, address string, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	packet, err := s.sender.seal(address, b, true)
	if err != nil {
		return err
	}
	s.receiver.seenAt = time.Now()
	_, err = packets.WriteTo(packet, s.peer)
	return err
}
