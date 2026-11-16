package native

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
)

type ssrDatagrams struct {
	key          *ssKey
	protocol     string
	userKey, uid []byte
	restricted   bool
}

func newSSRDatagrams(key *ssKey, protocol, param string) (*ssrDatagrams, error) {
	userKey, uid, _, err := ssrUser(key, ssrProtocol(protocol), param)
	if err != nil {
		return nil, err
	}
	return &ssrDatagrams{key: key, protocol: ssrProtocol(protocol), userKey: userKey, uid: uid, restricted: param != ""}, nil
}
func (s *ssrDatagrams) seal(body []byte, server bool) ([]byte, error) {
	if strings.HasPrefix(s.protocol, "auth_aes128_") {
		h := md5.New
		if s.protocol == "auth_aes128_sha1" {
			h = sha1.New
		}
		key := s.key.master
		if !server {
			body = append(body, s.uid...)
			key = s.userKey
		}
		body = append(body, ssrMAC(h, key, body, 4)...)
	} else if strings.HasPrefix(s.protocol, "auth_chain_") {
		auth := ssrRandom(3)
		if server {
			auth = ssrRandom(7)
		}
		hash := ssrMAC(md5.New, s.key.master, auth, 16)
		r := xorShift{}
		r.init(hash, -1)
		padding := int(r.next() % 127)
		stream, _ := rc4.NewCipher(ssrPasswordKey(base64.StdEncoding.EncodeToString(s.userKey)+base64.StdEncoding.EncodeToString(hash), 16))
		stream.XORKeyStream(body, body)
		body = append(body, ssrRandom(padding)...)
		body = append(body, auth...)
		if !server {
			body = binary.LittleEndian.AppendUint32(body, binary.LittleEndian.Uint32(s.uid)^binary.LittleEndian.Uint32(hash))
		}
		body = append(body, ssrMAC(md5.New, s.userKey, body, 1)...)
	}
	_, ivSize, _ := ssStreamParameters(s.key.method)
	iv := ssrRandom(ivSize)
	if s.protocol == "verify_sha1" && !server {
		body[0] |= 16
		key := append(append([]byte{}, iv...), s.key.master...)
		body = append(body, ssrMAC(sha1.New, key, body, 10)...)
	}
	if len(iv)+len(body) > 65507 {
		return nil, errors.New("SSR UDP packet exceeds 65507 bytes")
	}
	stream, err := s.key.stream(iv, false)
	if err != nil {
		return nil, err
	}
	packet := append(iv, make([]byte, len(body))...)
	stream.XORKeyStream(packet[ivSize:], body)
	return packet, nil
}
func (s *ssrDatagrams) open(packet []byte, server bool) ([]byte, error) {
	body, err := s.key.openStreamPacket(packet)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(s.protocol, "auth_aes128_") {
		h := md5.New
		if s.protocol == "auth_aes128_sha1" {
			h = sha1.New
		}
		key, extra := s.key.master, 4
		if server {
			key = s.userKey
			extra = 8
		}
		if len(body) < extra || !hmac.Equal(body[len(body)-4:], ssrMAC(h, key, body[:len(body)-4], 4)) {
			return nil, errors.New("SSR UDP authentication rejected")
		}
		if server && s.restricted && !bytes.Equal(body[len(body)-8:len(body)-4], s.uid) {
			return nil, errors.New("SSR UDP user rejected")
		}
		body = body[:len(body)-extra]
	} else if strings.HasPrefix(s.protocol, "auth_chain_") {
		if len(body) < 8 || !hmac.Equal(body[len(body)-1:], ssrMAC(md5.New, s.userKey, body[:len(body)-1], 1)) {
			return nil, errors.New("SSR chain UDP authentication rejected")
		}
		auth := body[len(body)-8 : len(body)-1]
		if server {
			auth = auth[:3]
		}
		hash := ssrMAC(md5.New, s.key.master, auth, 16)
		if server && s.restricted && binary.LittleEndian.Uint32(body[len(body)-5:len(body)-1])^binary.LittleEndian.Uint32(hash) != binary.LittleEndian.Uint32(s.uid) {
			return nil, errors.New("SSR chain UDP user rejected")
		}
		r := xorShift{}
		r.init(hash, -1)
		padding := int(r.next() % 127)
		size := len(body) - 8 - padding
		if size < 0 {
			return nil, errors.New("invalid SSR chain UDP padding")
		}
		body = body[:size]
		stream, _ := rc4.NewCipher(ssrPasswordKey(base64.StdEncoding.EncodeToString(s.userKey)+base64.StdEncoding.EncodeToString(hash), 16))
		stream.XORKeyStream(body, body)
	} else if s.protocol == "verify_sha1" && server {
		_, ivSize, _ := ssStreamParameters(s.key.method)
		key := append(append([]byte{}, packet[:ivSize]...), s.key.master...)
		if len(body) < 11 || body[0]&16 == 0 || !hmac.Equal(body[len(body)-10:], ssrMAC(sha1.New, key, body[:len(body)-10], 10)) {
			return nil, errors.New("SSR OTA UDP authentication rejected")
		}
		body = body[:len(body)-10]
		body[0] &= 15
	}
	return body, nil
}

type ssrPacketConn struct {
	net.Conn
	codec    *ssrDatagrams
	address  []byte
	rmu, wmu sync.Mutex
}

func (c *ssrPacketConn) Write(b []byte) (int, error) {
	return c.writeEncoded(b, c.address)
}
func (c *ssrPacketConn) writePacket(b []byte, address string) (int, error) {
	encoded, err := encodeAddress(address)
	if err != nil {
		return 0, err
	}
	return c.writeEncoded(b, encoded)
}
func (c *ssrPacketConn) writeEncoded(b, address []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	packet, err := c.codec.seal(append(append([]byte{}, address...), b...), false)
	if err != nil {
		return 0, err
	}
	if err := writeAll(c.Conn, packet); err != nil {
		return 0, err
	}
	return len(b), nil
}
func (c *ssrPacketConn) Read(b []byte) (int, error) {
	n, _, err := c.readPacket(b)
	return n, err
}
func (c *ssrPacketConn) readPacket(b []byte) (int, string, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	buffer := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(buffer)
	n, err := c.Conn.Read(buffer)
	if err != nil {
		return 0, "", err
	}
	plain, err := c.codec.open(buffer[:n], false)
	if err != nil {
		return 0, "", err
	}
	reader := bytes.NewReader(plain)
	address, err := readAddress(reader)
	if err != nil {
		return 0, "", err
	}
	if reader.Len() > len(b) {
		return 0, "", io.ErrShortBuffer
	}
	count, err := io.ReadFull(reader, b[:reader.Len()])
	return count, address, err
}
func (r *Runtime) ssrPacketClient(ctx context.Context, o Outbound, address string) (net.Conn, error) {
	encoded, err := encodeAddress(address)
	if err != nil {
		return nil, err
	}
	codec, err := newSSRDatagrams(r.keys["out:"+o.Tag], o.Protocol, o.ProtocolParam)
	if err != nil {
		return nil, err
	}
	conn, err := r.endpoint(ctx, o, "udp")
	if err != nil {
		return nil, err
	}
	return r.own(&ssrPacketConn{Conn: conn, codec: codec, address: encoded})
}
