package native

import (
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
)

const wechatHeaderSize = 13

var wechatHeader = [wechatHeaderSize]byte{0xa1, 0x08, 0, 0, 0, 0, 0, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30}

func writeWechat(payload []byte, sequence uint32, send func([]byte) (int, error)) (int, error) {
	if len(payload) > 65507-wechatHeaderSize {
		return 0, io.ErrShortBuffer
	}
	owner := packetBuffers.Get()
	buffer := owner.([]byte)
	defer packetBuffers.Put(owner)
	packet := buffer[:wechatHeaderSize+len(payload)]
	copy(packet, wechatHeader[:])
	binary.BigEndian.PutUint32(packet[2:6], sequence)
	copy(packet[wechatHeaderSize:], payload)
	n, err := send(packet)
	if err == nil && n != len(packet) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

type wechatConn struct {
	net.Conn
	sequence atomic.Uint32
}

func newWechatConn(raw net.Conn) *wechatConn {
	c := &wechatConn{Conn: raw}
	c.sequence.Store(uint32(geckoRandom(0, 65535)))
	return c
}

func (c *wechatConn) Write(b []byte) (int, error) {
	return writeWechat(b, c.sequence.Add(1)-1, c.Conn.Write)
}

func (c *wechatConn) Read(b []byte) (int, error) {
	owner := packetBuffers.Get()
	buffer := owner.([]byte)
	defer packetBuffers.Put(owner)
	for {
		n, err := c.Conn.Read(buffer)
		if err != nil {
			return 0, err
		}
		if n > wechatHeaderSize {
			return copy(b, buffer[wechatHeaderSize:n]), nil
		}
	}
}

type wechatPacket struct {
	net.PacketConn
	sequence atomic.Uint32
}

func newWechatPacket(raw net.PacketConn) *wechatPacket {
	c := &wechatPacket{PacketConn: raw}
	c.sequence.Store(uint32(geckoRandom(0, 65535)))
	return c
}

func (c *wechatPacket) WriteTo(b []byte, remote net.Addr) (int, error) {
	return writeWechat(b, c.sequence.Add(1)-1, func(packet []byte) (int, error) { return c.PacketConn.WriteTo(packet, remote) })
}

func (c *wechatPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	owner := packetBuffers.Get()
	buffer := owner.([]byte)
	defer packetBuffers.Put(owner)
	for {
		n, remote, err := c.PacketConn.ReadFrom(buffer)
		if err != nil {
			return 0, remote, err
		}
		// The camouflage header is not an authentication boundary. Peers ignore
		// its content; the enclosed QUIC AEAD and packet numbers authenticate the payload.
		if n > wechatHeaderSize {
			return copy(b, buffer[wechatHeaderSize:n]), remote, nil
		}
	}
}
