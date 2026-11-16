package native

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

func relayFeature(kind byte, data []byte) []byte {
	b := []byte{kind}
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func relayClient(c net.Conn, o Outbound, address string, udp bool) (net.Conn, error) {
	target, err := encodeAddress(address)
	if err != nil {
		return nil, err
	}
	features := relayFeature(2, target)
	if o.Username != "" || o.Password != "" {
		auth := append([]byte{byte(len(o.Username))}, o.Username...)
		auth = append(auth, byte(len(o.Password)))
		auth = append(auth, o.Password...)
		features = append(features, relayFeature(1, auth)...)
	}
	command := byte(1)
	if udp {
		command |= 128
	}
	header := []byte{1, command}
	header = binary.BigEndian.AppendUint16(header, uint16(len(features)))
	header = append(header, features...)
	if err := writeAll(c, header); err != nil {
		return nil, err
	}
	c = &relayResponseConn{Conn: c}
	if udp {
		return &streamPacketConn{Conn: c, address: address}, nil
	}
	return c, nil
}

type relayResponseConn struct {
	net.Conn
	once sync.Once
	err  error
}

func (c *relayResponseConn) Read(b []byte) (int, error) {
	c.once.Do(func() {
		_, c.err = readRelayResponse(c.Conn)
	})
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(b)
}
func (c *relayResponseConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

type relayRequest struct {
	username, password, address string
	udp                         bool
	command                     byte
}

func readRelayRequest(reader io.Reader) (relayRequest, error) {
	var q relayRequest
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return q, err
	}
	if header[0] != 1 || (header[1]&15 != 1 && header[1]&15 != 2) || header[1]&^byte(0x8f) != 0 {
		return q, errors.New("invalid Relay version, command or flags")
	}
	q.command = header[1] & 15
	q.udp = header[1]&128 != 0
	size := int(binary.BigEndian.Uint16(header[2:]))
	if size > 4096 {
		return q, errors.New("Relay request features exceed limit")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return q, err
	}
	seen := map[byte]bool{}
	for len(data) > 0 {
		if len(data) < 3 {
			return q, io.ErrUnexpectedEOF
		}
		kind, length := data[0], int(binary.BigEndian.Uint16(data[1:3]))
		data = data[3:]
		if length > len(data) || seen[kind] {
			return q, errors.New("invalid or duplicate Relay feature")
		}
		seen[kind] = true
		feature := data[:length]
		data = data[length:]
		switch kind {
		case 1:
			if len(feature) < 2 {
				return q, errors.New("invalid Relay credentials")
			}
			nameLen := int(feature[0])
			if nameLen+2 > len(feature) {
				return q, errors.New("invalid Relay username length")
			}
			passLen := int(feature[1+nameLen])
			if nameLen+2+passLen != len(feature) {
				return q, errors.New("invalid Relay password length")
			}
			q.username = string(feature[1 : 1+nameLen])
			q.password = string(feature[2+nameLen:])
		case 2:
			r := bytes.NewReader(feature)
			var err error
			q.address, err = readAddress(r)
			if err != nil || r.Len() != 0 {
				return q, errors.New("invalid Relay destination")
			}
		case 4:
			if len(feature) != 2 {
				return q, errors.New("invalid Relay network feature")
			}
			network := binary.BigEndian.Uint16(feature)
			if network > 1 {
				return q, errors.New("Relay network must be TCP or UDP")
			}
			q.udp = network == 1
		default:
			return q, errors.New("unsupported Relay feature")
		}
	}
	if q.command == 2 {
		if _, err := encodeRelayBind(q.address); err != nil {
			return q, err
		}
	} else if _, err := encodeAddress(q.address); err != nil {
		return q, err
	}
	return q, nil
}

func (r *Runtime) serveRelay(in Inbound, c net.Conn, q request) error {
	request, err := readRelayRequest(c)
	if err != nil {
		_ = writeAll(c, []byte{1, 1, 0, 0})
		return err
	}
	if !validUser(in.Users, request.username, request.password) {
		_ = writeAll(c, []byte{1, 2, 0, 0})
		return errors.New("Relay authentication rejected")
	}
	if request.command == 2 {
		_ = c.SetDeadline(time.Time{})
		return r.serveRelayBind(in, c, request)
	}
	q.address = request.address
	if request.udp {
		q.network = "udp"
	}
	remote, err := r.routeDial(r.ctx, q)
	if err != nil {
		_ = writeAll(c, []byte{1, 6, 0, 0})
		return err
	}
	if err := writeAll(c, []byte{1, 0, 0, 0}); err != nil {
		remote.Close()
		return err
	}
	if request.udp {
		defer remote.Close()
		_ = c.SetDeadline(time.Time{})
		return r.relayDatagrams(&streamPacketConn{Conn: c, address: q.address}, remote, r.udpTimeoutFor(in.Tag, udpTimeout))
	}
	r.relay(c, remote)
	return nil
}
