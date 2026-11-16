package native

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

func juicityPin(value string) ([]byte, error) {
	if b, e := hex.DecodeString(value); e == nil && len(b) == 32 {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, e := enc.DecodeString(value); e == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errors.New("Juicity certificate chain pin must be a SHA256 digest")
}
func configureJuicityPin(config *tls.Config, value string, options TLSOptions) {
	expected, _ := juicityPin(value)
	verify := config.VerifyConnection
	config.InsecureSkipVerify = true
	config.VerifyConnection = func(state tls.ConnectionState) error {
		var chain []byte
		for _, cert := range state.PeerCertificates {
			h := sha256.Sum256(cert.Raw)
			if chain == nil {
				chain = h[:]
			} else {
				v := sha256.Sum256(append(chain, h[:]...))
				chain = v[:]
			}
		}
		if subtle.ConstantTimeCompare(chain, expected) != 1 {
			return errors.New("Juicity certificate chain pin mismatch")
		}
		if verify != nil && len(options.CertificateSHA256)+len(options.CertificatePublicKeySHA256) != 0 {
			return verify(state)
		}
		return nil
	}
}
func juicityAddress(address string) ([]byte, error) {
	// Released Juicity peers use SOCKS address tags (1/3/4).
	return encodeAddress(address)
}
func readJuicityAddress(r io.Reader) (string, error) {
	return readAddress(r)
}
func (p *quicProxyClient) dialJuicity(ctx context.Context, s *quicProxySession, network, address string) (net.Conn, error) {
	stream, e := s.conn.OpenStream(ctx, false)
	if e != nil {
		return nil, e
	}
	if d, ok := ctx.Deadline(); ok {
		stream.SetWriteDeadline(d)
	}
	header, e := juicityAddress(address)
	command := byte(1)
	if network == "udp" {
		command = 3
	}
	if e == nil {
		e = writeAll(stream, append([]byte{command}, header...))
	}
	if e != nil {
		stream.Close()
		return nil, e
	}
	stream.SetWriteDeadline(time.Time{})
	if network == "udp" {
		return p.runtime.own(&juicityPacketConn{Conn: stream, address: address})
	}
	return p.runtime.own(stream)
}

type juicityPacketConn struct {
	net.Conn
	address         string
	readMu, writeMu sync.Mutex
}

func readJuicityPacket(r io.Reader) ([]byte, string, error) {
	a, e := readJuicityAddress(r)
	if e != nil {
		return nil, "", e
	}
	var size [2]byte
	if _, e = io.ReadFull(r, size[:]); e != nil {
		return nil, "", e
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n > 65507 {
		return nil, "", errors.New("oversized Juicity UDP")
	}
	b := make([]byte, n)
	_, e = io.ReadFull(r, b)
	return b, a, e
}
func writeJuicityPacket(w io.Writer, b []byte, address string) error {
	if len(b) > 65507 {
		return errors.New("oversized Juicity UDP")
	}
	a, e := juicityAddress(address)
	if e != nil {
		return e
	}
	header := binary.BigEndian.AppendUint16(a, uint16(len(b)))
	if e = writeAll(w, header); e != nil {
		return e
	}
	return writeAll(w, b)
}
func (c *juicityPacketConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	data, _, e := readJuicityPacket(c.Conn)
	if e != nil {
		return 0, e
	}
	return copy(b, data), nil
}
func (c *juicityPacketConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if e := writeJuicityPacket(c.Conn, b, c.address); e != nil {
		return 0, e
	}
	return len(b), nil
}
func (s *quicProxySession) serveJuicityStream(r *Runtime, in Inbound, stream *quicStream, auth chan struct{}, once *sync.Once) error {
	if stream.id&2 != 0 {
		var b [50]byte
		if _, e := io.ReadFull(stream, b[:]); e != nil {
			return e
		}
		if b[0] != 0 || b[1] != 0 {
			return errors.New("invalid Juicity authentication header")
		}
		valid := 0
		for _, u := range in.Users {
			id, _ := parseUUID(u.UUID)
			token, e := s.conn.state.ExportKeyingMaterial(string(id[:]), []byte(u.Password), 32)
			if e != nil {
				return e
			}
			valid |= subtle.ConstantTimeCompare(id[:], b[2:18]) & subtle.ConstantTimeCompare(token, b[18:])
		}
		if valid != 1 {
			s.conn.cancel()
			return errors.New("Juicity authentication rejected")
		}
		once.Do(func() { close(auth) })
		return nil
	}
	if e := waitQUICAuth(s.conn.ctx, auth); e != nil {
		return e
	}
	var kind [1]byte
	if _, e := io.ReadFull(stream, kind[:]); e != nil {
		return e
	}
	if kind[0] == 1 {
		address, e := readJuicityAddress(stream)
		if e != nil {
			return e
		}
		return s.relayTCP(r, in, stream, address, false)
	}
	if kind[0] != 3 {
		return errors.New("invalid Juicity proxy network")
	}
	if _, e := readJuicityAddress(stream); e != nil {
		return e
	}
	stream.SetDeadline(time.Time{})
	flows := newUDPFlows(r)
	defer flows.Close()
	var sendMu sync.Mutex
	for {
		stream.SetReadDeadline(time.Now().Add(4 * time.Minute))
		body, address, e := readJuicityPacket(stream)
		if e != nil {
			return e
		}
		if _, e = encodeAddress(address); e != nil {
			return e
		}
		q := request{origin: r.socketOrigin(s.conn.remote, s.conn.local), network: "udp", inbound: in.Tag, source: s.conn.remote.String(), address: address}
		e = flows.send(address, q, body, func(b []byte, from string) error {
			sendMu.Lock()
			defer sendMu.Unlock()
			stream.SetWriteDeadline(time.Now().Add(handshakeTimeout))
			return writeJuicityPacket(stream, b, from)
		})
		if e != nil {
			return e
		}
	}
}
