package native

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type tsDERPRegion struct {
	RegionID int
	Avoid    bool
	Nodes    []tsDERPNode
}
type tsDERPNode struct {
	HostName, CertName, IPv4, IPv6 string
	DERPPort, STUNPort             int
	STUNOnly                       bool
}

type tsDERP struct {
	c                      *tailscaleClient
	id                     int
	connectMu, writeMu, mu sync.Mutex
	conn                   net.Conn
	closed                 bool
	frame                  []byte
}

func (c *tailscaleClient) derp(id int) (*tsDERP, error) {
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	d := c.derps[id]
	if d == nil {
		d = &tsDERP{c: c, id: id}
		c.derps[id] = d
	}
	c.mu.Unlock()
	return d, d.connect()
}

func (d *tsDERP) close() {
	d.mu.Lock()
	d.closed = true
	raw := d.conn
	d.conn = nil
	d.mu.Unlock()
	if raw != nil {
		raw.Close()
	}
}

func (d *tsDERP) connect() error {
	d.connectMu.Lock()
	defer d.connectMu.Unlock()
	d.mu.Lock()
	exists, closed := d.conn != nil, d.closed
	d.mu.Unlock()
	if closed || d.c.ctx.Err() != nil {
		return net.ErrClosed
	}
	if exists {
		return nil
	}
	d.c.mu.Lock()
	region, ok := d.c.regions[d.id]
	d.c.mu.Unlock()
	if !ok {
		return errors.New("Tailscale peer has no known DERP region")
	}
	ctx, cancel := context.WithTimeout(d.c.ctx, 10*time.Second)
	defer cancel()
	var last error = errors.New("Tailscale DERP region has no relay nodes")
	for _, node := range region.Nodes {
		if node.STUNOnly {
			continue
		}
		raw, reader, e := d.dial(ctx, node)
		if e != nil {
			last = e
			continue
		}
		d.mu.Lock()
		if d.closed || d.c.ctx.Err() != nil {
			d.mu.Unlock()
			raw.Close()
			return net.ErrClosed
		}
		d.conn = raw
		d.mu.Unlock()
		d.c.spawn(func() { d.read(raw, reader) })
		return nil
	}
	return last
}

func (d *tsDERP) dial(ctx context.Context, node tsDERPNode) (net.Conn, *bufio.Reader, error) {
	if node.HostName == "" || node.DERPPort < 0 || node.DERPPort > 65535 {
		return nil, nil, errors.New("invalid Tailscale DERP node")
	}
	port := node.DERPPort
	if port == 0 {
		port = 443
	}
	host := node.HostName
	if ip := net.ParseIP(node.IPv4); ip != nil {
		host = node.IPv4
	} else if ip := net.ParseIP(node.IPv6); ip != nil {
		host = node.IPv6
	}
	bootstrap := "@local"
	if ref := d.c.o.DomainResolver; ref != "" {
		bootstrap = ref.tag()
	}
	raw, e := d.c.r.direct(context.WithValue(ctx, dnsBootstrapKey{}, bootstrap), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if e != nil {
		return nil, nil, e
	}
	ok := false
	defer func() {
		if !ok {
			raw.Close()
		}
	}()
	name := node.CertName
	if name == "" {
		name = node.HostName
	}
	cfg, e := d.c.tlsConfig(name)
	if e != nil {
		return nil, nil, e
	}
	if strings.HasPrefix(name, "sha256-raw:") {
		// This is an explicit pin from the authenticated controller, never a TLS bypass.
		cfg, e = d.c.tlsConfig(node.HostName)
		if e != nil {
			return nil, nil, e
		}
		pin := strings.TrimPrefix(name, "sha256-raw:")
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(cs tls.ConnectionState) error { return tsVerifyDERPPin(cs, pin) }
	}
	secure := clientTLS(raw, cfg, d.c.o.TLS)
	if e = secure.HandshakeContext(ctx); e != nil {
		return nil, nil, e
	}
	deadline, _ := ctx.Deadline()
	secure.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	header := "GET /derp HTTP/1.1\r\nHost: " + net.JoinHostPort(node.HostName, strconv.Itoa(port)) + "\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n"
	if e = writeAll(secure, []byte(header)); e != nil {
		return nil, nil, e
	}
	reader := bufio.NewReaderSize(secure, 4096)
	if e = tsReadDERPUpgrade(reader); e != nil {
		return nil, nil, e
	}
	kind, b, e := tsReadDERP(reader)
	if e != nil {
		return nil, nil, e
	}
	if kind != 1 || len(b) < 40 || string(b[:8]) != "DERP🔑" {
		return nil, nil, errors.New("invalid DERP server identity")
	}
	box, e := tsBoxKey(d.c.nodeKey, b[8:40])
	if e != nil {
		return nil, nil, e
	}
	info := []byte(`{"version":2,"CanAckPings":true}`)
	message := append(append([]byte{}, d.c.nodeKey.PublicKey().Bytes()...), tsBoxSeal(box, info)...)
	if e = tsWriteDERP(secure, 2, message); e != nil {
		return nil, nil, e
	}
	kind, b, e = tsReadDERP(reader)
	if e != nil {
		return nil, nil, e
	}
	if kind != 3 {
		return nil, nil, errors.New("DERP authentication rejected")
	}
	plain, e := tsBoxOpen(box, b)
	if e != nil {
		return nil, nil, e
	}
	var server struct{ Version int }
	if e = json.Unmarshal(plain, &server); e != nil || server.Version != 2 {
		return nil, nil, errors.New("unsupported DERP protocol version")
	}
	if e = tsWriteDERP(secure, 7, []byte{1}); e != nil {
		return nil, nil, e
	}
	secure.SetDeadline(time.Time{})
	ok = true
	return secure, reader, nil
}

func tsReadDERP(reader *bufio.Reader) (byte, []byte, error) {
	var header [5]byte
	if _, e := io.ReadFull(reader, header[:]); e != nil {
		return 0, nil, e
	}
	n := binary.BigEndian.Uint32(header[1:])
	if n > 65536+64 {
		return 0, nil, errors.New("DERP frame exceeds packet limit")
	}
	b := make([]byte, n)
	_, e := io.ReadFull(reader, b)
	return header[0], b, e
}
func tsWriteDERP(w io.Writer, kind byte, b []byte) error {
	if len(b) > 65536+64 {
		return errors.New("DERP packet exceeds limit")
	}
	var header [5]byte
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], uint32(len(b)))
	if e := writeAll(w, header[:]); e != nil {
		return e
	}
	return writeAll(w, b)
}

func (d *tsDERP) write(kind byte, b []byte) error {
	return d.writeParts(kind, nil, b)
}

func (d *tsDERP) writeParts(kind byte, prefix, b []byte) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	d.mu.Lock()
	raw := d.conn
	d.mu.Unlock()
	if raw == nil {
		return net.ErrClosed
	}
	n := len(prefix) + len(b)
	if n > 65536+64 {
		return errors.New("DERP packet exceeds limit")
	}
	raw.SetWriteDeadline(time.Now().Add(10 * time.Second))
	d.frame = append(d.frame[:0], kind, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	d.frame = append(d.frame, prefix...)
	d.frame = append(d.frame, b...)
	e := writeAll(raw, d.frame)
	raw.SetWriteDeadline(time.Time{})
	if e != nil {
		d.mu.Lock()
		if d.conn == raw {
			d.conn = nil
		}
		d.mu.Unlock()
		raw.Close()
	}
	return e
}

func (d *tsDERP) send(public, b []byte) error {
	if e := d.connect(); e != nil {
		return e
	}
	return d.writeParts(4, public, b)
}

func (d *tsDERP) read(raw net.Conn, reader *bufio.Reader) {
	defer raw.Close()
	defer func() {
		d.mu.Lock()
		if d.conn == raw {
			d.conn = nil
		}
		d.mu.Unlock()
	}()
	buffer := make([]byte, 65536+64)
	for {
		raw.SetReadDeadline(time.Now().Add(2 * time.Minute))
		var header [5]byte
		_, e := io.ReadFull(reader, header[:])
		if e != nil {
			return
		}
		n := int(binary.BigEndian.Uint32(header[1:]))
		if n > len(buffer) {
			return
		}
		kind, b := header[0], buffer[:n]
		_, e = io.ReadFull(reader, b)
		if e != nil {
			return
		}
		switch kind {
		case 5:
			if len(b) >= 32 {
				d.c.receiveDERP(d.id, b[:32], b[32:])
			}
		case 0x12:
			if len(b) != 8 {
				return
			}
			if e = d.write(0x13, b); e != nil {
				return
			}
		case 0x15:
			return
		case 0x14:
			if len(b) > 0 {
				return
			}
		}
	}
}

func tsReadDERPUpgrade(reader *bufio.Reader) error {
	header, e := readHTTPHeader(reader)
	if e != nil {
		return e
	}
	if !strings.HasPrefix(string(header), "HTTP/1.1 101 ") {
		return fmt.Errorf("DERP HTTP upgrade rejected")
	}
	return nil
}
