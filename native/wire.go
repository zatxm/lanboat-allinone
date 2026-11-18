package native

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func encodeAddress(address string) ([]byte, error) {
	return appendAddress(nil, address)
}

// validAddress reports whether address can be encoded, without allocating.
func validAddress(address string) error {
	var b [1 + 1 + 255 + 2]byte
	_, err := appendAddress(b[:0], address)
	return err
}

// appendAddress appends the SOCKS-style encoding of address to dst.
func appendAddress(dst []byte, address string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("destination port must be 1-65535")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Zone() != "" {
			return nil, errors.New("scoped IPv6 cannot be encoded in a proxy address")
		}
		if ip.Is4() {
			a := ip.As4()
			dst = append(append(dst, 1), a[:]...)
		} else {
			a := ip.As16()
			dst = append(append(dst, 4), a[:]...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("destination domain must contain 1-255 bytes")
		}
		if strings.ContainsAny(host, "\x00\r\n\t /?#@\\:") {
			return nil, errors.New("invalid destination hostname")
		}
		for _, b := range []byte(host) {
			if b < 32 || b == 127 {
				return nil, errors.New("control byte in destination hostname")
			}
		}
		dst = append(append(dst, 3, byte(len(host))), host...)
	}
	return binary.BigEndian.AppendUint16(dst, uint16(port)), nil
}

func readAddress(r io.Reader) (string, error) {
	var kind [1]byte
	if _, err := io.ReadFull(r, kind[:]); err != nil {
		return "", err
	}
	atyp := kind[0]
	var raw []byte
	switch kind[0] {
	case 1:
		raw = make([]byte, 4)
	case 4:
		raw = make([]byte, 16)
	case 3:
		if _, err := io.ReadFull(r, kind[:]); err != nil {
			return "", err
		}
		if kind[0] == 0 {
			return "", errors.New("empty destination domain")
		}
		raw = make([]byte, int(kind[0]))
	default:
		return "", errors.New("invalid address type")
	}
	if _, err := io.ReadFull(r, raw); err != nil {
		return "", err
	}
	host := string(raw)
	if atyp != 3 {
		host = net.IP(raw).String()
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *bufferedConn) CloseWrite() error {
	if c, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return nil
}

func vlessAddress(address string) ([]byte, error) {
	b, err := encodeAddress(address)
	if err != nil {
		return nil, err
	}
	port := b[len(b)-2:]
	kind := map[byte]byte{1: 1, 3: 2, 4: 3}[b[0]]
	out := append([]byte{}, port...)
	out = append(out, kind)
	return append(out, b[1:len(b)-2]...), nil
}

func readVLESSAddress(r io.Reader) (string, error) {
	var header [3]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return "", err
	}
	kind := map[byte]byte{1: 1, 2: 3, 3: 4}[header[2]]
	if kind == 0 {
		return "", errors.New("invalid VLESS address type")
	}
	var raw []byte
	switch kind {
	case 1:
		raw = make([]byte, 4)
	case 4:
		raw = make([]byte, 16)
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return "", err
		}
		if length[0] == 0 {
			return "", errors.New("empty VLESS domain")
		}
		raw = make([]byte, int(length[0]))
	}
	if _, err := io.ReadFull(r, raw); err != nil {
		return "", err
	}
	host := string(raw)
	if kind != 3 {
		host = net.IP(raw).String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(header[:2])))), nil
}

func readCRLF(r io.Reader) error {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	if b != [2]byte{13, 10} {
		return fmt.Errorf("invalid protocol delimiter")
	}
	return nil
}
