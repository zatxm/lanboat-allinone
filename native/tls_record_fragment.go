package native

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

func clientTLS(conn net.Conn, config *tls.Config, options TLSOptions) tlsConnection {
	if options.browserEnabled() {
		return &kernelTLSHandshake{Conn: conn, config: config, options: options}
	}
	conn, config = clientTLSConnection(conn, config, options)
	if options.KernelTX || options.KernelRX {
		return &kernelTLSHandshake{Conn: conn, config: config, options: options}
	}
	return tls.Client(conn, config)
}

func clientTLSConnection(conn net.Conn, config *tls.Config, options TLSOptions) (net.Conn, *tls.Config) {
	var tcp *tlsFragmentConn
	var record *tlsRecordFragmentConn
	if options.Fragment {
		delay, _ := options.fragmentDelay()
		tcp = newTLSFragmentConn(conn, delay)
		conn = tcp
	}
	if options.RecordFragment {
		record = &tlsRecordFragmentConn{Conn: conn}
		conn = record
	}
	if tcp != nil || record != nil {
		config = config.Clone()
		verify := config.VerifyConnection
		config.VerifyConnection = func(state tls.ConnectionState) error {
			// Stop before TLS1.2 encrypted Finished and resumed handshakes.
			if tcp != nil {
				tcp.done.Store(true)
			}
			if record != nil {
				record.done.Store(true)
			}
			if verify != nil {
				return verify(state)
			}
			return nil
		}
	}
	return conn, config
}

type tlsRecordFragmentConn struct {
	net.Conn
	mu        sync.Mutex
	remaining int
	done      atomic.Bool
}

// Change record boundaries only; the TLS transcript and encrypted data remain
// byte-identical. A complete SNI is split between records when it is available.
func fragmentTLSRecords(p []byte, remaining int) ([]byte, int, error) {
	if len(p) > 1<<20 {
		return nil, remaining, errors.New("TLS record write exceeds1MiB")
	}
	out := make([]byte, 0, len(p)+10)
	for len(p) > 0 {
		if len(p) < 5 {
			return nil, remaining, errors.New("truncated TLS record header")
		}
		n := int(binary.BigEndian.Uint16(p[3:5]))
		if n > len(p)-5 {
			return nil, remaining, errors.New("truncated TLS record payload")
		}
		record, payload := p[:5+n], p[5:5+n]
		split := 0
		if p[0] == 22 && len(payload) > 1 {
			if remaining > 0 {
				split = len(payload) / 2
				remaining = max(0, remaining-len(payload))
			} else if len(payload) >= 4 && payload[0] == 1 {
				remaining = max(0, 4+(int(payload[1])<<16|int(payload[2])<<8|int(payload[3]))-len(payload))
				split = len(payload) / 2
				if host, start, ok := clientHelloSNI(payload); ok && len(host) > 1 {
					split = start + len(host)/2
				}
			}
		}
		if split > 0 && split < len(payload) {
			out = append(out, p[:3]...)
			out = binary.BigEndian.AppendUint16(out, uint16(split))
			out = append(out, payload[:split]...)
			out = append(out, p[:3]...)
			out = binary.BigEndian.AppendUint16(out, uint16(len(payload)-split))
			out = append(out, payload[split:]...)
		} else {
			out = append(out, record...)
		}
		p = p[len(record):]
	}
	return out, remaining, nil
}

func (c *tlsRecordFragmentConn) Write(p []byte) (int, error) {
	if c.done.Load() || len(p) < 6 || p[0] != 22 {
		return c.Conn.Write(p)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.remaining == 0 && (len(p) < 6 || p[0] != 22 || p[5] != 1) {
		return c.Conn.Write(p)
	}
	wire, remaining, err := fragmentTLSRecords(p, c.remaining)
	if err != nil {
		return 0, err
	}
	if err = writeAll(c.Conn, wire); err != nil {
		return 0, err
	}
	c.remaining = remaining
	return len(p), nil
}
