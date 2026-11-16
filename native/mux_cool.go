package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

type coolFrame struct {
	id                     uint16
	status, flags, network byte
	address                string
	data                   []byte
}

// The caller owns scratch until the next frame. Bound metadata before reading it.
func readCoolFrame(r io.Reader, scratch []byte) (coolFrame, error) {
	var f coolFrame
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return f, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n < 4 || n > 512 {
		return f, errors.New("invalid Mux.Cool metadata length")
	}
	m := scratch[:n]
	if _, err := io.ReadFull(r, m); err != nil {
		return f, err
	}
	f.id, f.status, f.flags = binary.BigEndian.Uint16(m), m[2], m[3]
	if f.status < 1 || f.status > 4 || f.flags & ^byte(3) != 0 || f.flags&2 != 0 && f.status != 3 {
		return f, errors.New("invalid Mux.Cool status or options")
	}
	if f.status == 1 || f.status == 2 && n > 4 {
		if n < 8 || m[4] != 1 && m[4] != 2 || f.status == 2 && m[4] != 2 {
			return f, errors.New("invalid Mux.Cool target network")
		}
		f.network = m[4]
		reader := bytes.NewReader(m[5:])
		var err error
		f.address, err = readVLESSAddress(reader)
		if err != nil {
			return f, err
		}
		if left := reader.Len(); left != 0 && !(f.status == 1 && f.network == 2 && left == 8) {
			return f, errors.New("invalid Mux.Cool target metadata")
		}
	} else if n != 4 {
		return f, errors.New("unexpected Mux.Cool metadata")
	}
	if f.flags&1 != 0 {
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return f, err
		}
		f.data = scratch[:int(binary.BigEndian.Uint16(h[:]))]
		if _, err := io.ReadFull(r, f.data); err != nil {
			return f, err
		}
	}
	return f, nil
}

func (s *smuxSession) sendCool(cmd byte, id uint32, data []byte, c *smuxStream, target string) error {
	status := [...]byte{1, 3, 2, 4, 3}[cmd]
	m := s.tx[:6]
	binary.BigEndian.PutUint16(m[2:4], uint16(id))
	m[4], m[5] = status, 0
	if cmd == 4 {
		m[5] = 2
	}
	if cmd == 0 || cmd == 2 && c != nil && c.network == 2 {
		if target == "" {
			target = c.address
		}
		address, err := vlessAddress(target)
		if err != nil {
			return err
		}
		m = append(m, c.network)
		m = append(m, address...)
	}
	binary.BigEndian.PutUint16(m, uint16(len(m)-2))
	if len(data) > 0 || cmd == 2 && c != nil && c.network == 2 {
		m[5] |= 1
		m = binary.BigEndian.AppendUint16(m, uint16(len(data)))
		if len(data)+len(m) <= cap(m) {
			m = append(m, data...)
			data = nil
		}
	}
	if err := writeAll(s.conn, m); err != nil {
		return err
	}
	return writeAll(s.conn, data)
}

func (s *smuxSession) openCool(ctx context.Context, network, address string) (*smuxStream, error) {
	if _, err := vlessAddress(address); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.err != nil {
		err := s.err
		s.mu.Unlock()
		return nil, err
	}
	if len(s.streams) >= 128 || s.next > 65535 {
		s.mu.Unlock()
		return nil, errors.New("Mux.Cool stream capacity exhausted")
	}
	id := s.next
	s.next++
	c := s.newStream(id)
	c.network, c.address = 1, address
	if network == "udp" {
		c.network = 2
	}
	s.streams[id] = c
	s.mu.Unlock()
	if err := s.send(ctx, 0, id, nil, c); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (s *smuxSession) receiveCool() error {
	scratch := make([]byte, 65535)
	for {
		f, err := readCoolFrame(s.conn, scratch)
		if err != nil {
			return err
		}
		s.lastRead.Store(time.Now().UnixNano())
		if f.status == 4 {
			continue
		}
		id := uint32(f.id)
		s.mu.Lock()
		c := s.streams[id]
		if f.status == 1 {
			if s.client || c != nil || len(s.streams) >= 128 {
				s.mu.Unlock()
				return errors.New("invalid Mux.Cool New frame or session capacity")
			}
			c = s.newStream(id)
			c.network, c.address = f.network, f.address
			s.streams[id] = c
		}
		s.mu.Unlock()
		if c == nil {
			continue
		}
		if f.status == 1 {
			select {
			case s.accept <- c:
			case <-s.ctx.Done():
				return net.ErrClosed
			default:
				return errors.New("Mux.Cool accept queue full")
			}
		}
		if f.address != "" && f.network != c.network {
			return errors.New("Mux.Cool stream network changed")
		}
		if f.flags&1 != 0 {
			address := f.address
			if address == "" {
				address = c.address
			}
			if err := c.pushTarget(f.data, address); err != nil {
				return err
			}
		}
		if f.status == 3 {
			if f.flags&2 != 0 {
				c.mu.Lock()
				c.writeClosed = true
				c.mu.Unlock()
				c.finish(errors.New("Mux.Cool peer rejected stream"))
			} else {
				c.finish(io.EOF)
			}
		}
	}
}

// A separate worker per bounded stream prevents a slow target handshake from
// blocking other targets. Plugin targets are always re-authenticated as SS.
func (r *Runtime) serveMuxCool(c net.Conn, q request, plugin *Inbound, udpOnly bool) error {
	_ = c.SetDeadline(time.Time{})
	s := newMuxSession(r.ctx, c, false, true)
	flows := newUDPFlows(r)
	defer flows.Close()
	var workers sync.WaitGroup
	defer func() { s.close(net.ErrClosed); workers.Wait() }()
	for {
		select {
		case stream := <-s.accept:
			if udpOnly && stream.network != 2 {
				return errors.New("Vision Mux.Cool accepts UDP only")
			}
			workers.Go(func() {
				defer stream.Close()
				if plugin != nil {
					if stream.network != 1 {
						return
					}
					_ = stream.SetDeadline(time.Now().Add(handshakeTimeout))
					_ = r.serveProtocol(*plugin, stream, q.source)
					return
				}
				job := q
				job.address = stream.address
				if stream.network == 2 {
					job.network = "udp"
					prefix := strconv.Itoa(int(stream.id)) + ":"
					defer flows.closePrefix(prefix)
					data := make([]byte, 65535)
					for {
						_ = stream.SetReadDeadline(time.Now().Add(r.udpTimeoutFor(q.inbound, udpTimeout)))
						n, address, err := stream.readTarget(data)
						if err != nil {
							return
						}
						job.address = address
						if _, err = encodeAddress(address); err != nil {
							return
						}
						if err = flows.send(prefix+address, job, data[:n], func(b []byte, from string) error {
							_ = stream.SetWriteDeadline(time.Now().Add(handshakeTimeout))
							stream.writeMu.Lock()
							defer stream.writeMu.Unlock()
							return s.sendTarget(s.ctx, 2, stream.id, b, stream, from)
						}); err != nil {
							return
						}
					}
				}
				if _, err := encodeAddress(job.address); err != nil {
					_ = s.send(s.ctx, 4, stream.id, nil, stream)
					return
				}
				remote, err := r.routeDial(s.ctx, job)
				if err != nil {
					_ = s.send(s.ctx, 4, stream.id, nil, stream)
					return
				}
				stop := context.AfterFunc(s.ctx, func() { remote.Close() })
				defer stop()
				r.relay(stream, remote)
			})
		case <-s.done:
			s.mu.Lock()
			err := s.err
			s.mu.Unlock()
			return err
		}
	}
}
