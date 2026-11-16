package native

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// Yamux uses a 256KiB initial receive window and cumulative stream credits.
func (s *smuxSession) sendYAMUX(cmd byte, id uint32, data []byte) error {
	var kind byte
	var flags uint16
	var length uint32
	switch cmd {
	case 0:
		kind = 1
		flags = 1
	case 1:
		flags = 4
	case 2:
		length = uint32(len(data))
	case 3:
		kind = 2
		flags = 1
	case 4:
		kind = 1
		length = binary.LittleEndian.Uint32(data)
		data = nil
	case 5:
		kind = 1
		flags = 2
	case 6:
		flags = 8
	case 7:
		kind = 2
		flags = 2
		length = id
		id = 0
	default:
		return errors.New("invalid yamux command")
	}
	h := s.tx[:12]
	clear(h)
	h[1] = kind
	binary.BigEndian.PutUint16(h[2:], flags)
	binary.BigEndian.PutUint32(h[4:], id)
	binary.BigEndian.PutUint32(h[8:], length)
	if cmd == 2 {
		copy(s.tx[12:], data)
		h = s.tx[:12+len(data)]
	}
	return writeAll(s.conn, h)
}
func (s *smuxSession) yamuxControl(cmd byte, id uint32) error {
	select {
	case s.control <- sudokuMuxControl{command: cmd, id: id}:
		return nil
	case <-s.done:
		return net.ErrClosed
	default:
		return errors.New("yamux control queue full")
	}
}
func (s *smuxSession) receiveYAMUX() error {
	var header [12]byte
	buffer := make([]byte, 32768)
	for {
		if _, err := io.ReadFull(s.conn, header[:]); err != nil {
			return err
		}
		s.lastRead.Store(time.Now().UnixNano())
		kind, flags, id, size := header[1], binary.BigEndian.Uint16(header[2:]), binary.BigEndian.Uint32(header[4:]), binary.BigEndian.Uint32(header[8:])
		if header[0] != 0 || kind > 3 || flags & ^uint16(15) != 0 || flags&3 == 3 {
			return errors.New("invalid yamux header")
		}
		if kind >= 2 {
			if id != 0 || flags & ^uint16(3) != 0 {
				return errors.New("invalid yamux connection control")
			}
			if kind == 3 {
				return errors.New("yamux peer sent GOAWAY")
			}
			if flags == 1 {
				if err := s.yamuxControl(7, size); err != nil {
					return err
				}
			}
			continue
		}
		if id == 0 {
			return errors.New("zero yamux stream ID")
		}
		s.mu.Lock()
		c := s.streams[id]
		if flags&1 != 0 {
			if c != nil || (id&1 == 1) == s.client || !s.peerIDs.accept(uint64(id/2)) || len(s.streams) >= 128 {
				s.mu.Unlock()
				return errors.New("invalid yamux SYN or stream capacity")
			}
			c = s.newStream(id)
			s.streams[id] = c
		}
		s.mu.Unlock()
		if flags&1 != 0 {
			if err := s.yamuxControl(5, id); err != nil {
				return err
			}
			select {
			case s.accept <- c:
			case <-s.done:
				return net.ErrClosed
			default:
				return errors.New("yamux accept queue full")
			}
		}
		if kind == 1 && c != nil {
			c.mu.Lock()
			credit := uint64(c.peerWindow) + uint64(size)
			if credit > smuxBufferLimit {
				c.mu.Unlock()
				return errors.New("yamux send window exceeds limit")
			}
			c.peerWindow = uint32(credit)
			signal(c.writeNotify)
			c.mu.Unlock()
		}
		if kind == 0 {
			if size > 262144 {
				return errors.New("yamux data frame exceeds initial window")
			}
			if c != nil {
				c.mu.Lock()
				if size > c.yamuxWindow {
					c.mu.Unlock()
					return errors.New("yamux receive window exceeded")
				}
				c.yamuxWindow -= size
				c.mu.Unlock()
			}
			for size > 0 {
				n := min(size, uint32(len(buffer)))
				if _, err := io.ReadFull(s.conn, buffer[:n]); err != nil {
					return err
				}
				if c != nil {
					if err := c.push(buffer[:n]); err != nil {
						return err
					}
				}
				size -= n
			}
		}
		if c != nil && flags&8 != 0 {
			c.finish(errors.New("yamux stream reset"))
			c.Close()
		}
		if c != nil && flags&4 != 0 {
			c.finish(io.EOF)
		}
	}
}
