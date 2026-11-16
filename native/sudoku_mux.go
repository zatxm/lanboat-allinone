package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Sudoku uses its own frame codec over the existing bounded stream queues.
type sudokuMuxControl struct {
	command byte
	id      uint32
	data    []byte
}

func (s *smuxSession) sendSudoku(command byte, id uint32, data []byte) error {
	kinds := [...]byte{1, 3, 2, 5, 4, 6}
	if int(command) >= len(kinds) {
		return errors.New("invalid Sudoku mux command")
	}
	s.tx[0] = kinds[command]
	binary.BigEndian.PutUint32(s.tx[1:5], id)
	binary.BigEndian.PutUint32(s.tx[5:9], uint32(len(data)))
	copy(s.tx[9:], data)
	return writeAll(s.conn, s.tx[:9+len(data)])
}

// Control writes must not block the demultiplexer behind a full send window.
func (s *smuxSession) sudokuControl(command byte, id uint32, message string) error {
	select {
	case s.control <- sudokuMuxControl{command, id, []byte(message)}:
		return nil
	case <-s.done:
		return net.ErrClosed
	default:
		return errors.New("Sudoku mux control queue full")
	}
}

func (s *smuxSession) sudokuAbort(c *smuxStream) {
	c.mu.Lock()
	c.writeClosed = true
	c.mu.Unlock()
	c.Close()
}

func (s *smuxSession) receiveSudoku() error {
	var header [9]byte
	buffer := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(buffer)
	for {
		if _, err := io.ReadFull(s.conn, header[:]); err != nil {
			return err
		}
		kind, id, size := header[0], binary.BigEndian.Uint32(header[1:5]), binary.BigEndian.Uint32(header[5:])
		if size > 256<<10 || kind < 1 || kind > 6 || kind >= 5 && (id != 0 || size != 0) || kind == 3 && size != 0 || kind == 1 && (size < 5 || size > 259) {
			return errors.New("invalid Sudoku mux frame")
		}
		s.lastRead.Store(time.Now().UnixNano())
		if kind >= 5 {
			if kind == 5 {
				if err := s.sudokuControl(5, 0, ""); err != nil {
					return err
				}
			}
			continue
		}
		if id == 0 {
			return errors.New("invalid Sudoku mux stream identifier")
		}
		s.mu.Lock()
		c := s.streams[id]
		s.mu.Unlock()
		if kind == 2 {
			if c != nil {
				c.mu.Lock()
				full := c.bytes+int(size) > 1<<20 || s.buffered.Load()+int64(size) > smuxBufferLimit
				c.mu.Unlock()
				if full {
					s.sudokuAbort(c)
					c = nil
					if err := s.sudokuControl(4, id, "receive queue exceeded"); err != nil {
						return err
					}
				}
			}
			for size > 0 {
				n := min(int(size), 16384)
				if _, err := io.ReadFull(s.conn, buffer[:n]); err != nil {
					return err
				}
				if c != nil {
					if err := c.push(buffer[:n]); err != nil {
						return err
					}
				}
				size -= uint32(n)
			}
			continue
		}
		if kind == 4 {
			if _, err := io.CopyN(io.Discard, s.conn, int64(size)); err != nil {
				return err
			}
			if c != nil {
				s.sudokuAbort(c)
			}
			continue
		}
		if kind == 3 {
			if c != nil {
				c.finish(io.EOF)
			}
			continue
		}
		if _, err := io.ReadFull(s.conn, buffer[:size]); err != nil {
			return err
		}
		if s.client {
			return errors.New("unexpected Sudoku mux reverse stream")
		}
		reader := bytes.NewReader(buffer[:size])
		address, err := readAddress(reader)
		if err == nil && reader.Len() == 0 {
			_, err = encodeAddress(address)
		} else {
			err = errors.New("invalid Sudoku mux target")
		}
		if err != nil {
			if err = s.sudokuControl(4, id, "bad destination"); err != nil {
				return err
			}
			continue
		}
		s.mu.Lock()
		if c != nil || !s.peerIDs.accept(uint64(id)) {
			s.mu.Unlock()
			return errors.New("reused Sudoku mux stream identifier")
		}
		if len(s.streams) >= 128 {
			s.mu.Unlock()
			if err = s.sudokuControl(4, id, "stream capacity exceeded"); err != nil {
				return err
			}
			continue
		}
		c = s.newStream(id)
		c.address = address
		s.streams[id] = c
		s.mu.Unlock()
		select {
		case s.accept <- c:
		case <-s.ctx.Done():
			return net.ErrClosed
		default:
			return errors.New("Sudoku mux accept queue full")
		}
	}
}

type sudokuMuxClient struct {
	runtime  *Runtime
	outbound Outbound
	mu       sync.Mutex
	current  *smuxSession
}

func (p *sudokuMuxClient) reset() {
	p.mu.Lock()
	s := p.current
	p.current = nil
	p.mu.Unlock()
	if s != nil {
		s.close(net.ErrClosed)
	}
}

func (p *sudokuMuxClient) session(ctx context.Context) (*smuxSession, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s := p.current; s != nil {
		select {
		case <-s.done:
			p.current = nil
		default:
			return s, nil
		}
	}
	raw, err := p.runtime.dialProxyTransport(ctx, p.outbound)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	c, selected, err := sudokuHandshake(raw, p.outbound.Sudoku, 7)
	if err == nil && selected&2 == 0 {
		err = errors.New("Sudoku peer does not support multiplexing")
	}
	if err == nil {
		err = sudokuMessage(c, 0x11, nil)
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && !stop() {
		err = ctx.Err()
	}
	if err != nil {
		raw.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	s := newMuxConfigured(p.runtime.ctx, c, true, muxSudoku, 1, 15*time.Second, false)
	p.current = s
	return s, nil
}

func (p *sudokuMuxClient) dial(ctx context.Context, address string) (net.Conn, error) {
	target, err := encodeAddress(address)
	if err != nil {
		return nil, err
	}
	s, err := p.session(ctx)
	if err != nil {
		return nil, err
	}
	c, err := s.openPayload(ctx, target)
	if err != nil {
		return nil, err
	}
	return p.runtime.own(c)
}

func (r *Runtime) serveSudokuMux(c net.Conn, q request) error {
	_ = c.SetDeadline(time.Time{})
	s := newMuxConfigured(r.ctx, c, false, muxSudoku, 1, 15*time.Second, false)
	var workers sync.WaitGroup
	defer func() { s.close(net.ErrClosed); workers.Wait() }()
	for {
		select {
		case stream := <-s.accept:
			workers.Go(func() {
				defer stream.Close()
				job := q
				job.address = stream.address
				remote, err := r.routeDial(s.ctx, job)
				if err != nil {
					_ = s.sudokuControl(4, stream.id, "destination unavailable")
					s.sudokuAbort(stream)
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
