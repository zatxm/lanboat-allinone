package native

import (
	"encoding/binary"
	"net"
	"sync"
)

type mkcpListener struct {
	r        *Runtime
	packet   net.PacketConn
	options  MKCPOptions
	codec    *mkcpCodec
	mu       sync.Mutex
	peers    map[string]*mkcpConn
	accepted chan net.Conn
	done     chan struct{}
	once     sync.Once
	worker   sync.WaitGroup
}

func (r *Runtime) listenMKCP(in Inbound, host string) (*mkcpListener, error) {
	pc, e := in.ListenOptions.listenPacket(r.ctx, "udp", portAddress(host, in.ListenPort))
	if e != nil {
		return nil, e
	}
	o := in.Transport.mkcpOptions()
	l := &mkcpListener{r: r, packet: pc, options: o, codec: newMKCPCodec(o), peers: map[string]*mkcpConn{}, accepted: make(chan net.Conn, 128), done: make(chan struct{})}
	l.worker.Go(l.read)
	return l, nil
}

func (l *mkcpListener) read() {
	buffer := make([]byte, 2049)
	for {
		n, from, e := l.packet.ReadFrom(buffer)
		if e != nil {
			return
		}
		plain, e := l.codec.open(buffer[:n])
		if e != nil {
			continue
		}
		frames, e := parseMKCP(plain)
		if e != nil || len(frames) == 0 {
			continue
		}
		first := frames[0]
		key := string(binary.BigEndian.AppendUint16([]byte(from.String()+"\x00"), first.conv))
		l.mu.Lock()
		c := l.peers[key]
		fresh := c == nil
		if fresh {
			if len(l.peers) >= 128 || !(first.cmd == 1 && first.number == 0 || first.cmd == 3 && first.number == 0 && first.next == 0) {
				l.mu.Unlock()
				continue
			}
			c, e = l.r.newMKCP(l.options, l.codec, first.conv, l.packet.LocalAddr(), from, nil, func(b []byte) error { _, e := l.packet.WriteTo(b, from); return e }, l, key)
			if e != nil {
				l.mu.Unlock()
				continue
			}
			l.peers[key] = c
		}
		l.mu.Unlock()
		c.input(frames)
		if fresh {
			select {
			case l.accepted <- c:
			case <-l.done:
				c.abort(net.ErrClosed)
				return
			default:
				c.abort(net.ErrClosed)
			}
		}
	}
}

func (l *mkcpListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accepted:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	case <-l.r.ctx.Done():
		return nil, net.ErrClosed
	}
}
func (l *mkcpListener) Addr() net.Addr { return l.packet.LocalAddr() }
func (l *mkcpListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.packet.Close()
		l.worker.Wait()
		l.mu.Lock()
		var peers []*mkcpConn
		for _, c := range l.peers {
			peers = append(peers, c)
		}
		l.mu.Unlock()
		for _, c := range peers {
			c.abort(net.ErrClosed)
		}
		for _, c := range peers {
			c.workers.Wait()
		}
	})
	return nil
}
