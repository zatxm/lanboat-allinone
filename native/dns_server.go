package native

import (
	"encoding/binary"
	"io"
	"net"
	"time"
)

func (r *Runtime) serveDNSStream(conn net.Conn, inbound string) error {
	q := request{origin: r.socketOrigin(conn.RemoteAddr(), conn.LocalAddr()), inbound: inbound, network: "tcp", source: conn.RemoteAddr().String(), address: conn.LocalAddr().String()}
	r.enrichProcess(r.ctx, &q)
	r.enrichNeighbor(r.ctx, &q)
	ctx := WithMetadata(r.ctx, q.metadata)
	var size [2]byte
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return err
		}
		n := int(binary.BigEndian.Uint16(size[:]))
		if n < 12 {
			return io.ErrUnexpectedEOF
		}
		query := make([]byte, n)
		if _, err := io.ReadFull(conn, query); err != nil {
			return err
		}
		reply, err := r.ExchangeDNS(ctx, query, inbound)
		if err != nil {
			_, end, _, e := dnsQuestion(query)
			if e != nil {
				return err
			}
			reply = dnsResponse(query, end, nil, 0, 2)
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		binary.BigEndian.PutUint16(size[:], uint16(len(reply)))
		if err := writeAll(conn, size[:]); err != nil {
			return err
		}
		if err := writeAll(conn, reply); err != nil {
			return err
		}
	}
}
func (r *Runtime) serveDNSPackets(in Inbound, packets net.PacketConn) {
	slots := make(chan struct{}, 128)
	buffer := make([]byte, 65535)
	for {
		n, from, err := packets.ReadFrom(buffer)
		if err != nil {
			return
		}
		if n < 12 {
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			continue
		}
		query := append([]byte(nil), buffer[:n]...)
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			<-slots
			return
		}
		r.workers.Add(1)
		r.mu.Unlock()
		go func() {
			defer r.workers.Done()
			defer func() { <-slots }()
			ctx := r.ctx
			q := request{origin: r.socketOrigin(from, packets.LocalAddr()), source: from.String(), inbound: in.Tag}
			r.enrichProcess(ctx, &q)
			r.enrichNeighbor(ctx, &q)
			ctx = WithMetadata(ctx, q.metadata)
			reply, err := r.ExchangeDNS(ctx, query, in.Tag)
			if err != nil {
				_, end, _, e := dnsQuestion(query)
				if e != nil {
					return
				}
				reply = dnsResponse(query, end, nil, 0, 2)
			}
			_, _ = packets.WriteTo(reply, from)
		}()
	}
}
