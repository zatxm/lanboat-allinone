package native

import (
	"crypto/subtle"
	"errors"
	"io"
	"strconv"
	"sync"
	"time"
)

// This transport uses HTTP/3 authentication, then 0x401 followed by opaque bytes,
// without the destination or response record of an ordinary HY2 proxy stream.
func (r *Runtime) serveHY2Transport(in Inbound, q *quicConn, stream *quicStream, auth chan struct{}, once *sync.Once) error {
	if stream.id&2 != 0 {
		stream.SetDeadline(time.Time{})
		err := h3Uni(stream)
		if err != nil {
			q.Close()
		}
		return err
	}
	kind, err := readQUICVar(stream)
	if err != nil {
		return err
	}
	if kind == 1 {
		return serveHY2Auth(q, Inbound{Password: in.plugin.password}, stream, auth, once, true)
	}
	if kind != 0x401 {
		return errors.New("invalid Hysteria2 transport stream")
	}
	if err = waitQUICAuth(q.ctx, auth); err != nil {
		return err
	}
	return r.serveProtocol(in, stream, q.remote.String())
}

func serveHY2Auth(q *quicConn, in Inbound, stream *quicStream, auth chan struct{}, once *sync.Once, transport bool) error {
	n, err := readQUICVar(stream)
	if err != nil || n > 65536 {
		return errors.New("invalid HY2 HTTP headers")
	}
	b := make([]byte, n)
	if _, err = io.ReadFull(stream, b); err != nil {
		return err
	}
	h, err := h3Decode(b)
	if err != nil {
		return err
	}
	valid := 0
	for _, u := range in.Users {
		valid |= subtle.ConstantTimeCompare([]byte(h["hysteria-auth"]), []byte(u.Password))
	}
	if in.Password != "" {
		valid |= subtle.ConstantTimeCompare([]byte(h["hysteria-auth"]), []byte(in.Password))
	} else if transport {
		valid = 1
	}
	status, rx := "404", "auto"
	if valid == 1 && h[":method"] == "POST" && h[":path"] == "/auth" && h[":authority"] == "hysteria" {
		tx, advertised, err := hy2ServerRates(in, h["hysteria-cc-rx"])
		if err != nil {
			return err
		}
		status, rx = "233", advertised
		once.Do(func() { q.setBrutalRate(tx); close(auth) })
	}
	err = h3WriteFrame(stream, 1, h3Encode([][2]string{{":status", status}, {"hysteria-udp", strconv.FormatBool(!transport)}, {"hysteria-cc-rx", rx}}))
	if err == nil {
		err = stream.CloseWrite()
	}
	return err
}

func receiveHY2TransportStreams(q *quicConn) {
	var workers sync.WaitGroup
	defer workers.Wait()
	defer q.Close()
	slots := make(chan struct{}, 8)
	for {
		stream, err := q.AcceptStream(q.ctx)
		if err != nil {
			return
		}
		if stream.id&2 == 0 {
			stream.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			stream.Close()
			return
		}
		workers.Go(func() {
			defer func() { <-slots }()
			defer stream.Close()
			if err := h3Uni(stream); err != nil {
				q.Close()
			}
		})
	}
}
