package native

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"os"
	"time"
)

type realityPostKey struct {
	tag  string
	alpn [32]byte
}
type realityPost struct {
	done    chan struct{}
	sizes   []int
	err     error
	expires time.Time
}

// Only authenticated clients reach this cache. Bound entries and active probes
// separately; a failed/expired probe is retried without background polling.
func (r *Runtime) realityPostSizes(in Inbound, hello []byte) ([]int, error) {
	_, ext, err := realityClientParameters(hello)
	if err != nil {
		return nil, err
	}
	key := realityPostKey{in.Tag, sha256.Sum256(append([]byte(in.TLS.ServerName+"\x00"), ext[16]...))}
	r.realityMu.Lock()
	if r.realityPosts == nil {
		r.realityPosts = make(map[realityPostKey]*realityPost)
	}
	entry := r.realityPosts[key]
	if entry != nil && time.Now().After(entry.expires) {
		select {
		case <-entry.done:
			delete(r.realityPosts, key)
			entry = nil
		default:
		}
	}
	if entry == nil {
		if len(r.realityPosts) >= 64 {
			for k, v := range r.realityPosts {
				select {
				case <-v.done:
					delete(r.realityPosts, k)
				default:
				}
				if len(r.realityPosts) < 64 {
					break
				}
			}
		}
		if len(r.realityPosts) >= 64 {
			r.realityMu.Unlock()
			return nil, errors.New("Reality cover probe cache busy")
		}
		entry = &realityPost{done: make(chan struct{}), expires: time.Now().Add(10 * time.Minute)}
		r.realityPosts[key] = entry
		r.realityMu.Unlock()
		if r.realityProbes.Add(1) > 4 {
			entry.err = errors.New("Reality cover probes busy")
		} else {
			entry.sizes, entry.err = r.probeRealityPost(in, ext[16])
		}
		r.realityProbes.Add(-1)
		if entry.err != nil {
			r.realityMu.Lock()
			entry.expires = time.Now().Add(time.Second)
			r.realityMu.Unlock()
		}
		close(entry.done)
	} else {
		r.realityMu.Unlock()
	}
	select {
	case <-entry.done:
		return entry.sizes, entry.err
	case <-r.ctx.Done():
		return nil, r.ctx.Err()
	}
}

func (r *Runtime) probeRealityPost(in Inbound, alpn []byte) ([]int, error) {
	var protocols []string
	if len(alpn) > 0 {
		p := stCursor{data: alpn}
		list := stCursor{data: p.vector(2)}
		for len(list.data) > 0 && list.err == nil {
			protocols = append(protocols, string(list.vector(1)))
		}
		if p.end() != nil || list.end() != nil {
			return nil, errors.New("invalid Reality ALPN probe")
		}
	}
	remote, err := r.shadowHandshakeBackend(*in.TLS.Reality.Handshake)
	if err != nil {
		return nil, err
	}
	defer remote.Close()
	stop := context.AfterFunc(r.ctx, func() { remote.Close() })
	defer stop()
	config := &tls.Config{ServerName: in.TLS.ServerName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: protocols, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}}
	secure, err := independentTLS13(r.ctx, remote, config, TLSOptions{}, "", nil)
	if err != nil {
		return nil, err
	}
	remote.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	var buffer [5 + shadowRecordLimit]byte
	var sizes []int
	total := 0
	for len(sizes) < 16 {
		header := buffer[:5]
		n, err := io.ReadFull(remote, header)
		if n == 0 && (os.IsTimeout(err) || err == io.EOF) {
			return sizes, nil
		}
		if err != nil {
			return nil, err
		}
		size := 5 + (int(header[3])<<8 | int(header[4]))
		if size < 22 || size > 16406 || header[0] != 23 || header[1] != 3 || header[2] != 3 {
			return nil, errors.New("invalid Reality post-handshake cover record")
		}
		if _, err = io.ReadFull(remote, buffer[5:size]); err != nil {
			return nil, err
		}
		kind, _, err := secure.serverApp.open(buffer[:size])
		if err != nil {
			return nil, err
		}
		if kind == 21 {
			return sizes, nil
		}
		if kind != 22 && kind != 23 {
			return nil, errors.New("invalid Reality post-handshake cover content")
		}
		sizes = append(sizes, size)
		total += size
		if total > 65536 {
			return nil, errors.New("Reality post-handshake cover exceeds64KiB")
		}
	}
	return nil, errors.New("excessive Reality post-handshake cover records")
}

func (c *realityConn) writeCoverPost(sizes []int) error {
	for _, size := range sizes {
		record, err := realityPaddedRecord(c.tls.clientApp, 23, nil, size)
		if err != nil {
			return err
		}
		if err = writeAll(c.Conn, record); err != nil {
			return err
		}
	}
	return nil
}
