package native

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func realityRecordPair(t *testing.T, id uint16) (*realityConn, *realityConn) {
	t.Helper()
	suite, err := stSuite(id)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	a.SetDeadline(time.Now().Add(3 * time.Second))
	b.SetDeadline(time.Now().Add(3 * time.Second))
	makeConn := func(raw net.Conn, server bool) *realityConn {
		own, peer := bytes.Repeat([]byte{1}, suite.hash.Size()), bytes.Repeat([]byte{2}, suite.hash.Size())
		if server {
			own, peer = peer, own
		}
		tx, _ := suite.recordCipher(own)
		rx, _ := suite.recordCipher(peer)
		return &realityConn{Conn: raw, server: server, tls: &stTLS13{conn: raw, suite: suite, clientSecret: own, serverSecret: peer, clientApp: tx, serverApp: rx, state: tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}}}
	}
	return makeConn(a, false), makeConn(b, true)
}

func TestRealityRecords(t *testing.T) {
	for _, id := range []uint16{0x1301, 0x1302, 0x1303} {
		t.Run(tls.CipherSuiteName(id), func(t *testing.T) {
			c, s := realityRecordPair(t, id)
			want := bytes.Repeat([]byte("record"), 11000)
			done := make(chan error, 1)
			go func() {
				_, err := io.Copy(s, s)
				if err == nil {
					err = s.CloseWrite()
				}
				done <- err
			}()
			write := make(chan error, 1)
			go func() {
				_, err := c.Write(want)
				if err == nil {
					err = c.CloseWrite()
				}
				write <- err
			}()
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal(len(got), err)
			}
			if err = <-write; err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			if _, err = c.Write([]byte("closed")); !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
		})
	}
}

func TestRealityKeyUpdate(t *testing.T) {
	for _, requested := range []bool{false, true} {
		t.Run(map[bool]string{false: "automatic", true: "requested"}[requested], func(t *testing.T) {
			c, s := realityRecordPair(t, 0x1301)
			if !requested {
				c.tls.clientApp.sequence = 1 << 24
				s.tls.serverApp.sequence = 1 << 24
			}
			go io.Copy(s, s)
			done := make(chan error, 1)
			go func() {
				var err error
				if requested {
					c.writeMu.Lock()
					err = c.send(22, []byte{24, 0, 0, 1, 1})
					if err == nil {
						c.tls.clientSecret = c.tls.suite.expand(c.tls.clientSecret, "traffic upd", nil, c.tls.suite.hash.Size())
						c.tls.clientApp, err = c.tls.suite.recordCipher(c.tls.clientSecret)
					}
					c.writeMu.Unlock()
				}
				if err == nil {
					_, err = c.Write([]byte("updated"))
				}
				done <- err
			}()
			got := make([]byte, 7)
			if _, err := io.ReadFull(c, got); err != nil || string(got) != "updated" {
				t.Fatal(string(got), err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			// Both paths must have rotated the client's application key.
			if bytes.Equal(c.tls.clientSecret, bytes.Repeat([]byte{1}, 32)) {
				t.Fatal("write key was not updated")
			}
		})
	}
}

func TestRealityReadTimeout(t *testing.T) {
	for _, split := range []int{2, 5, 12} {
		c, s := realityRecordPair(t, 0x1301)
		frame, _ := s.tls.clientApp.seal(23, []byte("after-timeout"))
		written := make(chan error, 1)
		go func() { written <- writeAll(s.Conn, frame[:split]) }()
		c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		b := make([]byte, 13)
		if _, err := c.Read(b); !os.IsTimeout(err) {
			t.Fatal(split, err)
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(time.Second))
		go func() { written <- writeAll(s.Conn, frame[split:]) }()
		if _, err := io.ReadFull(c, b); err != nil || string(b) != "after-timeout" {
			t.Fatal(split, string(b), err)
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
	}
}

func TestRealityMalformedRecords(t *testing.T) {
	for _, kind := range []string{"mac", "header", "key-update", "oversized-handshake", "client-ticket", "interleaved"} {
		t.Run(kind, func(t *testing.T) {
			c, s := realityRecordPair(t, 0x1301)
			if kind == "client-ticket" {
				c, s = s, c
			}
			typ, data := byte(23), []byte("payload")
			switch kind {
			case "key-update":
				typ, data = 22, []byte{24, 0, 0, 1, 2}
			case "oversized-handshake":
				typ, data = 22, []byte{4, 1, 0, 1}
			case "client-ticket":
				typ, data = 22, []byte{4, 0, 0, 0}
			case "interleaved":
				typ, data = 22, []byte{4, 0}
			}
			frame, _ := s.tls.clientApp.seal(typ, data)
			if kind == "mac" {
				frame[len(frame)-1] ^= 1
			}
			if kind == "header" {
				frame[1] = 2
			}
			if kind == "interleaved" {
				next, _ := s.tls.clientApp.seal(23, []byte("bad"))
				frame = append(frame, next...)
			}
			go writeAll(s.Conn, frame)
			b := make([]byte, 32)
			_, err := c.Read(b)
			if err == nil || os.IsTimeout(err) {
				t.Fatal("malformed record accepted", err)
			}
			if _, again := c.Read(b); again != err {
				t.Fatal("record error not sticky", err, again)
			}
		})
	}
}

type realityWriteFailure struct {
	net.Conn
	calls atomic.Int32
}

func (c *realityWriteFailure) Write(b []byte) (int, error) {
	c.calls.Add(1)
	return 1, io.ErrClosedPipe
}
func TestRealityWriteFailure(t *testing.T) {
	c, _ := realityRecordPair(t, 0x1301)
	raw := &realityWriteFailure{Conn: c.Conn}
	c.Conn = raw
	_, err := c.Write([]byte("partial"))
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if _, again := c.Write([]byte("again")); again != err || raw.calls.Load() != 1 {
		t.Fatal("partial write retried", again, raw.calls.Load())
	}
}
