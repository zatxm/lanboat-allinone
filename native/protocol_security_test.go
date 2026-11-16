package native

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

type memoryNetConn struct {
	io.Reader
	io.Writer
}

func (c memoryNetConn) Close() error                     { return nil }
func (c memoryNetConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c memoryNetConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c memoryNetConn) SetDeadline(time.Time) error      { return nil }
func (c memoryNetConn) SetReadDeadline(time.Time) error  { return nil }
func (c memoryNetConn) SetWriteDeadline(time.Time) error { return nil }
func readerConn(b []byte) net.Conn                       { return memoryNetConn{bytes.NewReader(b), io.Discard} }

func TestSnellReplayAndTamper(t *testing.T) {
	for _, version := range []string{"1", "2", "3", "4", "5"} {
		t.Run(version, func(t *testing.T) {
			var wire bytes.Buffer
			client := newSnellConn(memoryNetConn{bytes.NewReader(nil), &wire}, "private", version, &replayWindow{})
			if err := writeAll(client, []byte("authenticated record")); err != nil {
				t.Fatal(err)
			}
			replay := &replayWindow{}
			first := newSnellConn(readerConn(wire.Bytes()), "private", version, replay)
			if _, err := first.readRecord(); err != nil {
				t.Fatal(err)
			}
			duplicate := newSnellConn(readerConn(wire.Bytes()), "private", version, replay)
			if _, err := duplicate.readRecord(); err == nil {
				t.Fatal("Snell replay accepted")
			}
			corrupt := append([]byte{}, wire.Bytes()...)
			corrupt[len(corrupt)-1] ^= 1
			if _, err := newSnellConn(readerConn(corrupt), "private", version, &replayWindow{}).readRecord(); err == nil {
				t.Fatal("Snell tamper accepted")
			}
		})
	}
}
func TestSSRAuthenticationReplayAndUDPIntegrity(t *testing.T) {
	key, _ := newSSKey("aes-256-cfb", "private")
	for _, protocol := range SSRProtocols() {
		if protocol == "origin" || protocol == "verify_sha1" || protocol == "verify_deflate" {
			continue
		}
		t.Run(protocol, func(t *testing.T) {
			var wire bytes.Buffer
			client, err := ssrClient(memoryNetConn{bytes.NewReader(nil), &wire}, Outbound{Protocol: protocol}, key)
			if err != nil {
				t.Fatal(err)
			}
			address, _ := encodeAddress("example.com:443")
			if err := writeAll(client, address); err != nil {
				t.Fatal(err)
			}
			replay := &replayWindow{}
			server, err := ssrAccept(readerConn(wire.Bytes()), Inbound{Protocol: protocol}, key, replay)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := readAddress(server); err != nil || got != "example.com:443" {
				t.Fatal(got, err)
			}
			if _, err := ssrAccept(readerConn(wire.Bytes()), Inbound{Protocol: protocol}, key, replay); err == nil {
				t.Fatal("SSR authentication replay accepted")
			}
			corrupt := append([]byte{}, wire.Bytes()...)
			corrupt[17] ^= 1
			server, err = ssrAccept(readerConn(corrupt), Inbound{Protocol: protocol}, key, &replayWindow{})
			if err == nil {
				_, err = readAddress(server)
			}
			if err == nil {
				t.Fatal("SSR authentication tamper accepted")
			}
			if protocol == "auth_aes128_md5" || protocol == "auth_aes128_sha1" {
				codec, _ := newSSRDatagrams(key, protocol, "")
				packet, err := codec.seal(append(address, []byte("UDP integrity")...), false)
				if err != nil {
					t.Fatal(err)
				}
				packet[len(packet)-1] ^= 1
				if _, err := codec.open(packet, true); err == nil {
					t.Fatal("SSR UDP tamper accepted")
				}
			}
		})
	}
}
func FuzzSSRAuthentication(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0}, byte(0))
	f.Add(bytes.Repeat([]byte{1}, 64), byte(1))
	key, _ := newSSKey("aes-256-cfb", "private")
	protocols := SSRProtocols()
	f.Fuzz(func(t *testing.T, data []byte, which byte) {
		c, err := ssrAccept(readerConn(data), Inbound{Protocol: protocols[int(which)%len(protocols)]}, key, &replayWindow{})
		if err == nil {
			_, _ = readSSRAddress(c)
		}
	})
}
func FuzzSnellRecord(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0}, 64), byte(4))
	f.Fuzz(func(t *testing.T, data []byte, version byte) {
		_, _ = newSnellConn(readerConn(data), "private", string([]byte{'1' + version%5}), &replayWindow{}).readRecord()
	})
}
