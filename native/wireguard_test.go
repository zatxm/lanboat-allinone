package native

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func wgTestKey(t *testing.T) (string, string) {
	t.Helper()
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

func TestWireGuardRetryFreshWithCookie(t *testing.T) {
	r := newTestRuntime(t, Config{})
	client, _ := wgTestKey(t)
	server, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	p, e := newWGPeer(r, []string{client}, base64.StdEncoding.EncodeToString(server.PublicKey().Bytes()), "", []string{"192.0.2.1/32"}, nil, "", 1280, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer p.close()
	remote := streamAddr("retry-test")
	p.remote = remote
	var first []byte
	cookie := bytes.Repeat([]byte{0x61}, 16)
	var result error
	p.sender = func(b []byte, _ net.Addr) error {
		if binary.LittleEndian.Uint32(b) != 1 {
			return nil
		}
		if first == nil {
			first = bytes.Clone(b)
			key := blake2s(append([]byte("cookie--"), server.PublicKey().Bytes()...), nil, 32)
			a, _ := newChaChaAEAD(key, true)
			nonce := bytes.Repeat([]byte{7}, 24)
			reply := binary.LittleEndian.AppendUint32(nil, 3)
			reply = binary.LittleEndian.AppendUint32(reply, binary.LittleEndian.Uint32(b[4:]))
			reply = append(reply, nonce...)
			reply = a.Seal(reply, nonce, cookie, b[116:132])
			p.handle(reply, remote)
			return nil
		}
		if bytes.Equal(first[4:8], b[4:8]) || bytes.Equal(first[8:40], b[8:40]) || !bytes.Equal(b[132:], blake2s(b[:132], cookie, 16)) {
			result = errors.New("retry did not refresh index/ephemeral or retain cookie")
			return result
		}
		pub, stamp, ck, h, err := wgReadInitiation(server, b)
		if err != nil {
			return err
		}
		_, oldStamp, _, _, err := wgReadInitiation(server, first)
		if err != nil {
			return err
		}
		if bytes.Compare(stamp, oldStamp) <= 0 {
			result = errors.New("retry reused timestamp")
			return result
		}
		reply, _, err := wgRespond(server, pub, make([]byte, 32), ck, h, b)
		if err != nil {
			return err
		}
		p.handle(reply, remote)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if e = p.ensure(ctx); e != nil || result != nil {
		t.Fatal(e, result)
	}
}
func TestWireGuardNoiseAndReplay(t *testing.T) {
	for _, preshared := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "psk"}[preshared], func(t *testing.T) {
			a, _ := ecdh.X25519().GenerateKey(rand.Reader)
			b, _ := ecdh.X25519().GenerateKey(rand.Reader)
			psk := make([]byte, 32)
			if preshared {
				rand.Read(psk)
			}
			s, e := wgInitiate(a, b.PublicKey().Bytes(), psk)
			if e != nil {
				t.Fatal(e)
			}
			pub, stamp, ck, h, e := wgReadInitiation(b, s.message)
			if e != nil || !bytes.Equal(pub, a.PublicKey().Bytes()) || len(stamp) != 12 {
				t.Fatal(e)
			}
			reply, server, e := wgRespond(b, pub, psk, ck, h, s.message)
			if e != nil {
				t.Fatal(e)
			}
			client, e := s.response(reply)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(client.send, server.receive) || !bytes.Equal(client.receive, server.send) {
				t.Fatal("transport keys differ")
			}
			packet := makeUDPPacket(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1"), 30000, 53, []byte("wireguard"))
			sealed, e := client.seal(packet)
			if e != nil {
				t.Fatal(e)
			}
			tampered := append([]byte{}, sealed...)
			tampered[len(tampered)-1] ^= 1
			if _, e = server.open(tampered); e == nil {
				t.Fatal("tampered packet accepted")
			}
			plain, e := server.open(sealed)
			if e != nil || !bytes.Equal(plain, packet) {
				t.Fatal(e)
			}
			if _, e = server.open(sealed); e == nil {
				t.Fatal("replayed packet accepted")
			}
			for range 8300 {
				b, e := client.seal(nil)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = server.open(b); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = server.open(sealed); e == nil {
				t.Fatal("stale packet accepted")
			}
			s.message[100] ^= 1
			if _, _, _, _, e = wgReadInitiation(b, s.message); e == nil {
				t.Fatal("tampered initiation accepted")
			}
		})
	}
}
func TestWireGuardIndependent(t *testing.T) {
	serverKey, serverPub := wgTestKey(t)
	clientKey, clientPub := wgTestKey(t)
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "ipv4", true: "ipv6"}[ipv6], func(t *testing.T) {
			local, allowed := "10.20.0.2/32", "10.20.0.2/32"
			if ipv6 {
				local, allowed = "fd20::2/128", "fd20::2/128"
			}
			in := Inbound{Type: "wireguard", Tag: "server", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{serverKey}}, WireGuardOptions: WireGuardOptions{Peers: []WireGuardPeer{{PublicKey: clientPub, AllowedIPs: []string{allowed}}}}}
			fragment := true
			in.ListenOptions = ListenOptions{BindInterface: "lo", ReuseAddr: true, UDPFragment: &fragment}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Password, out.Username, out.UUID = "", "", ""
			out.PrivateKey = []string{clientKey}
			out.WireGuardOptions = WireGuardOptions{PublicKey: serverPub, LocalAddress: []string{local}}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			if !ipv6 {
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 511, 4096, 60000})
			} else {
				target, e := net.Listen("tcp6", "[::1]:0")
				if e != nil {
					t.Fatal(e)
				}
				defer target.Close()
				go func() {
					c, e := target.Accept()
					if e == nil {
						defer c.Close()
						io.Copy(c, c)
					}
				}()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				c, e := client.Dial(ctx, "tcp", target.Addr().String())
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				want := bytes.Repeat([]byte("v6"), 40000)
				go writeAll(c, want)
				got := make([]byte, len(want))
				if _, e = io.ReadFull(c, got); e != nil || !bytes.Equal(want, got) {
					t.Fatal(e)
				}
			}
		})
	}
}
