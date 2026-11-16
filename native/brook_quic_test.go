package native

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func brookQUICInbound(t *testing.T) Inbound {
	in := brookInbound(t, "tcp")
	in.Transport = Transport{Type: "quic"}
	in.TLS = certificate(t)
	return in
}

func TestBrookQUICIndependent(t *testing.T) {
	for _, stream := range []bool{false, true} {
		name := "datagram"
		if stream {
			name = "stream"
		}
		t.Run(name, func(t *testing.T) {
			in := brookQUICInbound(t)
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := brookOutbound(t, in, s.Address(in.Tag))
			out.UDPOverStream = stream
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, c)
			sizes := []int{0, 1, 511, 1158}
			if stream {
				sizes = append(sizes, 4096, 60000, 65440)
			}
			assertUDPSizes(t, c, sizes)
			ipv6Sizes := []int{0, 1, 511, 1146}
			if stream {
				ipv6Sizes = append(ipv6Sizes, 60000)
			}
			assertUDPAddress(t, c, ipv6Sizes, masqueEcho(t, "udp", "[::1]:0"))
			c.resetNetworkTransports()
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{1, 511})
		})
	}
}

func TestBrookQUICReference(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, side := range []string{"client", "server"} {
			mode := "datagram"
			if stream {
				mode = "stream"
			}
			t.Run(mode+"/"+side, func(t *testing.T) {
				in := brookQUICInbound(t)
				sizes := []int{1, 511, 1158}
				if stream {
					sizes = append(sizes, 4096, 60000)
				}
				if side == "server" {
					s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					query := url.Values{"quicserver": {"quic://" + s.Address(in.Tag)}, "password": {in.Password}, "insecure": {"true"}}
					if stream {
						query.Set("udpoverstream", "true")
					}
					link := "brook://quicserver?" + query.Encode()
					assertBrookReferenceServer(t, link, sizes...)
					address := portAddress("127.0.0.1", unusedPort(t))
					startBrookReference(t, "relayoverbrook", "--link", link, "--from", address, "--to", masqueEcho(t, "udp", "[::1]:0"))
					waitPort(t, address)
					direct := newTestRuntime(t, Config{})
					assertUDPAddress(t, direct, []int{1, 511, 1146}, address)
					return
				}
				in.ListenPort = unusedPort(t)
				address := portAddress(in.Listen, in.ListenPort)
				dir := t.TempDir()
				cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
				if err := os.WriteFile(cert, []byte(strings.Join(in.TLS.Certificate, "\n")), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(key, []byte(strings.Join(in.TLS.Key, "\n")), 0600); err != nil {
					t.Fatal(err)
				}
				startBrookReference(t, "quicserver", "--domainaddress", address, "--password", in.Password, "--cert", cert, "--certkey", key)
				waitPacketPort(t, address)
				out := brookOutbound(t, in, address)
				out.UDPOverStream = stream
				c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, c)
				assertUDPSizes(t, c, sizes)
				assertUDPAddress(t, c, []int{1, 511, 1146}, masqueEcho(t, "udp", "[::1]:0"))
			})
		}
	}
}

func TestBrookQUICDatagramLifecycle(t *testing.T) {
	in := brookQUICInbound(t)
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := brookOutbound(t, in, s.Address(in.Tag))
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	target := echoUDP(t)
	first, err := c.Dial(context.Background(), "udp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := c.Dial(context.Background(), "udp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	for _, conn := range []net.Conn{first, second} {
		conn.SetDeadline(time.Now().Add(3 * time.Second))
	}
	for i, conn := range []net.Conn{first, second} {
		want := bytes.Repeat([]byte{byte(i + 1)}, 511)
		if _, err := conn.Write(want); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 1000)
		n, err := conn.Read(got)
		if err != nil || !bytes.Equal(got[:n], want) {
			t.Fatal("UDP association crossed", err)
		}
	}
	if _, err := first.Write(make([]byte, 1159)); err == nil || !strings.Contains(err.Error(), "udp_over_stream") {
		t.Fatal("oversize datagram accepted", err)
	}
	first.SetReadDeadline(time.Now().Add(-time.Second))
	if _, err := first.Read(make([]byte, 100)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("expired read", err)
	}
	first.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := first.Write([]byte("expired")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("expired write", err)
	}
	first.SetDeadline(time.Now().Add(time.Second))
	if _, err := first.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if n, err := first.Read(make([]byte, 1)); err != io.ErrShortBuffer || n != 0 {
		t.Fatal("short buffer", n, err)
	}
	first.SetDeadline(time.Time{})
	done := make(chan error, 1)
	go func() { _, err := first.Read(make([]byte, 10)); done <- err }()
	first.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("updated read deadline did not unblock")
	}
	first.SetDeadline(time.Time{})
	go func() { _, err := second.Read(make([]byte, 10)); done <- err }()
	c.resetNetworkTransports()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("reset kept old packet session")
		}
	case <-time.After(time.Second):
		t.Fatal("reset did not unblock")
	}
	assertUDPSizes(t, c, []int{1})
	if len(c.quicTransports[out.Tag].packets) != 0 {
		t.Fatal("closed UDP association retained")
	}
}

func TestBrookQUICConcurrent(t *testing.T) {
	in := brookQUICInbound(t)
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := brookOutbound(t, in, s.Address(in.Tag))
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() { assertTCP(t, c); assertUDPSizes(t, c, []int{1, 511}) })
	}
	workers.Wait()
	conn, err := c.Dial(context.Background(), "udp", echoUDP(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() { c.Close(); s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runtime close retained QUIC workers")
	}
}
