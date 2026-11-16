//go:build linux

package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestTrustTunnelICMPNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_TRUST_CHILD") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^TestTrustTunnelICMPNamespace$", "-test.v", "-test.timeout=35s")
		cmd.Env = append(os.Environ(), "LANBOAT_TRUST_CHILD=1")
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("TrustTunnel ICMP namespace: %v\n%s", e, out)
		}
		t.Log(string(out))
		return
	}
	lo, e := net.InterfaceByName("lo")
	if e != nil {
		t.Fatal(e)
	}
	if e = configureLink(lo.Index, 65536); e != nil {
		t.Fatal(e)
	}
	if out, e := exec.Command("ip", "-6", "address", "add", "fd42::1/128", "dev", "lo").CombinedOutput(); e != nil {
		t.Fatalf("namespace IPv6 address: %v %s", e, out)
	}
	for _, version := range []int{2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			_, client := trustPair(t, version)
			if os.Getenv("LANBOAT_TEST_TRUST_SERVER") != "" {
				f := newMutualTLSFixture(t)
				in := Inbound{Type: "trusttunnel", Tag: "server", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
				startTrustEndpoint(t, f, in, true)
				out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
				out.TLS = f.client()
				out.HTTPVersion = version
				reference := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				for _, address := range []string{"127.0.0.1", "fd42::1"} {
					kind := byte(8)
					if address == "fd42::1" {
						kind = 128
					}
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					response, e := reference.trustClients["proxy"].exchangeICMP(ctx, netip.MustParseAddr(address), []byte{kind, 0, 0, 0, 0, 8, 0, 7, 1, 2, 3}, 63)
					cancel()
					if e != nil || response.source.String() != address {
						t.Fatal("official ICMP", address, response, e)
					}
				}
			}
			for _, address := range []string{"127.0.0.1", "::1"} {
				destination := netip.MustParseAddr(address)
				kind, replyKind := byte(8), byte(0)
				if destination.Is6() {
					kind, replyKind = 128, 129
				}
				request := append([]byte{kind, 0, 0, 0, 0, 17, 0, 25}, bytes.Repeat([]byte("icmp"), 32)...)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				response, e := client.trustClients["proxy"].exchangeICMP(ctx, destination, request, 63)
				cancel()
				if e != nil || response.source != destination || len(response.data) != len(request) || response.data[0] != replyKind || !bytes.Equal(request[4:], response.data[4:]) {
					t.Fatal("raw echo", address, response, e)
				}
			}
			// Exercise the TUN packet adapter with actual remote Echo and valid checksum.
			source, destination := netip.MustParseAddr("172.19.0.2"), netip.MustParseAddr("127.0.0.1")
			segment := []byte{8, 0, 0, 0, 0, 7, 0, 9, 1, 2, 3}
			binary.BigEndian.PutUint16(segment[2:], checksum(segment, 0))
			p, e := parseTunPacket(makeWGIP(source, destination, 1, segment))
			if e != nil {
				t.Fatal(e)
			}
			var result []byte
			stack := &wgIPStack{peer: &ipEndpoint{runtime: client, inbound: "tun", sendIP: func(b []byte) error { result = append([]byte{}, b...); return nil }}}
			stack.forwardICMP(p)
			reply, e := parseTunPacket(result)
			if e != nil || reply.source != destination || reply.destination != source || reply.data[reply.header] != 0 || checksum(reply.data[reply.header:], 0) != 0 {
				t.Fatal("TUN Echo", reply, e)
			}
		})
	}
}
