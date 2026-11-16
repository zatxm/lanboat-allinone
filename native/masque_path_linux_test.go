//go:build linux

package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestMasquePathReferenceNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_MASQUE_PATH_CHILD") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v", "-test.timeout=60s")
		cmd.Env = append(os.Environ(), "LANBOAT_MASQUE_PATH_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated path probe:%v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	loop, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = configureLink(loop.Index, 65536); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("ip", "addr", "add", "192.0.2.1/32", "dev", "lo").CombinedOutput(); err != nil {
		t.Fatalf("fixture address:%v %s", err, out)
	}
	t.Run("connect-ip-go-kernel", func(t *testing.T) {
		in := Inbound{Type: "masque", Tag: "server", Listen: "127.0.0.1", ListenPort: unusedPort(t), TLS: certificate(t)}
		address := portAddress("127.0.0.1", in.ListenPort)
		dir := t.TempDir()
		cert := trustReferenceFile(t, dir, "cert.pem", strings.Join(in.TLS.Certificate, "\n"))
		key := trustReferenceFile(t, dir, "key.pem", strings.Join(in.TLS.Key, "\n"))
		masqueReferenceProcess(t, "server-mtu", address, cert, key)
		out := testOutbound(t, in, address)
		out.Username, out.Password = "client", "private"
		client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		p, err := client.masqueClients["proxy"].ipSession(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Log("initial datagram limit", p.flow.session.datagramLimit(), "addresses", p.addresses())

		status, err := client.ProbeMasquePath(ctx, "proxy", netip.MustParseAddr("fd44::1"))
		if err != nil || status.MTU != 1280 || !status.DatagramVerified {
			t.Fatal(status, err)
		}
		assertUDPAddress(t, client, []int{1, 511, 1232}, masqueEcho(t, "udp", "[fd44::1]:0"))
	})
	t.Run("connect-ip-go-client", func(t *testing.T) {
		server := masqueEndpointRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": 3, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "users": []User{{Username: "client", Password: "private"}}, "tls": certificate(t)})
		writer, reader := masqueReferenceProcess(t, "client-ip-mtu", server.Address("server"))
		for _, destination := range []netip.Addr{masqueAllNodes, netip.MustParseAddr("fd44::1")} {
			segment := bytes.Repeat([]byte{73}, 1240)
			segment[0], segment[1] = 128, 0
			clear(segment[2:4])
			peer := netip.MustParseAddr("fd44::2")
			packet := makeWGIP(peer, destination, 58, segment)
			ip, _ := parseTunPacket(packet)
			binary.BigEndian.PutUint16(packet[42:], transportChecksum(ip, packet[40:]))
			wire := binary.BigEndian.AppendUint16(nil, uint16(len(packet)))
			wire = append(wire, packet...)
			if err := writeAll(writer, wire); err != nil {
				t.Fatal(err)
			}
			result := make(chan []byte, 1)
			go func() {
				var header [2]byte
				if _, err := io.ReadFull(reader, header[:]); err != nil {
					result <- nil
					return
				}
				reply := make([]byte, int(binary.BigEndian.Uint16(header[:])))
				if _, err := io.ReadFull(reader, reply); err != nil {
					reply = nil
				}
				result <- reply
			}()
			select {
			case reply := <-result:
				p, err := parseTunPacket(reply)
				if err != nil || len(reply) != 1280 || p.source != netip.MustParseAddr("fd44::1") || p.destination != peer || reply[40] != 129 || transportChecksum(p, reply[40:]) != 0 || !bytes.Equal(packet[44:], reply[44:]) {
					t.Fatal("independent client received invalid or missing Echo reply", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("independent client did not receive datagram Echo reply", destination)
			}
		}
	})

	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			port := unusedPort(t)
			address := portAddress("127.0.0.1", port)
			ep := map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "listen_port": port, "version": []int{version}, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "tls": certificate(t), "users": []User{{Username: "client", Password: "private"}}}
			if version == 3 {
				ep["initial_packet_size"] = 1400
			}
			readyPort := unusedPort(t)
			ready := portAddress("127.0.0.1", readyPort)
			masqueOfficial(t, map[string]any{"endpoints": []any{ep}, "inbounds": []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": readyPort}}, "outbounds": []Outbound{{Type: "direct", Tag: "direct"}}, "route": Route{Final: "direct"}}, ready)
			host, p, _ := net.SplitHostPort(address)
			n, _ := shadowPort(p)
			client := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "masque", Tag: "proxy", Server: host, ServerPort: n, Username: "client", Password: "private", HTTPVersion: version, TLS: TLSOptions{Enabled: true, Insecure: true}, MasqueOptions: MasqueOptions{DisableVersionFallback: true}}}})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			status, err := client.ProbeMasquePath(ctx, "proxy", netip.MustParseAddr("fd44::1"))
			if err != nil || status.MTU != 1280 || status.DatagramVerified != (version == 3) {
				t.Fatal(status, err)
			}
			conn, err := client.Dial(ctx, "tcp", masqueEcho(t, "tcp", "192.0.2.1:0"))
			if err != nil {
				t.Fatal(err)
			}
			wgRoundtripTCP(t, conn)
		})
	}
}
