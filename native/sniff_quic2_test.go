package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sniffTestQUIC2(t *testing.T, id []byte, pn, offset uint64, hello []byte) []byte {
	t.Helper()
	_, key, err := quicInitialKeysVersion(id, false, quicVersion2)
	if err != nil {
		t.Fatal(err)
	}
	frame := append(quicVar(quicVar([]byte{6}, offset), uint64(len(hello))), hello...)
	header := binary.BigEndian.AppendUint32([]byte{0xd3}, quicVersion2)
	header = append(append(header, byte(len(id))), id...)
	header = append(header, 0, 0)
	header = quicVar(header, uint64(4+len(frame)+key.aead.Overhead()))
	pnOffset := len(header)
	header = binary.BigEndian.AppendUint32(header, uint32(pn))
	wire := key.aead.Seal(header, key.nonce(pn), frame, header)
	mask := key.mask(wire[pnOffset+4:])
	wire[0] ^= mask[0] & 15
	for i := range 4 {
		wire[pnOffset+i] ^= mask[i+1]
	}
	return wire
}

func TestSniffQUIC2RFC9369(t *testing.T) {
	wire, err := os.ReadFile("testdata/quic-v2-client-initial.bin")
	if err != nil {
		t.Fatal(err)
	}
	host, ok, more := sniffQUICData(wire)
	if host != "example.com" || !ok || more {
		t.Fatal("RFC9369 client Initial", host, ok, more)
	}
	if _, err = parseQUICHeader(wire); err == nil {
		t.Fatal("QUICv1 endpoint accepted QUICv2 without negotiation")
	}
	for _, offset := range []int{0, 1, 17, 200, len(wire) - 1} {
		bad := bytes.Clone(wire)
		bad[offset] ^= 1
		if _, ok, more := sniffQUICData(bad); ok || more {
			t.Fatal("tampered Initial accepted", offset)
		}
	}
	for n := range len(wire) {
		if _, ok, more := sniffQUICData(wire[:n]); ok || more {
			t.Fatal("truncated datagram accepted", n)
		}
	}
}

func TestSniffQUIC2Reassembly(t *testing.T) {
	hello := sniffTestHello(t)
	id := []byte("12345678")
	cut := len(hello) / 2
	a := sniffTestQUIC2(t, id, 0, 0, hello[:cut])
	b := sniffTestQUIC2(t, id, 1, uint64(cut), hello[cut:])
	for _, packets := range [][][]byte{{a, b}, {b, a}, {a, a, b}} {
		wire := bytes.Join(packets, nil)
		if p, h := sniffPacket("udp", wire, []string{"quic"}); p != "quic" || h != "fragment.test" {
			t.Fatal(p, h)
		}
	}
	if !sniffNeedsMore("udp", a, nil) || !sniffNeedsMore("udp", b, nil) {
		t.Fatal("QUICv2 CRYPTO fragments were not retained")
	}
	for _, tail := range [][]byte{
		sniffTestQUIC2(t, id, 2, 0, bytes.Repeat([]byte{9}, cut)),
		sniffTestQUIC2(t, []byte("87654321"), 1, uint64(cut), hello[cut:]),
		sniffTestQUIC(t, id, 1, uint64(cut), hello[cut:]),
		sniffTestQUIC2(t, id, 2, sniffLimit, []byte{1}),
	} {
		if _, ok, more := sniffQUICData(append(bytes.Clone(a), tail...)); ok || more {
			t.Fatal("mixed or conflicting QUICv2 Initial accepted")
		}
	}
}

func TestSniffQUIC2Reference(t *testing.T) {
	reference := os.Getenv("LANBOAT_TEST_QUIC")
	if reference == "" {
		t.Skip("LANBOAT_TEST_QUIC required for QUICv2 reference traffic")
	}
	p, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := p.LocalAddr().String()
	p.Close()
	cert, dir := certificate(t), t.TempDir()
	cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err = os.WriteFile(cp, []byte(strings.Join(cert.Certificate, "\n")), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(kp, []byte(strings.Join(cert.Key, "\n")), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	server := exec.CommandContext(ctx, reference, "v2-server", address, cp, kp)
	pipe, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	server.Stderr = os.Stderr
	if err = server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { server.Process.Kill(); server.Wait() }()
	if !bufio.NewScanner(pipe).Scan() {
		t.Fatal("QUICv2 server not ready")
	}
	host, port := splitTestAddress(t, address)
	r := newTestRuntime(t, Config{Route: Route{Rules: []Rule{
		{Action: "sniff", Sniffer: []string{"quic"}},
		{Domain: []string{"fragment.test"}, Action: "route-options", OverrideAddress: host, OverridePort: port},
		{Domain: []string{"fragment.test"}, Outbound: "direct"}, {Action: "reject"},
	}}})
	c, err := r.Dial(ctx, "udp", "192.0.2.9:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	ingress, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ingress.Close()
	peer, up, down := make(chan net.Addr, 1), make(chan int, 1), make(chan struct{})
	go func() {
		b, held, first := make([]byte, 65535), 0, true
		defer func() { up <- held }()
		for {
			n, addr, err := ingress.ReadFrom(b)
			if err != nil {
				return
			}
			if first {
				if n < 5 || binary.BigEndian.Uint32(b[1:5]) != quicVersion2 {
					return
				}
				peer <- addr
				first = false
			}
			select {
			case <-c.(*routeConn).ready:
			default:
				held++
			}
			if _, err = c.Write(b[:n]); err != nil {
				return
			}
		}
	}()
	go func() {
		defer close(down)
		var addr net.Addr
		select {
		case addr = <-peer:
		case <-ctx.Done():
			return
		}
		b := make([]byte, 65535)
		for {
			n, err := c.Read(b)
			if err != nil {
				return
			}
			if _, err = ingress.WriteTo(b[:n], addr); err != nil {
				return
			}
		}
	}()
	output, err := exec.CommandContext(ctx, reference, "v2-client", ingress.LocalAddr().String()).CombinedOutput()
	ingress.Close()
	c.Close()
	cancel()
	held := <-up
	<-down
	if err != nil || !bytes.Contains(output, []byte("PASS")) {
		t.Fatal(err, string(output))
	}
	if held < 2 {
		t.Fatal("reference ClientHello did not span datagrams", held)
	}
	t.Logf("QUICv2:20 streams(6MB) plus datagram echo;held%d Initial datagrams", held)
}
