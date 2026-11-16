package native

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

func TestSniffFragmentedQUICReference(t *testing.T) {
	reference := os.Getenv("LANBOAT_TEST_QUIC")
	if reference == "" {
		t.Skip("LANBOAT_TEST_QUIC not set")
	}
	listener := testQUICListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	served := make(chan error, 1)
	go func() {
		server, e := listener.Accept(ctx)
		if e != nil {
			served <- e
			return
		}
		defer server.Close()
		go func() {
			for {
				b, e := server.ReceiveDatagram(ctx)
				if e != nil {
					return
				}
				if e = server.SendDatagram(ctx, b); e != nil {
					return
				}
			}
		}()
		for {
			stream, e := server.AcceptStream(ctx)
			if e != nil {
				served <- e
				return
			}
			go func() { defer stream.Close(); io.Copy(stream, stream); stream.CloseWrite() }()
		}
	}()
	ingress, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ingress.Close()
	host, port := splitTestAddress(t, listener.packet.LocalAddr().String())
	r := newTestRuntime(t, Config{Route: Route{Rules: []Rule{{Action: "sniff", Sniffer: []string{"quic"}}, {Domain: []string{"fragment.test"}, Client: []string{"quic-go"}, Action: "route-options", OverrideAddress: host, OverridePort: port}, {Domain: []string{"fragment.test"}, Client: []string{"quic-go"}, Outbound: "direct"}, {Action: "reject"}}}})
	c, e := r.Dial(ctx, "udp", "192.0.2.9:443")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(12 * time.Second))
	firstAddr := make(chan net.Addr, 1)
	upDone := make(chan error, 1)
	downDone := make(chan error, 1)
	var held atomic.Int64
	go func() {
		b := make([]byte, 65535)
		first := true
		for {
			n, addr, e := ingress.ReadFrom(b)
			if e != nil {
				upDone <- e
				return
			}
			if first {
				firstAddr <- addr
				first = false
			}
			select {
			case <-c.(*routeConn).ready:
			default:
				held.Add(1)
			}
			if _, e = c.Write(b[:n]); e != nil {
				upDone <- e
				return
			}
		}
	}()
	go func() {
		select {
		case addr := <-firstAddr:
			b := make([]byte, 65535)
			for {
				n, e := c.Read(b)
				if e != nil {
					downDone <- e
					return
				}
				if _, e = ingress.WriteTo(b[:n], addr); e != nil {
					downDone <- e
					return
				}
			}
		case <-ctx.Done():
			downDone <- ctx.Err()
		}
	}()
	cmd := exec.CommandContext(ctx, reference, "sniff-client", ingress.LocalAddr().String())
	output, err := cmd.CombinedOutput()
	ingress.Close()
	c.Close()
	cancel()
	listener.Close()
	<-upDone
	<-downDone
	<-served
	if err != nil || !bytes.Contains(output, []byte("PASS")) {
		t.Fatal(err, string(output))
	}
	if held.Load() < 2 {
		t.Fatal("reference ClientHello did not span datagrams", held.Load())
	}
	t.Log(fmt.Sprintf("quic-go reference completed20streams and datagram echo;held%d Initial datagrams", held.Load()))
}
