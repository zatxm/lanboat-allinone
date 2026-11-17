package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

func TestQUICBBRReceiveBurstLoss(t *testing.T) {
	options := quicOptions{bbr: true}
	listener := testQUICListener(t, options)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := net.Dial("udp", listener.packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	// Exercise bounded socket bursts without changing production buffer sizes.
	if err = raw.(*net.UDPConn).SetReadBuffer(4096); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	client, err := dialQUIC(ctx, context.Background(), raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"lanboat-quic-test"}}, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		s, e := server.AcceptStream(ctx)
		if e == nil {
			defer s.Close()
			io.Copy(s, s)
			s.CloseWrite()
		}
	}()
	s, err := client.OpenStream(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	s.SetDeadline(time.Now().Add(5 * time.Second))
	want := bytes.Repeat([]byte("burst-loss-recovery"), 15000)
	written := make(chan error, 1)
	go func() {
		e := writeAll(s, want)
		if e == nil {
			e = s.CloseWrite()
		}
		written <- e
	}()
	got, err := io.ReadAll(s)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("burst-loss transfer", len(got), err)
	}
	if err = <-written; err != nil {
		t.Fatal(err)
	}
}
