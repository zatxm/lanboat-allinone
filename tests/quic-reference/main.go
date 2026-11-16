package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	quic "github.com/quic-go/quic-go"
	"io"
	"os"
	"time"
)

func main() {
	if os.Args[1] == "http-server" {
		httpMain()
		return
	}
	if os.Args[1] == "dns-server" || os.Args[1] == "dns-client" {
		dnsMain()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cfg := &quic.Config{EnableDatagrams: true, MaxIncomingStreams: 128, MaxIncomingUniStreams: 16}
	if os.Args[1] == "v2-server" || os.Args[1] == "v2-client" {
		cfg.Versions = []quic.Version{quic.Version2}
	}
	if os.Args[1] == "server" || os.Args[1] == "v2-server" {
		cert, e := tls.LoadX509KeyPair(os.Args[3], os.Args[4])
		check(e)
		l, e := quic.ListenAddr(os.Args[2], &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"lanboat-quic-test"}}, cfg)
		check(e)
		fmt.Println("READY")
		c, e := l.Accept(ctx)
		check(e)
		go func() {
			for {
				d, e := c.ReceiveDatagram(ctx)
				if e != nil {
					return
				}
				check(c.SendDatagram(d))
			}
		}()
		for {
			s, e := c.AcceptStream(ctx)
			check(e)
			go func() { io.Copy(s, s); s.Close() }()
		}
	} else {
		tlsConfig := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"lanboat-quic-test"}}
		if os.Args[1] == "sniff-client" || os.Args[1] == "v2-client" {
			tlsConfig.ServerName = "fragment.test"
			tlsConfig.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
			cfg.InitialPacketSize = 1200
		}
		c, e := quic.DialAddr(ctx, os.Args[2], tlsConfig, cfg)
		check(e)
		defer c.CloseWithError(0, "")
		for i := 0; i < 20; i++ {
			s, e := c.OpenStreamSync(ctx)
			check(e)
			want := bytes.Repeat([]byte{byte(i)}, 300000)
			done := make(chan error, 1)
			go func() {
				_, e := s.Write(want)
				if e == nil {
					e = s.Close()
				}
				done <- e
			}()
			got, e := io.ReadAll(s)
			check(e)
			check(<-done)
			if !bytes.Equal(got, want) {
				panic("bad echo")
			}
		}
		check(c.SendDatagram([]byte("datagram")))
		d, e := c.ReceiveDatagram(ctx)
		check(e)
		if string(d) != "datagram" {
			panic("bad datagram")
		}
		fmt.Println("PASS")
	}
}
func check(e error) {
	if e != nil {
		panic(e)
	}
}
