package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	quic "github.com/refraction-networking/uquic"
	tls "github.com/refraction-networking/utls"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: quic-client-reference chrome115|chrome146|firefox116 address")
	}
	ids := map[string]quic.QUICID{"chrome115": quic.QUICChrome_115, "chrome146": quic.QUICChrome_146, "firefox116": quic.QUICFirefox_116}
	id, ok := ids[os.Args[1]]
	if !ok {
		panic("unknown profile")
	}
	spec, e := quic.QUICID2Spec(id)
	if e != nil {
		panic(e)
	}
	peer, e := net.ResolveUDPAddr("udp", os.Args[2])
	if e != nil {
		panic(e)
	}
	pc, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		panic(e)
	}
	defer pc.Close()
	transport := &quic.UTransport{Transport: &quic.Transport{Conn: pc}, QUICSpec: &spec}
	defer transport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, e := transport.Dial(ctx, peer, &tls.Config{ServerName: "reference.quic.test", InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{})
	if e == nil {
		conn.CloseWithError(0, "")
	}
	fmt.Println(os.Args[1], e)
}
