package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	tls "github.com/refraction-networking/utls"
)

type capture struct{ bytes.Buffer }

func (*capture) Read([]byte) (int, error)         { return 0, fmt.Errorf("capture complete") }
func (*capture) Close() error                    { return nil }
func (*capture) LocalAddr() net.Addr             { return &net.TCPAddr{} }
func (*capture) RemoteAddr() net.Addr            { return &net.TCPAddr{} }
func (*capture) SetDeadline(time.Time) error      { return nil }
func (*capture) SetReadDeadline(time.Time) error  { return nil }
func (*capture) SetWriteDeadline(time.Time) error { return nil }

func main() {
	profiles := map[string]tls.ClientHelloID{
		"safari16_0": tls.HelloSafari_16_0,
		"safari26_3": tls.HelloSafari_26_3,
	}
	profile, ok := profiles[os.Args[1]]
	if !ok {
		panic("unknown profile")
	}
	wire := new(capture)
	c := tls.UClient(wire, &tls.Config{ServerName: "fingerprint.example", NextProtos: []string{"h2", "http/1.1"}}, profile)
	_ = c.Handshake()
	if wire.Len() == 0 {
		panic("missing ClientHello")
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"profile": os.Args[1], "record": base64.StdEncoding.EncodeToString(wire.Bytes())}); err != nil {
		panic(err)
	}
}
