package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func dnsMain() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	kind, address := os.Args[2], os.Args[3]
	config := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"doq"}}
	if os.Args[1] == "dns-server" {
		cert, e := tls.LoadX509KeyPair(os.Args[4], os.Args[5])
		check(e)
		config.Certificates = []tls.Certificate{cert}
		if kind == "h3" {
			p, e := net.ListenPacket("udp", address)
			check(e)
			s := &http3.Server{TLSConfig: config, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var q []byte
				var e error
				if r.Method == "GET" {
					q, e = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
				} else {
					q, e = io.ReadAll(r.Body)
				}
				check(e)
				if r.URL.Path != "/dns-query" || len(q) < 12 {
					http.Error(w, "bad request", 400)
					return
				}
				w.Header().Set("Content-Type", "application/dns-message")
				w.Write(oracleDNSAnswer(q))
			})}
			fmt.Println("READY")
			check(s.Serve(p))
			return
		}
		l, e := quic.ListenAddr(address, config, &quic.Config{})
		check(e)
		fmt.Println("READY")
		for {
			c, e := l.Accept(ctx)
			check(e)
			go func() {
				for {
					s, e := c.AcceptStream(ctx)
					if e != nil {
						return
					}
					go func() {
						defer s.Close()
						q := oracleDoQRead(s)
						if q[0] != 0 || q[1] != 0 {
							panic("nonzero DoQ ID")
						}
						reply := oracleDNSAnswer(q)
						_, e = s.Write(binary.BigEndian.AppendUint16(nil, uint16(len(reply))))
						check(e)
						_, e = s.Write(reply)
						check(e)
					}()
				}
			}()
		}
	}
	q := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
	var conn *quic.Conn
	var transport *http3.Transport
	if kind == "quic" {
		var e error
		conn, e = quic.DialAddr(ctx, address, config, &quic.Config{})
		check(e)
		defer conn.CloseWithError(0, "")
	} else {
		transport = &http3.Transport{TLSClientConfig: config}
		defer transport.Close()
	}
	for i := 0; i < 12; i++ {
		var b []byte
		if kind == "quic" {
			s, e := conn.OpenStreamSync(ctx)
			check(e)
			_, e = s.Write(binary.BigEndian.AppendUint16(nil, uint16(len(q))))
			check(e)
			_, e = s.Write(q)
			check(e)
			check(s.Close())
			b = oracleDoQRead(s)
		} else {
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			var req *http.Request
			if i%2 == 0 {
				req, _ = http.NewRequestWithContext(ctx, "POST", "https://"+address+"/dns-query", bytes.NewReader(q))
				req.Header.Set("Content-Type", "application/dns-message")
			} else {
				req, _ = http.NewRequestWithContext(ctx, "GET", "https://"+address+"/dns-query?dns="+base64.RawURLEncoding.EncodeToString(q), nil)
			}
			response, e := client.Do(req)
			check(e)
			b, e = io.ReadAll(response.Body)
			response.Body.Close()
			check(e)
			if response.StatusCode != 200 {
				panic(response.Status)
			}
		}
		if len(b) < 16 || !bytes.Equal(b[len(b)-4:], []byte{192, 0, 2, 42}) || b[3]&15 != 0 {
			panic(fmt.Sprintf("invalid DNS response %x", b))
		}
	}
	fmt.Println("PASS")
}
func oracleDoQRead(r io.Reader) []byte {
	var size [2]byte
	_, e := io.ReadFull(r, size[:])
	check(e)
	b := make([]byte, binary.BigEndian.Uint16(size[:]))
	_, e = io.ReadFull(r, b)
	check(e)
	var extra [1]byte
	if _, e = io.ReadFull(r, extra[:]); e != io.EOF {
		panic("missing DoQ FIN")
	}
	return b
}
func oracleDNSAnswer(q []byte) []byte {
	b := append([]byte(nil), q...)
	b[2], b[3], b[6], b[7] = 0x81, 0x80, 0, 1
	return append(b, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 42)
}
