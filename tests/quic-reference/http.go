package main

import (
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/quic-go/quic-go/http3"
)

func httpMain() {
	cert, err := tls.LoadX509KeyPair(os.Args[3], os.Args[4])
	check(err)
	packet, err := net.ListenPacket("udp", os.Args[2])
	check(err)
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 3 {
			panic("expected HTTP3")
		}
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/rules", 307)
			return
		case "/post":
			_, err := io.Copy(w, r.Body)
			check(err)
			return
		}
		data, err := os.ReadFile(os.Args[5])
		check(err)
		w.Header().Add("Set-Cookie", "first=1")
		w.Header().Add("Set-Cookie", "second=2")
		if r.URL.Path == "/gzip" {
			w.Header().Set("Content-Encoding", "gzip")
			writer := gzip.NewWriter(w)
			_, err = writer.Write(data)
			check(err)
			check(writer.Close())
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		_, err = w.Write(data)
		check(err)
	})}
	fmt.Println("READY")
	check(server.Serve(packet))
}
