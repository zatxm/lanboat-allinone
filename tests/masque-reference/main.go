// External interoperability fixture. This separate module is never linked into
// the independent core; application data crosses the upstream public APIs.
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	connectip "github.com/quic-go/connect-ip-go"
	masque "github.com/quic-go/masque-go"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

var ctx = context.Background()

func main() {
	if e := run(); e != nil {
		log.Fatal(e)
	}
}
func run() error {
	if len(os.Args) < 3 {
		return errors.New("server address cert key | client-ip address | client-udp address target")
	}
	switch os.Args[1] {
	case "configuration-server":
		return configurationServer(os.Args[2], os.Args[3], os.Args[4])
	case "configuration-client":
		return configurationClient(os.Args[2])
	case "server", "server-mtu":
		var initial uint16
		if os.Args[1] == "server-mtu" {
			initial = 1400
		}
		return server(os.Args[2], os.Args[3], os.Args[4], initial)
	case "client-ip", "client-ip-mtu":
		path := "/.well-known/masque/ip/*/*/"
		if len(os.Args) > 3 {
			path = os.Args[3]
		}
		return clientIP(os.Args[2], path, os.Args[1] == "client-ip-mtu")
	case "client-udp":
		return clientUDP(os.Args[2], os.Args[3])
	}
	return errors.New("bad mode")
}
func tlsClient() *tls.Config {
	return &tls.Config{NextProtos: []string{"h3"}, InsecureSkipVerify: true}
}
func writePacket(w io.Writer, b []byte) error {
	if len(b) > 65535 {
		return errors.New("fixture packet too large")
	}
	h := binary.BigEndian.AppendUint16(nil, uint16(len(b)))
	if _, e := w.Write(h); e != nil {
		return e
	}
	_, e := w.Write(b)
	return e
}
func readPacket(r io.Reader) ([]byte, error) {
	var h [2]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, e
	}
	b := make([]byte, int(binary.BigEndian.Uint16(h[:])))
	_, e := io.ReadFull(r, b)
	return b, e
}
func clientIP(address, path string, mtu bool) error {
	t := &connectip.Transport{TLSClientConfig: tlsClient()}
	if mtu {
		t.QUICConfig = &quic.Config{EnableDatagrams: true, InitialPacketSize: 1400}
	}
	req, e := connectip.NewRequest(ctx, uritemplate.MustNew("https://"+address+path))
	if e != nil {
		return e
	}
	req.Header().Set("Proxy-Authorization", "Basic Y2xpZW50OnByaXZhdGU=")
	c, _, e := t.Dial(req)
	if e != nil {
		return e
	}
	defer c.Close()
	assigned, e := c.ReceiveAddressAssignment(ctx)
	if e != nil {
		return e
	}
	// WritePacket rejects destinations until the peer's route capsule arrives.
	if _, e = c.Routes(ctx); e != nil {
		return e
	}
	fmt.Fprintln(os.Stderr, "ready", assigned)
	go func() {
		b := make([]byte, 65535)
		for {
			n, e := c.ReadPacket(b)
			if e != nil {
				return
			}
			if e = writePacket(os.Stdout, b[:n]); e != nil {
				return
			}
		}
	}()
	for {
		b, e := readPacket(os.Stdin)
		if e != nil {
			return nil
		}
		icmp, e := c.WritePacket(b)
		if e != nil {
			return e
		}
		if len(icmp) > 0 {
			return errors.New("fixture IP packet exceeded upstream datagram MTU")
		}
	}
}
func clientUDP(address, target string) error {
	t := &masque.Transport{TLSClientConfig: tlsClient()}
	req, e := masque.NewRequest(ctx, uritemplate.MustNew("https://"+address+"/.well-known/masque/udp/{target_host}/{target_port}/"), target)
	if e != nil {
		return e
	}
	req.Header().Set("Proxy-Authorization", "Basic Y2xpZW50OnByaXZhdGU=")
	c, _, e := t.Dial(req)
	if e != nil {
		return e
	}
	defer c.Close()
	fmt.Fprintln(os.Stderr, "ready")
	go func() {
		b := make([]byte, 65535)
		for {
			n, _, e := c.ReadFrom(b)
			if e != nil {
				return
			}
			if e = writePacket(os.Stdout, b[:n]); e != nil {
				return
			}
		}
	}()
	for {
		b, e := readPacket(os.Stdin)
		if e != nil {
			return nil
		}
		if _, e = c.WriteTo(b, nil); e != nil {
			return e
		}
	}
}
func newTUN() (*os.File, error) {
	fd, e := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	var f *os.File
	if e != nil {
		return nil, e
	}
	var request [40]byte
	copy(request[:], "mref0")
	*(*uint16)(unsafe.Pointer(&request[16])) = 0x1001
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x400454ca, uintptr(unsafe.Pointer(&request[0])))
	if errno != 0 {
		syscall.Close(fd)
		return nil, errno
	}
	_ = syscall.SetNonblock(fd, true)
	f = os.NewFile(uintptr(fd), "mref0")
	for _, args := range [][]string{{"link", "set", "mref0", "up"}, {"addr", "add", "10.44.0.1/24", "dev", "mref0"}, {"addr", "add", "fd44::1/64", "dev", "mref0", "nodad"}} {
		if out, e := exec.Command("ip", args...).CombinedOutput(); e != nil {
			f.Close()
			return nil, fmt.Errorf("ip: %s: %w", out, e)
		}
	}
	return f, nil
}
func server(address, cert, key string, initial uint16) error {
	tun, e := newTUN()
	if e != nil {
		return e
	}
	defer tun.Close()
	identity, e := tls.LoadX509KeyPair(cert, key)
	if e != nil {
		return e
	}
	var mu sync.Mutex
	var active *connectip.Conn
	go func() {
		b := make([]byte, 65535)
		for {
			n, e := tun.Read(b)
			if e != nil {
				return
			}
			mu.Lock()
			c := active
			mu.Unlock()
			if c != nil {
				_, _ = c.WritePacket(b[:n])
			}
		}
	}()
	ipProxy := &connectip.Proxy{}
	udpProxy := &masque.Proxy{}
	defer udpProxy.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "Basic Y2xpZW50OnByaXZhdGU=" {
			w.WriteHeader(407)
			return
		}
		if r.Proto == "connect-udp" {
			req, e := masque.ParseProxyRequest(r, uritemplate.MustNew("https://"+address+"/.well-known/masque/udp/{target_host}/{target_port}/"))
			if e != nil {
				log.Print(e)
				w.WriteHeader(400)
				return
			}
			if e = udpProxy.Proxy(w, req); e != nil {
				log.Print(e)
			}
			return
		}
		if r.Proto == "connect-ip" {
			req, e := connectip.ParseProxyRequest(r, uritemplate.MustNew("https://"+address+"/.well-known/masque/ip/*/*/"))
			if e != nil {
				log.Print(e)
				w.WriteHeader(400)
				return
			}
			c, e := ipProxy.Proxy(w, req)
			if e != nil {
				log.Print(e)
				return
			}
			defer c.Close()
			mu.Lock()
			active = c
			mu.Unlock()
			defer func() {
				mu.Lock()
				if active == c {
					active = nil
				}
				mu.Unlock()
			}()
			prefixes := []netip.Prefix{netip.MustParsePrefix("10.44.0.2/32"), netip.MustParsePrefix("fd44::2/128")}
			if e = c.AssignAddresses(prefixes); e != nil {
				return
			}
			if e = c.AdvertiseRoute([]connectip.IPRoute{{StartIP: netip.MustParseAddr("0.0.0.0"), EndIP: netip.MustParseAddr("255.255.255.255")}, {StartIP: netip.MustParseAddr("::"), EndIP: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")}}); e != nil {
				return
			}
			go func() {
				for {
					q, e := c.ReceiveAddressRequest(r.Context())
					if e != nil {
						return
					}
					answers := make([]netip.Prefix, len(q.Prefixes))
					for i, p := range q.Prefixes {
						for _, a := range prefixes {
							if a.Addr().BitLen() == p.Addr().BitLen() {
								answers[i] = a
								break
							}
						}
					}
					if e = q.Respond(answers, nil); e != nil {
						return
					}
				}
			}()
			b := make([]byte, 65535)
			for {
				n, e := c.ReadPacket(b)
				if e != nil {
					return
				}
				if _, e = tun.Write(b[:n]); e != nil {
					return
				}
			}
		}
		if r.Method != "CONNECT" || r.Proto != "HTTP/3.0" {
			w.WriteHeader(405)
			return
		}
		target := r.Host
		if !strings.Contains(target, ":") {
			w.WriteHeader(400)
			return
		}
		remote, e := net.Dial("tcp", target)
		if e != nil {
			w.WriteHeader(502)
			return
		}
		defer remote.Close()
		w.WriteHeader(200)
		stream := w.(http3.HTTPStreamer).HTTPStream()
		go func() {
			io.Copy(remote, stream)
			if c, ok := remote.(*net.TCPConn); ok {
				c.CloseWrite()
			}
		}()
		io.Copy(stream, remote)
	})
	packets, e := net.ListenPacket("udp", address)
	if e != nil {
		return e
	}
	defer packets.Close()
	s := &http3.Server{Handler: handler, TLSConfig: &tls.Config{Certificates: []tls.Certificate{identity}, NextProtos: []string{"h3"}}, EnableDatagrams: true, QUICConfig: &quic.Config{EnableDatagrams: true, InitialPacketSize: initial}}
	fmt.Fprintln(os.Stderr, "ready")
	return s.Serve(packets)
}
