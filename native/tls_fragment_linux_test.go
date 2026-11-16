package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestTLSFragmentPacketCapture(t *testing.T) {
	if os.Getenv("LANBOAT_TLS_PACKET_CHILD") != "1" {
		command := exec.Command("unshare", "-Urn", "--", os.Args[0], "-test.run=^TestTLSFragmentPacketCapture$", "-test.v")
		command.Env = append(os.Environ(), "LANBOAT_TLS_PACKET_CHILD=1")
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("isolated packet check: %v\n%s", err, out)
		}
		return
	}
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("loopback: %s %v", out, err)
	}
	for _, combined := range []bool{false, true} {
		t.Run(fmt.Sprint(combined), func(t *testing.T) {
			if combined {
				if out, err := exec.Command("tc", "qdisc", "add", "dev", "lo", "root", "netem", "delay", "15ms").CombinedOutput(); err != nil {
					t.Fatalf("isolated netem: %s %v", out, err)
				}
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			port := listener.Addr().(*net.TCPAddr).Port
			fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0x0300)
			if err != nil {
				t.Fatal(err)
			}
			defer syscall.Close(fd)
			loop, err := net.InterfaceByName("lo")
			if err != nil {
				t.Fatal(err)
			}
			if err = syscall.Bind(fd, &syscall.SockaddrLinklayer{Ifindex: loop.Index, Protocol: 0x0300}); err != nil {
				t.Fatal(err)
			}
			_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 2})
			captured := make(chan error, 1)
			go func() {
				var buffer [65536]byte
				seen := map[uint32]bool{}
				total, wanted, segments := 0, 0, 0
				for total < wanted || wanted == 0 {
					n, source, err := syscall.Recvfrom(fd, buffer[:], 0)
					if err == syscall.EINTR {
						continue
					}
					if err != nil {
						captured <- err
						return
					}
					if source.(*syscall.SockaddrLinklayer).Pkttype != 4 || n < 54 {
						continue
					}
					ip := buffer[14:n]
					if ip[0]>>4 != 4 || ip[9] != 6 {
						continue
					}
					header := int(ip[0]&15) * 4
					if len(ip) < header+20 {
						continue
					}
					tcp := ip[header:]
					if int(binary.BigEndian.Uint16(tcp[2:4])) != port {
						continue
					}
					offset := int(tcp[12]>>4) * 4
					if offset < 20 || len(tcp) <= offset {
						continue
					}
					seq := binary.BigEndian.Uint32(tcp[4:8])
					if seen[seq] {
						continue
					}
					seen[seq] = true
					payload := tcp[offset:]
					if wanted == 0 {
						if len(payload) < 5 || payload[0] != 22 {
							captured <- fmt.Errorf("first segment is not TLS")
							return
						}
						wanted = 5 + int(binary.BigEndian.Uint16(payload[3:5]))
					}
					if bytes.Contains(payload, []byte("packet-fragment.example")) {
						captured <- fmt.Errorf("SNI remained in one TCP packet")
						return
					}
					total += len(payload)
					segments++
				}
				if segments < 2 {
					captured <- fmt.Errorf("only%d segment", segments)
					return
				}
				captured <- nil
			}()
			options, err := certificate(t).config(true, "")
			if err != nil {
				t.Fatal(err)
			}
			serverDone := make(chan error, 1)
			go func() {
				raw, err := listener.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
				serverDone <- tls.Server(raw, options).Handshake()
			}()
			raw, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			if rtt := tlsFragmentRTT(raw); rtt <= 0 || rtt > time.Second {
				t.Fatal("kernel RTT", rtt)
			}
			o := TLSOptions{Fragment: true, FragmentFallbackDelay: "30ms", RecordFragment: combined}
			if combined {
				o.FragmentFallbackDelay = "1h"
				if rtt := tlsFragmentRTT(raw); rtt < 20*time.Millisecond {
					t.Fatal("netem RTT was not detected", rtt)
				}
			}
			c := clientTLS(raw, &tls.Config{ServerName: "packet-fragment.example", InsecureSkipVerify: true}, o)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err = c.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			if err = <-serverDone; err != nil {
				t.Fatal(err)
			}
			if err = <-captured; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTLSFragmentOwnedTCPRTT(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	raw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	wrapped := &ownedConn{Conn: raw}
	if fragmentTCP(wrapped) != raw || tlsFragmentRTT(wrapped) <= 0 {
		t.Fatal("owned TCP connection stats not available")
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if tlsFragmentRTT(a) != 0 {
		t.Fatal("non TCP statistics")
	}
}
