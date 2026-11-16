package native

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestListenOptionsLinuxTCP(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprint(disabled), func(t *testing.T) {
			o := ListenOptions{BindInterface: "lo", ReuseAddr: true, TCPFastOpen: true, DisableTCPKeepAlive: disabled}
			if !disabled {
				o.TCPKeepAlive, o.TCPKeepAliveInterval = "5s", "2s"
			}
			l, err := o.listen(context.Background(), "tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			raw, err := l.(*net.TCPListener).SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range [][3]int{{syscall.SOL_SOCKET, 15, 1}, {syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1}, {syscall.IPPROTO_TCP, 23, 1024}} {
				if got := dialOptionInt(t, raw, v[0], v[1]); got != v[2] {
					t.Fatal("listener option", v, got)
				}
			}
			c, err := net.Dial("tcp4", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			peer, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			raw, err = peer.(*net.TCPConn).SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			keep := dialOptionInt(t, raw, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
			if disabled && keep != 0 || !disabled && keep != 1 {
				t.Fatal("accepted keepalive", keep)
			}
			if !disabled && (dialOptionInt(t, raw, syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE) != 5 || dialOptionInt(t, raw, syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL) != 2) {
				t.Fatal("accepted keepalive periods")
			}
			duplicate, err := o.listen(context.Background(), "tcp4", l.Addr().String())
			if err != nil {
				t.Fatal("reuse ignored", err)
			}
			duplicate.Close()
		})
	}
}
func TestListenOptionsLinuxUDP(t *testing.T) {
	for _, family := range []string{"4", "6"} {
		for _, fragment := range []bool{false, true} {
			t.Run(family+fmt.Sprint(fragment), func(t *testing.T) {
				host := "127.0.0.1:0"
				level, option := syscall.IPPROTO_IP, 10
				if family == "6" {
					host = "[::1]:0"
					level, option = syscall.IPPROTO_IPV6, 23
				}
				o := ListenOptions{BindInterface: "lo", ReuseAddr: true, UDPFragment: &fragment}
				pc, err := o.listenPacket(context.Background(), "udp"+family, host)
				if err != nil {
					t.Fatal(err)
				}
				defer pc.Close()
				raw, err := pc.(*net.UDPConn).SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				want := 2
				if fragment {
					want = 0
				}
				if got := dialOptionInt(t, raw, level, option); got != want {
					t.Fatal("fragmentation", got, want)
				}
				dup, err := o.listenPacket(context.Background(), "udp"+family, pc.LocalAddr().String())
				if err != nil {
					t.Fatal("UDP reuse ignored", err)
				}
				dup.Close()
			})
		}
	}
}

func TestListenOptionsLinuxMPTCP(t *testing.T) {
	l, err := (ListenOptions{TCPMultiPath: true}).listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	dialer := new(net.Dialer)
	dialer.SetMultipathTCP(true)
	c, err := dialer.DialContext(context.Background(), "tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	peer, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	for _, conn := range []net.Conn{c, peer} {
		enabled, err := conn.(*net.TCPConn).MultipathTCP()
		if err != nil || !enabled {
			t.Fatal("MPTCP not negotiated", enabled, err)
		}
	}
}
func TestListenOptionsLinuxMarkNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_LISTEN_NAMESPACE") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run=^TestListenOptionsLinuxMarkNamespace$", "-test.v", "-test.timeout=20s")
		cmd.Env = append(os.Environ(), "LANBOAT_LISTEN_NAMESPACE=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated listener marks: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	opts := ListenOptions{BindInterface: "lo", RoutingMark: 0x4c42, ReuseAddr: true}
	l, err := opts.listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	raw, err := l.(*net.TCPListener).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if got := dialOptionInt(t, raw, syscall.SOL_SOCKET, 36); got != 0x4c42 {
		t.Fatal("TCP mark", got)
	}
	pc, err := opts.listenPacket(context.Background(), "udp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	raw, err = pc.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if got := dialOptionInt(t, raw, syscall.SOL_SOCKET, 36); got != 0x4c42 {
		t.Fatal("UDP mark", got)
	}
}
