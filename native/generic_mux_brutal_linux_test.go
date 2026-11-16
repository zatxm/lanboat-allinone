//go:build linux

package native

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestGenericMuxBrutalKernel(t *testing.T) {
	if os.Getenv("LANBOAT_TEST_BRUTAL_KERNEL") != "1" {
		if os.Getenv("LANBOAT_TEST_BRUTAL_VM") != "1" {
			t.Skip("requires brutal module in isolated kernel VM")
		}
		cmd := exec.Command("bash", filepath.Join("..", "scripts", "test-multiplex-brutal.sh"))
		output, err := cmd.CombinedOutput()
		t.Log(string(output))
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := listener.Accept(); accepted <- c }()
	c, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	peer := <-accepted
	if peer == nil {
		t.Fatal("accept failed")
	}
	defer peer.Close()
	const rate = 12500000
	if err = setTCPBrutal(&bufferedConn{Conn: c}, rate); err != nil {
		t.Fatal(err)
	}
	raw, _ := c.(*net.TCPConn).SyscallConn()
	var cause error
	if err = raw.Control(func(fd uintptr) {
		var name [16]byte
		length := uint32(len(name))
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_TCP, syscall.TCP_CONGESTION, uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&length)), 0)
		if e != 0 {
			cause = e
			return
		}
		if string(name[:6]) != "brutal" {
			cause = io.ErrUnexpectedEOF
			return
		}
		var params [12]byte
		size := uint32(len(params))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_TCP, 23301, uintptr(unsafe.Pointer(&params[0])), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 {
			cause = errno
			return
		}
		if binary.NativeEndian.Uint64(params[:]) != rate || binary.NativeEndian.Uint32(params[8:]) != 20 {
			cause = io.ErrUnexpectedEOF
		}
	}); err != nil {
		t.Fatal(err)
	}
	if cause != nil {
		t.Fatal(cause)
	}
	for _, protocol := range []string{"h2mux", "smux", "yamux"} {
		t.Run(protocol, func(t *testing.T) {
			in := testInbound(t, "shadowsocks")
			in.Multiplex = MultiplexOptions{Enabled: true, Padding: true, Brutal: BrutalOptions{Enabled: true, UpMbps: 100, DownMbps: 80}}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Multiplex = MultiplexOptions{Enabled: true, Protocol: protocol, Padding: true, Brutal: BrutalOptions{Enabled: true, UpMbps: 50, DownMbps: 60}}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 1400, 14000})
			// A refused destination is stream-local, even after the bandwidth exchange.
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			stream, e := client.Dial(ctx, "tcp", "127.0.0.1:1")
			if e == nil {
				stream.SetDeadline(time.Now().Add(time.Second))
				_, e = stream.Read(make([]byte, 1))
				stream.Close()
			}
			if e == nil {
				t.Fatal("refused stream succeeded")
			}
			assertTCP(t, client)
		})
	}
	if reference := os.Getenv("LANBOAT_TEST_SINGBOX15"); reference != "" {
		t.Setenv("LANBOAT_TEST_REFERENCE", reference)
		for _, protocol := range []string{"h2mux", "smux", "yamux"} {
			for _, side := range []string{"client", "server"} {
				t.Run("official/"+protocol+"/"+side, func(t *testing.T) {
					in := testInbound(t, "shadowsocks")
					in.Multiplex = MultiplexOptions{Enabled: true, Padding: true, Brutal: BrutalOptions{Enabled: true, UpMbps: 100, DownMbps: 80}}
					var client *Runtime
					if side == "client" {
						in.ListenPort = unusedPort(t)
						referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
						out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
						out.Multiplex = MultiplexOptions{Enabled: true, Protocol: protocol, Padding: true, Brutal: BrutalOptions{Enabled: true, UpMbps: 50, DownMbps: 60}}
						client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
					} else {
						server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						out := testOutbound(t, in, server.Address("server"))
						out.UUID = ""
						out.Username = ""
						out.Multiplex = MultiplexOptions{Enabled: true, Protocol: protocol, Padding: true, Brutal: BrutalOptions{Enabled: true, UpMbps: 50, DownMbps: 60}}
						front := Inbound{Type: "socks", Tag: "front", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
						referenceRuntime(t, Config{Inbounds: []Inbound{front}, Outbounds: []Outbound{out}})
						client = newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "proxy", Server: "127.0.0.1", ServerPort: front.ListenPort}}})
					}
					assertTCP(t, client)
					assertUDPSizes(t, client, []int{1, 1400, 14000})
				})
			}
		}
	}

}
