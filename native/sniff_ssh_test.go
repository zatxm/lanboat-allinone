package native

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSniffSSHClient(t *testing.T) {
	for _, name := range []string{"OpenSSH_10.0p2", "OpenSSH_10.0p2 Debian-7 comment", "dropbear_2025.88", "Go", strings.Repeat("x", 245)} {
		for _, prefix := range []string{"SSH-2.0-", "SSH-1.99-"} {
			wire := []byte(prefix + name + "\r\n")
			if len(wire) > 255 {
				continue
			}
			p, host, client := sniffPacketInfo("tcp", wire, []string{"ssh"})
			if p != "ssh" || host != "" || client != name {
				t.Fatal(p, host, client, name)
			}
			for n := 1; n < len(wire); n++ {
				if !sniffNeedsMore("tcp", wire[:n], []string{"ssh"}) {
					t.Fatal("incomplete identification decided early", n)
				}
				if _, _, client := sniffPacketInfo("tcp", wire[:n], []string{"ssh"}); client != "" {
					t.Fatal("partial client name published", n, client)
				}
			}
			p, _, client = sniffPacketInfo("tcp", append(wire, 0, 1, 2, 3), nil)
			if p != "ssh" || client != name || sniffNeedsMore("tcp", wire, nil) {
				t.Fatal("binary key exchange confused identification", p, client)
			}
		}
	}
	for _, wire := range []string{"SSH-", "SSH-2.0-", "SSH-2.0-a\r"} {
		if sniffNeedsMore("tcp", []byte(wire), []string{"http"}) {
			t.Fatal("disabled SSH retained bytes")
		}
	}
	for _, wire := range []string{"SSH-2.0-\r\n", "SSH-2.0- bad\r\n", "SSH-2.0-bad\x00\r\n", "SSH-2.0-bad\tvalue\r\n", "SSH-2.0-" + strings.Repeat("x", 246) + "\r\n", "SSH-9.0-Go\r\n", "SSH-2.0-Go\rbroken\n"} {
		p, _, client := sniffPacketInfo("tcp", []byte(wire), []string{"ssh"})
		if p != "" || client != "" || sniffNeedsMore("tcp", []byte(wire), []string{"ssh"}) {
			t.Fatalf("invalid identification accepted: %q", wire)
		}
	}
}

func TestSniffSSHFragmentedRoute(t *testing.T) {
	host, port := splitTestAddress(t, tcpEcho(t))
	client := "OpenSSH_10.0p2 Debian-7 comment"
	r, logs := loggingRuntime(t, Config{ExternalController: "127.0.0.1:0", Route: Route{Rules: []Rule{
		{Action: "sniff", Sniffer: []string{"ssh"}},
		{Protocol: []string{"ssh"}, Client: []string{client}, Action: "route-options", OverrideAddress: host, OverridePort: port},
		{Client: []string{client}, Outbound: "direct"}, {Action: "reject"},
	}}})
	c, err := r.Dial(context.Background(), "tcp", "192.0.2.1:22")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	want := []byte("SSH-2.0-" + client + "\r\n")
	for _, b := range want {
		if _, err = c.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	got := make([]byte, len(want))
	if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, want) {
		t.Fatal("identification replay changed", err, string(got))
	}
	rows := controllerRows(t, r)
	if len(rows) != 1 || rows[0].(map[string]any)["metadata"].(map[string]any)["client"] != client {
		t.Fatal(rows)
	}
	if logs.FilterMessageSnippet(", client: "+client).Len() == 0 {
		t.Fatal("client missing from connection log")
	}
	wrong, err := r.Dial(context.Background(), "tcp", "192.0.2.1:22")
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if _, err = io.WriteString(wrong, "SSH-2.0-other\r\n"); err == nil {
		t.Fatal("wrong SSH client bypassed policy")
	}
}

func TestSniffSSHOpenSSH(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	cmd := exec.CommandContext(ctx, "ssh", "-F", "/dev/null", "-p", port, "-o", "BatchMode=yes", "user@127.0.0.1")
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); cmd.Wait() }()
	l.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	wire, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	p, _, client := sniffPacketInfo("tcp", wire, nil)
	if p != "ssh" || !strings.HasPrefix(client, "OpenSSH_") {
		t.Fatal(p, client)
	}
	t.Log("actual OpenSSH identification:", client)
}

func TestSniffSSHReference(t *testing.T) {
	reference := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if reference == "" {
		t.Fatal("LANBOAT_TEST_SINGBOX15 required")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", reference)
	for _, name := range []string{"OpenSSH_10.0p2", "OpenSSH_10.0p2 Debian-7 comment", "dropbear_2025.88", "Go"} {
		t.Run(name, func(t *testing.T) {
			host, port := splitTestAddress(t, tcpEcho(t))
			in := Inbound{Type: "mixed", Tag: "in", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
			referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}, Route: Route{Rules: []Rule{
				{Action: "sniff", Sniffer: []string{"ssh"}},
				{Protocol: []string{"ssh"}, Client: []string{name}, Action: "route-options", OverrideAddress: host, OverridePort: port},
				{Client: []string{name}, Outbound: "direct"}, {Action: "reject"},
			}}})
			out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
			out.Username, out.Password, out.UUID = "", "", ""
			r := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			c, err := r.Dial(context.Background(), "tcp", "192.0.2.1:22")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(2 * time.Second))
			want := []byte("SSH-2.0-" + name + "\r\n")
			if _, err = c.Write(want); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(want))
			if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, want) {
				t.Fatal("reference client rule failed", err, string(got))
			}
		})
	}
}

func FuzzSniffSSH(f *testing.F) {
	for _, wire := range []string{"SSH-2.0-OpenSSH_10.0p2 Debian-7\r\n", "SSH-1.99-Go\n", "S", "SSH-2.0-\x00\n"} {
		f.Add([]byte(wire))
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		p, _, client := sniffPacketInfo("tcp", wire, []string{"ssh"})
		more := sniffNeedsMore("tcp", wire, []string{"ssh"})
		if client != "" && (p != "ssh" || more || len(client) > 246 || strings.ContainsAny(client, "\r\n\x00\t")) {
			t.Fatal("invalid published SSH client", p, client, more)
		}
	})
}
