package native

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestUnusedPortWildcard(t *testing.T) {
	if os.Getenv("LANBOAT_PORT_CHILD") != "1" {
		parent, err := os.Readlink("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^TestUnusedPortWildcard$", "-test.v", "-test.timeout=10s")
		cmd.Env = append(os.Environ(), "LANBOAT_PORT_CHILD=1", "LANBOAT_PORT_PARENT_NS="+parent)
		output, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "no free TCP/UDP test port") {
			t.Fatalf("IPv6-only listener was not protected: %v\n%s", err, output)
		}
		return
	}
	current, err := os.Readlink("/proc/self/ns/net")
	parent := os.Getenv("LANBOAT_PORT_PARENT_NS")
	if err != nil || parent == "" || current == parent {
		t.Fatal("port fixture requires a private network namespace")
	}
	link, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := configureLink(link.Index, 65536); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_local_port_range", []byte("40000 40001\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{40000, 40001} {
		conn, err := net.ListenPacket("udp6", fmt.Sprintf("[::1]:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
	}
	unusedPort(t)
}
