package native

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestSnell5SaltDiscriminator(t *testing.T) {
	dir := os.Getenv("LANBOAT_TEST_SNELL_DIR")
	if dir == "" {
		t.Skip("Snell reference required")
	}
	port := unusedPort(t)
	cfg := filepath.Join(t.TempDir(), "server.conf")
	os.WriteFile(cfg, fmt.Appendf(nil, "[snell-server]\nlisten=127.0.0.1:%d\npsk=private\n", port), 0600)
	cmd := exec.Command(filepath.Join(dir, "5.0.1", "snell-server"), "-c", cfg)
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	waitPort(t, portAddress("127.0.0.1", port))
	waitPacketPort(t, portAddress("127.0.0.1", port))
	target, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	for _, prefix := range []byte{0, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0} {
		cid := quicPadding()[:8]
		_, key, e := quicInitialKeys(cid, false)
		if e != nil {
			t.Fatal(e)
		}
		initial := sealQUICPacket([]byte{1}, cid, quicPadding()[:8], nil, 0, 0, false, key)
		salt := quicPadding()[:16]
		salt[0] = prefix
		packet, e := snellQUICSealSalt("private", target.LocalAddr().String(), initial, salt)
		if e != nil {
			t.Fatal(e)
		}
		c, e := net.Dial("udp", portAddress("127.0.0.1", port))
		if e != nil {
			t.Fatal(e)
		}
		c.Write(packet)
		target.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		buffer := make([]byte, 2000)
		n, _, e := target.ReadFrom(buffer)
		c.Close()
		if (e == nil) != (prefix&0x40 == 0) {
			t.Fatalf("salt=%02x forward=%v bytes=%d: unexpected QUIC fixed-bit dispatch", prefix, e == nil, n)
		}
	}
}
