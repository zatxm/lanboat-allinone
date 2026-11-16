package allinone

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestNetworkNamespacePublicAPI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "namespace.pid")
	raw, err := json.Marshal(map[string]any{
		"network_namespaces": []any{map[string]any{"type": "unshare", "tag": "public", "pid_file": path}},
		"inbounds":           []any{map[string]any{"type": "socks", "tag": "local", "listen": "127.0.0.1", "netns": "public"}},
		"outbounds":          []any{map[string]any{"type": "direct", "tag": "direct", "netns": "public"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewWithLogger(context.Background(), raw, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err = r.Start(); err != nil {
		t.Fatal(err)
	}
	c, err := r.Dial(context.Background(), "tcp", r.Address("local"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte{5, 1, 0})
	var reply [2]byte
	if _, err = io.ReadFull(c, reply[:]); err != nil || !bytes.Equal(reply[:], []byte{5, 0}) {
		t.Fatal(reply, err)
	}
	r.Close()
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("pid file not cleaned", err)
	}
}
