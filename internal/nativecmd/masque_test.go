package nativecmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/zatxm/lanboat-allinone/native"
)

func TestMasqueProbeCommand(t *testing.T) {
	raw := []byte(`{"log":{"disabled":true},"endpoints":[{"type":"masque-server","tag":"server","listen":"127.0.0.1","version":1,"address":["10.44.0.1/24","fd44::1/64"]}]}`)
	s, err := native.New(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Start(); err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(s.Address("server"))
	data, _ := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "endpoints": []any{map[string]any{"type": "masque-client", "tag": "proxy", "server": host, "server_port": json.Number(port), "version": 1}}})
	path := filepath.Join(t.TempDir(), "config.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = Execute(context.Background(), []string{"masque-probe", "-c", path, "-timeout", "2s"}, &out); err != nil {
		t.Fatal(err)
	}
	var status native.MasquePathStatus
	if err = json.Unmarshal(out.Bytes(), &status); err != nil || status.MTU != 1280 || status.HTTPVersion != 1 || status.DatagramVerified {
		t.Fatal(out.String(), err)
	}
	for _, args := range [][]string{{"-c", path, "extra"}, {"-c", path, "-timeout", "0s"}, {"-c", path, "-timeout", "2m"}, {"-c", path, "-outbound", ""}, {"-c", path, "-outbound", "missing"}, {"-c", path + "missing"}, {"-c", path, "-peer", "not-an-ip"}, {"-c", path, "-peer", "127.0.0.1"}} {
		if err := Execute(context.Background(), append([]string{"masque-probe"}, args...), &bytes.Buffer{}); err == nil {
			t.Fatal("invalid probe accepted", args)
		}
	}
}
