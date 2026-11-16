package native

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func xrayMuxReference(t *testing.T, cfg map[string]any, port uint16) {
	t.Helper()
	binary := os.Getenv("LANBOAT_TEST_XRAY")
	if binary == "" {
		t.Skip("LANBOAT_TEST_XRAY required for external Mux.Cool interoperability")
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(t.TempDir(), "reference.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "run", "-c", path)
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		log.Close()
		if t.Failed() {
			b, _ := os.ReadFile(log.Name())
			t.Log(string(b))
		}
	})
	waitPort(t, portAddress("127.0.0.1", port))
}

func TestMuxCoolXrayReference(t *testing.T) {
	for _, kind := range []string{"vmess", "vless"} {
		for _, transport := range []string{"tcp", "ws"} {
			for _, side := range []string{"client", "server"} {
				t.Run(kind+"/"+transport+"/"+side, func(t *testing.T) {
					in := testInbound(t, kind)
					if transport == "ws" {
						in.Transport = Transport{Type: "ws", Path: "/mux"}
					}
					port := unusedPort(t)
					stream := map[string]any{"network": transport, "wsSettings": map[string]any{"path": "/mux"}}
					cfg := map[string]any{"log": map[string]any{"loglevel": "warning"}}
					var c *Runtime
					if side == "client" {
						settings := map[string]any{"clients": []any{map[string]any{"id": testUUID}}, "decryption": "none"}
						if kind == "vmess" {
							delete(settings, "decryption")
						}
						cfg["inbounds"] = []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": kind, "settings": settings, "streamSettings": stream}}
						cfg["outbounds"] = []any{map[string]any{"protocol": "freedom"}}
						xrayMuxReference(t, cfg, port)
						o := testOutbound(t, in, portAddress("127.0.0.1", port))
						o.Transport, o.Multiplex.Enabled = in.Transport, true
						o.Multiplex.Protocol = "mux.cool"
						c = newTestRuntime(t, Config{Outbounds: []Outbound{o}})
					} else {
						s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						port = unusedPort(t)
						o := testOutbound(t, in, s.Address("server"))
						user := map[string]any{"id": testUUID, "encryption": "none"}
						if kind == "vmess" {
							delete(user, "encryption")
							user["security"] = "auto"
						}
						cfg["inbounds"] = []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"udp": true}}}
						cfg["outbounds"] = []any{map[string]any{"protocol": kind, "settings": map[string]any{"vnext": []any{map[string]any{"address": o.Server, "port": o.ServerPort, "users": []any{user}}}}, "streamSettings": stream, "mux": map[string]any{"enabled": true, "concurrency": 8, "xudpConcurrency": 8}}}
						xrayMuxReference(t, cfg, port)
						c = newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "front", Server: "127.0.0.1", ServerPort: port}}})
					}
					assertTCP(t, c)
					assertUDPSizes(t, c, []int{1, 511, 1400})
					assertTCP(t, c)
				})
			}
		}
	}
}
