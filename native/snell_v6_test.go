package native

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSnellV6Config(t *testing.T) {
	for _, role := range []struct{ name, endpoint string }{
		{"inbounds", `"listen":"127.0.0.1","listen_port":8388`},
		{"outbounds", `"server":"127.0.0.1","server_port":8388`},
	} {
		t.Run(role.name, func(t *testing.T) {
			for _, tc := range []struct {
				name, version, password, options, wantError string
			}{
				{name: "implicit-default", version: "6", password: strings.Repeat("é", 6)},
				{name: "unshaped", version: "6", password: strings.Repeat("x", 255), options: `,"mode":"unshaped"`},
				{name: "short-key", version: "6", password: strings.Repeat("x", 11), wantError: "12-255 bytes"},
				{name: "long-key", version: "6", password: strings.Repeat("x", 256), wantError: "12-255 bytes"},
				{name: "unknown-mode", version: "6", password: snellV6TestPassword, options: `,"mode":"other"`, wantError: "Snell v6 mode"},
				{name: "legacy-obfs", version: "6", password: snellV6TestPassword, options: `,"obfs":{"type":"http"}`, wantError: "legacy obfs"},
				{name: "legacy-obfs-param", version: "6", password: snellV6TestPassword, options: `,"obfs_param":"example.com"`, wantError: "legacy obfs"},
				{name: "legacy-mode", version: "5", password: "private", options: `,"mode":"default"`, wantError: "mode requires Snell v6"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					raw := fmt.Sprintf(`{%q:[{"type":"snell","tag":"proxy","version":%q,"password":%q,%s%s}]}`, role.name, tc.version, tc.password, role.endpoint, tc.options)
					_, err := Parse([]byte(raw))
					if tc.wantError == "" {
						if err != nil {
							t.Fatal(err)
						}
					} else if err == nil || !strings.Contains(err.Error(), tc.wantError) {
						t.Fatalf("wanted %q, got %v", tc.wantError, err)
					}
				})
			}
		})
	}
}

func TestSnellV6PingAndErrorReply(t *testing.T) {
	in := Inbound{Type: "snell", Tag: "server", Listen: "127.0.0.1", Version: "6", Password: snellV6TestPassword}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "block", Tag: "block"}}})
	for _, ping := range []bool{true, false} {
		raw, err := net.DialTimeout("tcp", server.Address("server"), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { raw.Close() })
		_ = raw.SetDeadline(time.Now().Add(time.Second))
		stream := newSnellConn(raw, in.Password, in.Version, "", &replayWindow{})
		if ping {
			if err := writeAll(stream, []byte{1, 0}); err != nil {
				t.Fatal(err)
			}
			var response [1]byte
			if _, err := io.ReadFull(stream, response[:]); err != nil || response[0] != 1 {
				t.Fatalf("ping reply = %v, %v", response, err)
			}
		} else {
			c, err := snellClientStream(stream, "127.0.0.1:1", false)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Read(make([]byte, 1)); err == nil || !strings.Contains(err.Error(), "Connection failed") {
				t.Fatalf("expected a structured Snell rejection, got %v", err)
			}
		}
	}
}
