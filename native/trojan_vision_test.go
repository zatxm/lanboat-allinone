package native

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

func trojanVisionPair(t *testing.T) (*Runtime, *Runtime) {
	t.Helper()
	in := testInbound(t, "trojan")
	in.Users[0].Flow = visionFlow
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, s.Address("server"))
	out.Flow = visionFlow
	return s, newTestRuntime(t, Config{Outbounds: []Outbound{out}})
}
func TestTrojanVisionIndependent(t *testing.T) {
	_, c := trojanVisionPair(t)
	assertTCP(t, c)
	visionHTTPS(t, c, tls.VersionTLS13, true)
	visionHTTPS(t, c, tls.VersionTLS12, true)
	assertUDPSizes(t, c, []int{0, 1, 511, 4096, 60000})
	assertUDPAddress(t, c, []int{1, 4096}, masqueEcho(t, "udp", "[::1]:0"))
	c.resetNetworkTransports()
	visionHTTPS(t, c, tls.VersionTLS13, true)
}
func TestTrojanVisionModeIsolation(t *testing.T) {
	for _, serverVision := range []bool{false, true} {
		t.Run(map[bool]string{false: "standard-server", true: "vision-server"}[serverVision], func(t *testing.T) {
			in := testInbound(t, "trojan")
			if serverVision {
				in.Users[0].Flow = visionFlow
			}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, s.Address("server"))
			if !serverVision {
				out.Flow = visionFlow
			}
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, e := c.Dial(ctx, "tcp", "127.0.0.1:1")
			if e == nil {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				conn.Write([]byte("must reject"))
				var b [1]byte
				_, e = conn.Read(b[:])
			}
			if e == nil {
				t.Fatal("mode mismatch accepted")
			}
		})
	}
}
func TestTrojanVisionConfiguration(t *testing.T) {
	for _, bad := range []string{"tls", "version", "transport", "mux", "secondary", "flow"} {
		t.Run(bad, func(t *testing.T) {
			out := Outbound{Type: "trojan", Tag: "proxy", Server: "127.0.0.1", ServerPort: 443, Password: "private", Flow: visionFlow, TLS: TLSOptions{Enabled: true}}
			switch bad {
			case "tls":
				out.TLS.Enabled = false
			case "version":
				out.TLS.MaxVersion = "1.2"
			case "transport":
				out.Transport.Type = "ws"
			case "mux":
				out.Multiplex.Enabled = true
				out.Multiplex.Protocol = "trojan-go"
			case "secondary":
				out.Shadowsocks = &TrojanShadowsocksOptions{Enabled: true, Method: "aes-128-gcm", Password: "secondary"}
			case "flow":
				out.Flow = "unknown"
			}
			raw, _ := json.Marshal(Config{Outbounds: []Outbound{out}})
			if _, e := Parse(raw); e == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}
func TestTrojanVisionAcknowledgement(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { b.Write([]byte("wrong")) }()
	if _, e := trojanVisionClient(a, "private"); e == nil {
		t.Fatal("invalid acknowledgement accepted")
	}
	a, b = net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { io.WriteString(b, "LBT"); b.Close() }()
	if _, e := trojanVisionClient(a, "private"); e == nil {
		t.Fatal("truncated acknowledgement accepted")
	}
}

func TestTrojanVisionAuthenticatedMixedAccounts(t *testing.T) {
	in := testInbound(t, "trojan")
	in.Users = []User{{Name: "alice", Password: "private", Flow: visionFlow}, {Name: "bob", Password: "ordinary"}}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "deny"}}, Route: Route{Final: "deny", Rules: []Rule{{AuthUser: []string{"alice", "bob"}, Outbound: "direct"}}}})
	for _, vision := range []bool{false, true} {
		out := testOutbound(t, in, s.Address("server"))
		out.Password = "ordinary"
		if vision {
			out.Flow = visionFlow
			out.Password = "private"
		}
		c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
		assertTCP(t, c)
		assertUDPSizes(t, c, []int{1, 4096})
		if vision {
			visionHTTPS(t, c, tls.VersionTLS13, true)
		}
	}
	in.Users = append(in.Users, User{Password: "private"})
	raw, _ := json.Marshal(Config{Inbounds: []Inbound{in}})
	if _, e := Parse(raw); e == nil {
		t.Fatal("same password with contradictory flows accepted")
	}
}
func TestTrojanVisionRealityAndFragment(t *testing.T) {
	_, c := realityPair(t, "trojan", true, Transport{})
	visionHTTPS(t, c, tls.VersionTLS13, true)
	assertUDPSizes(t, c, []int{0, 4096})
	for _, record := range []bool{false, true} {
		in := testInbound(t, "trojan")
		in.Users[0].Flow = visionFlow
		s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
		out := testOutbound(t, in, s.Address("server"))
		out.Flow = visionFlow
		out.TLS.RecordFragment = record
		out.TLS.Fragment = !record
		c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
		visionHTTPS(t, c, tls.VersionTLS13, true)
	}
}
