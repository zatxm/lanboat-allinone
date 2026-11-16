package native

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestDialOptionsValidation(t *testing.T) {
	for _, value := range []string{
		`"inet4_bind_address":"::1"`, `"inet6_bind_address":"127.0.0.1"`,
		`"inet6_bind_address":"::ffff:127.0.0.1"`, `"inet4_bind_address":"host.test"`,
		`"connect_timeout":"0s"`, `"tcp_keep_alive":"-1s"`, `"tcp_keep_alive_interval":"bad"`,
		`"disable_tcp_keep_alive":true,"tcp_keep_alive":"1m"`, `"bind_interface":"lo\u0000x"`,
		`"routing_mark":"0x100000000"`,
	} {
		if _, err := Parse([]byte(`{"outbounds":[{"type":"direct",` + value + `}]}`)); err == nil {
			t.Fatal("invalid dial fields accepted", value)
		}
	}
	for _, raw := range []string{
		`{"outbounds":[{"type":"direct","inet4_bind_address":"127.0.0.1","inet6_bind_address":"::1","connect_timeout":"2s","tcp_keep_alive":"10s","tcp_keep_alive_interval":"2s","tcp_multi_path":true}]}`,
		`{"dns":{"servers":[{"type":"udp","server":"127.0.0.1","connect_timeout":"2s","inet4_bind_address":"127.0.0.1"}]}}`,
		`{"http_clients":[{"tag":"fetch","connect_timeout":"2s","tcp_keep_alive":"10s"}]}`,
		`{"endpoints":[{"type":"masque-client","server":"127.0.0.1","server_port":443,"tls":{"enabled":true,"insecure":true},"inet4_bind_address":"127.0.0.1"}]}`,
	} {
		if _, err := Parse([]byte(raw)); err != nil {
			t.Fatal(err, raw)
		}
	}
	for _, raw := range []string{
		`{"dns":{"servers":[{"type":"hosts","connect_timeout":"1s"}]}}`,
		`{"outbounds":[{"type":"tailscale","inet4_bind_address":"127.0.0.1","inet6_bind_address":"::1"}]}`,
	} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatal("dial fields accepted without an applicable socket", raw)
		}
	}
}

func TestDialOptionsDeadlineIncludesResolution(t *testing.T) {
	blackhole, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	host, port := splitTestAddress(t, blackhole.LocalAddr().String())
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", DialOptions: DialOptions{ConnectTimeout: "40ms"}}}, DNS: DNSConfig{Strategy: "ipv4_only", Servers: []DNSServer{{Type: "udp", Server: host, ServerPort: port}}}})
	start := time.Now()
	_, err = r.Dial(context.Background(), "tcp", "timeout.test:443")
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() || time.Since(start) > time.Second {
		t.Fatal("connect deadline did not bound DNS", err, time.Since(start))
	}
}

func TestDialOptionsInvalidInterfaceDoesNotBypass(t *testing.T) {
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", DialOptions: DialOptions{BindInterface: "lanboat-missing-interface"}}}})
	conn, err := r.Dial(context.Background(), "tcp", tcpEcho(t))
	if err == nil {
		conn.Close()
		t.Fatal("invalid interface silently bypassed")
	}
}
