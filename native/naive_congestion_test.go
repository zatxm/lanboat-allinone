package native

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestNaiveQUICCongestionConfiguration(t *testing.T) {
	f := newMutualTLSFixture(t)
	for _, role := range []string{"client", "server"} {
		for _, algorithm := range []string{"", "cubic", "bbr", "bbr2", "reno", "bbr3", "new_reno", "none", "CUBIC"} {
			t.Run(role+"/"+algorithm, func(t *testing.T) {
				in := Inbound{Type: "naive", Tag: "server", Listen: "127.0.0.1", TLS: f.server(), Users: []User{{Username: "client", Password: "private"}}, QUICCongestionControl: algorithm}
				out := testOutbound(t, in, "127.0.0.1:2443")
				out.TLS, out.QUIC, out.QUICCongestionControl = f.client(), true, algorithm
				cfg := Config{Outbounds: []Outbound{out}}
				if role == "server" {
					cfg = Config{Inbounds: []Inbound{in}}
				}
				raw, err := json.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := Parse(raw)
				valid := algorithm == "" || algorithm == "cubic" || algorithm == "bbr" || algorithm == "reno" || algorithm == "bbr2" && role == "client"
				if (err == nil) != valid {
					t.Fatal("congestion configuration decision", valid, err)
				}
				if valid {
					got := algorithm
					if role == "server" {
						got = parsed.Inbounds[0].QUICCongestionControl
					} else {
						got = parsed.Outbounds[0].QUICCongestionControl
					}
					if got != algorithm {
						t.Fatal("lost congestion option on parse", got)
					}
				}
			})
		}
	}
	for _, role := range []string{"client-http2", "server-http2", "other-outbound", "other-inbound"} {
		t.Run(role, func(t *testing.T) {
			in := Inbound{Type: "naive", Tag: "server", Network: "tcp", TLS: f.server(), Users: []User{{Username: "client", Password: "private"}}, QUICCongestionControl: "cubic"}
			out := testOutbound(t, in, "127.0.0.1:2443")
			out.QUICCongestionControl = "cubic"
			cfg := Config{Outbounds: []Outbound{out}}
			switch role {
			case "server-http2":
				cfg = Config{Inbounds: []Inbound{in}}
			case "other-outbound":
				cfg.Outbounds[0].Type = "direct"
			case "other-inbound":
				in.Type, in.Network = "socks", ""
				cfg = Config{Inbounds: []Inbound{in}}
			}
			raw, _ := json.Marshal(cfg)
			if _, err := Parse(raw); err == nil {
				t.Fatal("accepted ignored quic_congestion_control")
			}
		})
	}
}

func assertNaiveController(t *testing.T, q *quicConn, algorithm string) {
	t.Helper()
	if (q.cubic != nil) != (algorithm == "cubic") || (q.bbr != nil) != (algorithm == "bbr" || algorithm == "bbr2") {
		t.Fatal("wrong live congestion controller", algorithm)
	}
	if q.bbr != nil && (q.bbr.model != nil) != (algorithm == "bbr2") {
		t.Fatal("BBRv1/v2 selection was lost", algorithm)
	}
	if algorithm == "bbr2" && !q.bbr.model.v2 {
		t.Fatal("BBRv3 substituted for BBRv2")
	}
}

func TestNaiveQUICCongestionIndependent(t *testing.T) {
	f := newMutualTLSFixture(t)
	for _, serverAlgorithm := range []string{"", "cubic", "bbr", "reno"} {
		for _, clientAlgorithm := range []string{"", "cubic", "bbr", "bbr2", "reno"} {
			t.Run("server="+serverAlgorithm+"/client="+clientAlgorithm, func(t *testing.T) {
				in := Inbound{Type: "naive", Tag: "server", Listen: "127.0.0.1", Network: "udp", TLS: f.server(), Users: []User{{Username: "client", Password: "private"}}, QUICCongestionControl: serverAlgorithm}
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out := testOutbound(t, in, server.Address("server"))
				out.TLS, out.QUIC, out.UDPOverTCP, out.QUICCongestionControl = f.client(), true, true, clientAlgorithm
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 4096, 60000})
				wantClient, wantServer := clientAlgorithm, serverAlgorithm
				if wantClient == "" {
					wantClient = "cubic"
				}
				if wantServer == "" {
					wantServer = "bbr"
				}
				q, err := client.trustClients["proxy"].h3Session(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				assertNaiveController(t, q, wantClient)
				endpoint := server.quicListeners["server"]
				endpoint.mu.Lock()
				var peers []*quicConn
				for _, peer := range endpoint.conns {
					peers = append(peers, peer)
				}
				endpoint.mu.Unlock()
				if len(peers) == 0 {
					t.Fatal("server did not retain the live session")
				}
				for _, peer := range peers {
					assertNaiveController(t, peer, wantServer)
				}
				if serverAlgorithm == "" && clientAlgorithm == "" {
					client.resetNetworkTransports()
					assertTCP(t, client)
					next, err := client.trustClients["proxy"].h3Session(context.Background())
					if err != nil || next == q {
						t.Fatal("network rebuild reused retired session", err)
					}
					assertNaiveController(t, next, "cubic")
				}
			})
		}
	}
	t.Run("trusttunnel-default-unchanged", func(t *testing.T) {
		_, client := trustPair(t, 3)
		assertTCP(t, client)
		q, err := client.trustClients["proxy"].h3Session(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		assertNaiveController(t, q, "reno")
	})
}

func TestNaiveQUICCongestionReference(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if ref == "" || os.Getenv("LANBOAT_TEST_NAIVE") == "" {
		t.Fatal("LANBOAT_TEST_SINGBOX15 and LANBOAT_TEST_NAIVE required")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", ref)
	f := newMutualTLSFixture(t)
	for _, algorithm := range []string{"", "cubic", "bbr", "bbr2", "reno"} {
		t.Run("client/"+algorithm, func(t *testing.T) {
			in := Inbound{Type: "naive", Tag: "server", Listen: "127.0.0.1", ListenPort: unusedPort(t), TLS: f.server(), Users: []User{{Username: "client", Password: "private"}}, QUICCongestionControl: "bbr"}
			in.TLS.ClientAuthentication, in.TLS.ClientCertificate = "", nil
			referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
			out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
			out.TLS, out.QUIC, out.UDPOverTCP, out.QUICCongestionControl = f.client(), true, true, algorithm
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 4096, 14000})
		})
	}
	for _, algorithm := range []string{"", "cubic", "bbr", "reno"} {
		t.Run("server/"+algorithm, func(t *testing.T) {
			in := Inbound{Type: "naive", Tag: "server", Listen: "127.0.0.1", Network: "udp", TLS: f.server(), Users: []User{{Username: "client", Password: "private"}}, QUICCongestionControl: algorithm}
			in.TLS.ClientAuthentication, in.TLS.ClientCertificate = "", nil
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			_, port, _ := net.SplitHostPort(server.Address("server"))
			ca := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(ca, []byte(f.ca), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SSL_CERT_FILE", ca)
			local := portAddress("127.0.0.1", unusedPort(t))
			startTrustReference(t, "LANBOAT_TEST_NAIVE", "--listen=socks://"+local, "--proxy=quic://client:private@example.com:"+port, "--host-resolver-rules=MAP example.com 127.0.0.1", "--log")
			waitPort(t, local)
			out := testOutbound(t, Inbound{Type: "socks"}, local)
			out.Username, out.Password = "", ""
			assertTCP(t, newTestRuntime(t, Config{Outbounds: []Outbound{out}}))
		})
	}
}
