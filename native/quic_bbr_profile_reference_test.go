package native

import (
	"os"
	"testing"
)

func TestBBRProfileReference(t *testing.T) {
	reference := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if reference == "" {
		t.Skip("LANBOAT_TEST_SINGBOX15 is required for bbr_profile interoperability")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", reference)
	for _, profile := range []string{"conservative", "standard", "aggressive"} {
		for _, direction := range []string{"client", "server"} {
			t.Run(profile+"/"+direction, func(t *testing.T) {
				in := Inbound{Type: "hysteria2", Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{Password: "private"}}, IgnoreClientBandwidth: true, BBRProfile: profile}
				var client *Runtime
				if direction == "client" {
					in.ListenPort = unusedPort(t)
					ready := Inbound{Type: "mixed", Tag: "ready", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
					referenceRuntime(t, Config{Inbounds: []Inbound{ready, in}})
					out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
					out.Username, out.UUID = "", ""
					out.BBRProfile = profile
					client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				} else {
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					out := testOutbound(t, in, server.Address("server"))
					out.Username, out.UUID = "", ""
					out.BBRProfile = profile
					local := Inbound{Type: "mixed", Tag: "local", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
					referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{out}, Route: Route{Final: "proxy"}})
					front := testOutbound(t, local, portAddress(local.Listen, local.ListenPort))
					front.Username, front.Password = "", ""
					client = newTestRuntime(t, Config{Outbounds: []Outbound{front}})
				}
				assertTCP(t, client)
				// The pinned reference's HY2 UDP buffer is limited to 4096 bytes.
				assertUDPSizes(t, client, []int{1, 511, 4096})
			})
		}
	}
}
