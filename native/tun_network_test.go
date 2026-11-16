package native

import "testing"

func TestTUNNetworkSessionRebuild(t *testing.T) {
	for _, kind := range []string{"anytls", "snell", "ssh", "wireguard", "hysteria2"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, kind)
			var sshHost string
			clientKey, clientPub := wgTestKey(t)
			serverKey, serverPub := wgTestKey(t)
			switch kind {
			case "snell":
				in.Password = "private"
				in.Version = "4"
			case "ssh":
				key, pub := sshTestKey(t)
				sshHost = pub
				in.PrivateKey = []string{key}
				in.Users = []User{{Username: "client", Password: "private"}}
			case "wireguard":
				in.PrivateKey = []string{serverKey}
				in.Peers = []WireGuardPeer{{PublicKey: clientPub, AllowedIPs: []string{"10.88.0.2/32"}}}
			case "hysteria2":
				in.TLS = certificate(t)
				in.TLS.ALPN = quicALPN(kind)
				in.Users = []User{{Password: "private"}}
			}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			switch kind {
			case "ssh":
				out.HostKey = []string{sshHost}
			case "snell":
				out.Version = "4"
				out.Multiplex.Enabled = true
			case "wireguard":
				out.PrivateKey = []string{clientKey}
				out.PublicKey = serverPub
				out.LocalAddress = []string{"10.88.0.2/32"}
			case "hysteria2":
				out.UUID = ""
				out.TLS.ALPN = quicALPN(kind)
			}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			client.resetNetworkTransports()
			client.resetNetworkTransports()
			assertTCP(t, client)
		})
	}
}
