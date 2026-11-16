package native

import "testing"

func TestHY1InitialDatagramLimit(t *testing.T) {
	for _, kind := range []string{"hysteria", "hysteria2", "tuic", "juicity"} {
		t.Run(kind, func(t *testing.T) {
			for _, server := range []bool{false, true} {
				o := proxyQUICOptions(kind, "").defaults()
				params := quicConnectionParameters([]byte("12345678"), []byte("abcdefgh"), nil, server, o)
				p, err := parseQUICParameters(params, []byte("12345678"), []byte("abcdefgh"), nil, !server)
				if err != nil {
					t.Fatal(err)
				}
				want := uint64(1400)
				if kind == "hysteria" {
					want = 1136
				}
				if p.maxDatagram != want || p.maxUDPPayload != 1472 {
					t.Fatal("datagram limit changed stream MTU", p.maxDatagram, p.maxUDPPayload)
				}
			}
		})
	}
}
