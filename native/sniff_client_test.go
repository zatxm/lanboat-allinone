package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestQUICClientCaptures(t *testing.T) {
	manifest := os.Getenv("LANBOAT_TEST_QUIC_CAPTURES")
	if manifest == "" {
		t.Skip("set LANBOAT_TEST_QUIC_CAPTURES to the pinned capture manifest")
	}
	var data struct {
		Cases []struct {
			Name, Want string
			Flows      []struct {
				DCID      string
				Want      string
				Datagrams []string
			}
		}
	}
	b, e := os.ReadFile(manifest)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &data); e != nil {
		t.Fatal(e)
	}
	for _, test := range data.Cases {
		for _, flow := range test.Flows {
			t.Run(test.Name+"/"+flow.DCID, func(t *testing.T) {
				var packets [][]byte
				for _, name := range flow.Datagrams {
					b, e := os.ReadFile(name)
					if e != nil {
						t.Fatal(e)
					}
					packets = append(packets, b)
				}
				for n := 1; n <= len(packets); n++ {
					_, client, complete, _ := sniffQUICInfo(bytes.Join(packets[:n], nil))
					if complete && client != "" {
						packets = packets[:n]
						break
					}
				}
				want := test.Want
				if flow.Want != "" {
					want = flow.Want
				}
				host, client, complete, more := sniffQUICInfo(bytes.Join(packets, nil))
				if !complete || more || client != want {
					t.Fatalf("host=%q client=%q complete=%v more=%v want=%s", host, client, complete, more, want)
				}
				for _, order := range [][][]byte{packets, reverseQUICPackets(packets)} {
					var wire []byte
					for _, p := range order {
						wire = append(wire, p...)
						wire = append(wire, p...)
					}
					_, client, ok, more := sniffQUICInfo(wire)
					if !ok || more || client != want {
						t.Fatal("reordering/retransmission", client, ok, more)
					}
				}
			})
		}
	}
}
func reverseQUICPackets(packets [][]byte) [][]byte {
	out := make([][]byte, len(packets))
	for i, p := range packets {
		out[len(out)-1-i] = p
	}
	return out
}

func TestQUICClientRouteMetadata(t *testing.T) {
	for _, client := range []string{"chromium", "firefox", "safari", "quic-go", "unknown"} {
		t.Run(client, func(t *testing.T) {
			rules, e := compileRoute(Route{Final: "direct", Rules: []Rule{{Client: []string{client}, Action: "reject"}}}, map[string]Outbound{"direct": {Type: "direct"}})
			if e != nil {
				t.Fatal(e)
			}
			q := request{network: "udp", address: "192.0.2.1:443", metadata: Metadata{Client: client}}
			if !rules[0].matches(q) {
				t.Fatal("client did not match")
			}
			q.metadata.Client = "different"
			if rules[0].matches(q) {
				t.Fatal("wrong client matched")
			}
			q.preMatch = true
			q.metadata.Client = ""
			if !rules[0].preMatchNeedsData(q) {
				t.Fatal("unknown client was treated as complete metadata")
			}
		})
	}
	if _, e := Parse([]byte(`{"route":{"rules":[{"type":"logical","mode":"or","client":"chromium","rules":[{"domain":"test"}],"action":"reject"}]}}`)); e == nil {
		t.Fatal("client allowed outside logical child")
	}
	for _, rule := range []Rule{{Client: []string{"chromium"}}, {Type: "logical", Mode: "or", Rules: []Rule{{Client: []string{"firefox"}}}}} {
		if _, e := compileRuleSet([]Rule{rule}); e == nil {
			t.Fatal("route-only client accepted in headless rule set")
		}
	}
}

func TestQUICClientChromiumLocalCapture(t *testing.T) {
	directory := os.Getenv("LANBOAT_TEST_CHROME_CAPTURE")
	if directory == "" {
		t.Skip("set LANBOAT_TEST_CHROME_CAPTURE for isolated real Chromium capture")
	}
	files, e := filepath.Glob(filepath.Join(directory, "chromium-*.bin"))
	if e != nil || len(files) < 2 {
		t.Fatal(e, files)
	}
	var packets [][]byte
	for _, file := range files {
		b, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		packets = append(packets, b)
	}
	for n := 1; n <= len(packets); n++ {
		_, client, complete, _ := sniffQUICInfo(bytes.Join(packets[:n], nil))
		if complete && client != "" {
			packets = packets[:n]
			break
		}
	}
	host, client, ok, more := sniffQUICInfo(bytes.Join(packets, nil))
	if host != "quic.test" || client != "chromium" || !ok || more {
		t.Fatal(host, client, ok, more)
	}
}

func TestQUICClientCaptureRouting(t *testing.T) {
	manifest := os.Getenv("LANBOAT_TEST_QUIC_CAPTURES")
	if manifest == "" {
		t.Skip("set LANBOAT_TEST_QUIC_CAPTURES for capture routing")
	}
	var captures struct {
		Cases []struct {
			Name, Want string
			Flows      []struct {
				Want      string
				Datagrams []string
			}
		}
	}
	data, e := os.ReadFile(manifest)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(data, &captures); e != nil {
		t.Fatal(e)
	}
	for _, test := range captures.Cases {
		t.Run(test.Name, func(t *testing.T) {
			if len(test.Flows) == 0 {
				t.Fatal("no flows")
			}
			echo := echoUDP(t)
			host, port := splitTestAddress(t, echo)
			want := test.Want
			if test.Flows[0].Want != "" {
				want = test.Flows[0].Want
			}
			cfg := Config{ExternalController: "127.0.0.1:0", Route: Route{Rules: []Rule{{Action: "sniff", Sniffer: []string{"quic"}}, {Client: []string{want}, Action: "route-options", OverrideAddress: host, OverridePort: port}, {Client: []string{want}, Outbound: "direct"}, {Action: "reject"}}}}
			r, logs := loggingRuntime(t, cfg)
			c, e := r.Dial(context.Background(), "udp", "192.0.2.1:443")
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			var sent [][]byte
			for _, file := range test.Flows[0].Datagrams {
				b, e := os.ReadFile(file)
				if e != nil {
					t.Fatal(e)
				}
				sent = append(sent, b)
				if _, e = c.Write(b); e != nil {
					t.Fatal(e)
				}
			}
			for _, want := range sent {
				got := make([]byte, 65535)
				n, e := c.Read(got)
				if e != nil || !bytes.Equal(got[:n], want) {
					t.Fatal("capture payload changed", e, n)
				}
			}
			rows := controllerRows(t, r)
			if len(rows) != 1 || rows[0].(map[string]any)["metadata"].(map[string]any)["client"] != want {
				t.Fatal(rows)
			}
			if logs.FilterMessageSnippet(", client: "+want).Len() == 0 {
				t.Fatal("sniffed client missing from connection log")
			}
		})
	}
}

func TestQUICClientUQUICReference(t *testing.T) {
	reference := os.Getenv("LANBOAT_TEST_UQUIC")
	if reference == "" {
		t.Skip("set LANBOAT_TEST_UQUIC to the separate uQUIC reference")
	}
	for _, test := range []struct{ name, want string }{{"chrome115", "quic-go"}, {"chrome146", "quic-go"}, {"firefox116", "firefox"}} {
		t.Run(test.name, func(t *testing.T) {
			s, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, reference, test.name, s.LocalAddr().String())
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cmd.Process.Kill(); cmd.Wait() }()
			s.SetReadDeadline(time.Now().Add(3 * time.Second))
			var wire []byte
			for len(wire) < sniffLimit {
				b := make([]byte, 65535)
				n, _, err := s.ReadFrom(b)
				if err != nil {
					t.Fatal("reference Initial capture", err)
				}
				wire = append(wire, b[:n]...)
				host, client, ok, more := sniffQUICInfo(wire)
				if !ok || more {
					continue
				}
				// A randomized Chrome parrot can match Chromium or leave insufficient layout evidence.
				matched := client == test.want || test.name != "firefox116" && (client == "chromium" || client == "unknown")
				if host != "reference.quic.test" || !matched {
					t.Fatal(host, client, test.want)
				}
				return
			}
			t.Fatal("reference ClientHello exceeds sniff limit")
		})
	}
}

func TestQUICClientZeroRTTHeader(t *testing.T) {
	id := []byte("12345678")
	wire := append([]byte{0xd0, 0, 0, 0, 1, 8}, id...)
	wire = append(wire, 0, 20)
	wire = append(wire, make([]byte, 20)...)
	h, err := parseQUICHeaderVersion(wire, quicVersion)
	if err != nil || h.level != 3 || h.end != len(wire) {
		t.Fatal(h, err)
	}
	if _, err = parseQUICHeader(wire); err == nil {
		t.Fatal("endpoint accepted unsupported 0-RTT")
	}
	hello := sniffTestHello(t)
	cut := len(hello) / 2
	a := sniffTestQUIC(t, id, 0, 0, hello[:cut])
	b := sniffTestQUIC(t, id, 1, uint64(cut), hello[cut:])
	for _, payload := range [][][]byte{{a, wire, b}, {b, wire, a}} {
		host, _, ok, more := sniffQUICInfo(bytes.Join(payload, nil))
		if host != "fragment.test" || !ok || more {
			t.Fatal(host, ok, more)
		}
	}
}

func quicClientTestHello() []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0)
	var extensions []byte
	for _, ext := range []struct {
		id   uint16
		data []byte
	}{{10, []byte{0, 2, 0, 29}}, {13, []byte{0, 2, 4, 3}}, {43, []byte{2, 3, 4}}, {57, nil}} {
		extensions = binary.BigEndian.AppendUint16(extensions, ext.id)
		extensions = binary.BigEndian.AppendUint16(extensions, uint16(len(ext.data)))
		extensions = append(extensions, ext.data...)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)
	return append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func TestQUICClientTraitsBounds(t *testing.T) {
	hello := quicClientTestHello()
	if _, valid := parseQUICHelloTraits(hello); !valid {
		t.Fatal("valid hello rejected")
	}
	for n := range len(hello) {
		if _, valid := parseQUICHelloTraits(hello[:n]); valid {
			t.Fatal("truncated hello accepted", n)
		}
	}
	for _, data := range [][]byte{nil, append(bytes.Clone(hello), 0), {1, 0xff, 0xff, 0xff}} {
		if got := classifyQUICClient(quicClientFrames{ping: 1}, data); got != "unknown" {
			t.Fatal(got)
		}
	}
}

func FuzzQUICClientTraits(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0})
	f.Add(quicClientTestHello())
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > sniffLimit {
			return
		}
		parseQUICHelloTraits(b)
		classifyQUICClient(quicClientFrames{ping: 1}, b)
	})
}
