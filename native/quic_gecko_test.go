package native

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func geckoTestFrame(id, index, count byte, padding int, chunk []byte) []byte {
	frame := make([]byte, 5+padding)
	frame[0], frame[1], frame[2] = 0x80, id, index<<4|count
	binary.BigEndian.PutUint16(frame[3:5], uint16(padding))
	return salamanderSeal(append(frame, chunk...), "gecko-test")
}

func TestGeckoWireAndRoundTrip(t *testing.T) {
	for _, sizes := range [][2]int{{0, 0}, {14, 163}, {512, 512}, {1000, 2048}} {
		t.Run(fmt.Sprint(sizes), func(t *testing.T) {
			options := quicObfsOptions{Type: "gecko", Password: "gecko-test", MinPacketSize: sizes[0], MaxPacketSize: sizes[1]}
			sender, receiver := newGecko(options), newGecko(options)
			for _, long := range []bool{false, true} {
				for _, size := range []int{1200, 71, 2} {
					want := bytes.Repeat([]byte{0x66}, size)
					if long {
						want[0] |= 0x80
					}
					var packets [][]byte
					err := sender.write(want, func(packet []byte) error { packets = append(packets, packet); return nil })
					if err != nil {
						t.Fatal(err)
					}
					if !long {
						if len(packets) != 1 {
							t.Fatal("short header was fragmented")
						}
						if got := receiver.open(packets[0], "client", time.Now()); !bytes.Equal(got, want) {
							t.Fatal("short header changed")
						}
						continue
					}
					if len(packets) < 2 || len(packets) > 8 {
						t.Fatal("invalid fragment count", len(packets))
					}
					var wire [][]byte
					var messageID byte
					for index, packet := range packets {
						if len(packet) < sender.low || len(packet) > sender.high {
							t.Fatal("padding outside configured range", len(packet))
						}
						plain, err := salamanderOpen(append([]byte(nil), packet...), options.Password)
						if err != nil {
							t.Fatal(err)
						}
						if index == 0 {
							messageID = plain[1]
						}
						if plain[0] != 0x80 || plain[1] != messageID || int(plain[2]>>4) != index || int(plain[2]&15) != len(packets) {
							t.Fatal("wire header", plain[:5])
						}
						padding := int(binary.BigEndian.Uint16(plain[3:5]))
						wire = append(wire, plain[5+padding:])
					}
					if !bytes.Equal(bytes.Join(wire, nil), want) {
						t.Fatal("wire chunks do not reconstruct input")
					}
					for index := len(packets) - 1; index >= 0; index-- {
						got := receiver.open(packets[index], "client", time.Now())
						if index != 0 && got != nil || index == 0 && !bytes.Equal(got, want) {
							t.Fatal("out-of-order reassembly", index, len(got))
						}
					}
					if receiver.bytes != 0 || len(receiver.messages) != 0 || len(receiver.peers) != 0 {
						t.Fatal("completed message retained")
					}
				}
			}
		})
	}
}

func TestGeckoMalformedAndBounds(t *testing.T) {
	now := time.Unix(100, 0)
	codec := newGecko(quicObfsOptions{Password: "gecko-test"})
	first := func(id byte) []byte { return geckoTestFrame(id, 0, 2, 0, []byte{0xc0, 1}) }
	if codec.open(first(1), "a", now) != nil || codec.open(first(1), "a", now) != nil || codec.bytes != 2 {
		t.Fatal("duplicate chunk retained")
	}
	if codec.open(geckoTestFrame(1, 1, 2, 0, []byte{2}), "b", now) != nil {
		t.Fatal("cross-source assembly")
	}
	if got := codec.open(geckoTestFrame(1, 1, 2, 2, []byte{2}), "a", now); !bytes.Equal(got, []byte{0xc0, 1, 2}) {
		t.Fatal("source isolation", got)
	}
	codec.open(first(2), "a", now)
	codec.open(geckoTestFrame(2, 1, 3, 0, []byte{3}), "a", now)
	if codec.messages[geckoKey{"a", 2}] != nil {
		t.Fatal("inconsistent fragment count retained")
	}
	for _, frame := range [][]byte{{}, {0x80}, {0x81, 1, 2, 0, 0, 1}, {0x80, 1, 1, 0, 0, 1}, {0x80, 1, 9, 0, 0, 1}, {0x80, 1, 0x22, 0, 0, 1}, {0x80, 1, 2, 0, 10, 1}, {0x80, 1, 2, 0, 1, 1}} {
		if codec.open(salamanderSeal(frame, "gecko-test"), "bad", now) != nil || codec.peers["bad"] != 0 {
			t.Fatal("malformed frame accepted", frame)
		}
	}
	for id := byte(0); id < 20; id++ {
		codec.open(first(id), "bounded", now)
	}
	if codec.peers["bounded"] != geckoMaxPerPeer {
		t.Fatal("per-peer bound", codec.peers)
	}
	for source := 0; source < 256; source++ {
		codec.open(first(0), fmt.Sprint(source), now)
	}
	if len(codec.messages) != geckoMaxMessages {
		t.Fatal("message count bound", len(codec.messages))
	}
	codec.open(first(99), "fresh", now.Add(geckoTTL))
	if len(codec.messages) != 1 || codec.bytes != 2 || len(codec.peers) != 1 {
		t.Fatal("expired fragments retained", len(codec.messages), codec.bytes, codec.peers)
	}
	// Fill many incomplete messages with maximum-sized chunks, not just headers.
	codec = newGecko(quicObfsOptions{Password: "gecko-test"})
	for source := 0; source < 128; source++ {
		for index := byte(0); index < 7; index++ {
			codec.open(geckoTestFrame(0, index, 8, 0, bytes.Repeat([]byte{0xc0}, 2035)), fmt.Sprint(source), now)
			if codec.bytes > geckoMaxBytes || len(codec.messages) > geckoMaxMessages {
				t.Fatal("unbounded reassembly storage", codec.bytes, len(codec.messages))
			}
		}
	}
	if codec.bytes < geckoMaxBytes/2 {
		t.Fatal("byte bound was not exercised", codec.bytes)
	}
	want := errors.New("write failed")
	if err := codec.write(bytes.Repeat([]byte{0xc0}, 1200), func([]byte) error { return want }); err != want {
		t.Fatal("write error swallowed", err)
	}
	for _, data := range [][]byte{nil, {0xc0}, bytes.Repeat([]byte{0xc0}, geckoMaxPacket+1)} {
		if err := codec.write(data, func([]byte) error { t.Fatal("invalid packet sent"); return nil }); err == nil {
			t.Fatal("invalid send length accepted", len(data))
		}
	}
}

func TestGeckoConfig(t *testing.T) {
	for _, tc := range []struct {
		fields string
		valid  bool
	}{
		{``, true}, {`,"min_packet_size":600,"max_packet_size":800`, true}, {`,"min_packet_size":14,"max_packet_size":163`, true},
		{`,"min_packet_size":-1`, false}, {`,"min_packet_size":1201`, false}, {`,"max_packet_size":2049`, false}, {`,"min_packet_size":14,"max_packet_size":162`, false}, {`,"host":"not-allowed"`, false},
	} {
		raw := []byte(`{"type":"gecko","password":"gecko-test"` + tc.fields + `}`)
		var obfs Obfuscation
		if err := json.Unmarshal(raw, &obfs); (err == nil) != tc.valid {
			t.Fatal(string(raw), err)
		}
		if tc.valid {
			settings, err := obfs.quicSettings()
			if err != nil || settings.Type != "gecko" || settings.Password != "gecko-test" {
				t.Fatal("settings", settings, err)
			}
		}
	}
}

func TestHysteria2GeckoIndependent(t *testing.T) {
	for _, sizes := range [][2]int{{0, 0}, {14, 163}, {512, 2048}} {
		t.Run(fmt.Sprint(sizes), func(t *testing.T) {
			in := Inbound{Type: "hysteria2", Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{Password: "private"}}, Obfs: Obfuscation(fmt.Sprintf(`{"type":"gecko","password":"gecko-test","min_packet_size":%d,"max_packet_size":%d}`, sizes[0], sizes[1]))}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Obfs = in.Obfs
			out.UpMbps, out.DownMbps = 100, 100
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 511, 4096, 60000})
		})
	}
}

func TestHysteria2GeckoReference(t *testing.T) {
	for _, direction := range []string{"client", "server"} {
		for _, custom := range []bool{false, true} {
			t.Run(fmt.Sprint(direction, "/", custom), func(t *testing.T) {
				obfs := Obfuscation(`{"type":"gecko","password":"gecko-test"}`)
				if custom {
					obfs = Obfuscation(`{"type":"gecko","password":"gecko-test","min_packet_size":600,"max_packet_size":1400}`)
				}
				in := Inbound{Type: "hysteria2", Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{Password: "private"}}, Obfs: obfs}
				in.TLS.ALPN = []string{"h3"}
				outbound := func(address string) Outbound {
					out := testOutbound(t, in, address)
					out.Username, out.UUID, out.Obfs, out.TLS.ALPN = "", "", obfs, []string{"h3"}
					out.UpMbps, out.DownMbps = 100, 100
					return out
				}
				var client *Runtime
				if direction == "client" {
					in.ListenPort = unusedPort(t)
					ready := Inbound{Type: "mixed", Tag: "ready", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
					referenceRuntime(t, Config{Inbounds: []Inbound{ready, in}})
					client = newTestRuntime(t, Config{Outbounds: []Outbound{outbound(portAddress(in.Listen, in.ListenPort))}})
				} else {
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					local := Inbound{Type: "mixed", Tag: "local", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
					referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{outbound(server.Address("server"))}})
					client = newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "proxy", Server: local.Listen, ServerPort: local.ListenPort}}})
				}
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 511, 4096})
			})
		}
	}
}

func FuzzGeckoReassembly(f *testing.F) {
	f.Add([]byte{0x80, 1, 2, 0, 0, 0xc0}, byte(3))
	f.Add([]byte{0x80, 1, 0x12, 0, 0, 3}, byte(9))
	f.Fuzz(func(t *testing.T, data []byte, peer byte) {
		if len(data) > 8192 {
			return
		}
		codec := newGecko(quicObfsOptions{Password: "gecko-test"})
		now := time.Unix(100, 0)
		for offset := 0; offset < min(len(data), 64); offset++ {
			codec.open(salamanderSeal(data[offset:], "gecko-test"), string([]byte{peer}), now.Add(time.Duration(offset)*time.Second))
			if codec.bytes > geckoMaxBytes || len(codec.messages) > geckoMaxMessages {
				t.Fatal("unbounded state")
			}
		}
	})
}
