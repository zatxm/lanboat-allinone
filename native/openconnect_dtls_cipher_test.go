package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"slices"
	"testing"
	"time"
)

func TestOpenConnectDTLSCipherTraffic(t *testing.T) {
	for _, spec := range ocDTLSSuites {
		t.Run(spec.name, func(t *testing.T) {
			_, c := ocPair(t, spec.name)
			for round := range 2 {
				tunnel, err := c.ocClients["proxy"].session(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				d := ocWaitDTLS(t, tunnel)
				if d.suite != spec.id {
					t.Fatalf("requested %x,negotiated %x", spec.id, d.suite)
				}
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{0, 1, 511, 4096, 60000})
				assertUDPAddress(t, c, []int{1, 4096, 60000}, masqueEcho(t, "udp", "[::1]:0"))
				if d.sent.Load() == 0 || d.received.Load() == 0 {
					t.Fatal("CSTP concealed failed DTLS traffic")
				}
				if round == 0 {
					c.resetNetworkTransports()
				}
			}
		})
	}
}

func TestOpenConnectDTLSCipherExhaustion(t *testing.T) {
	for _, spec := range ocDTLSSuites {
		t.Run(spec.name, func(t *testing.T) {
			_, c := ocPair(t, spec.name)
			tunnel, err := c.ocClients["proxy"].session(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			d := ocWaitDTLS(t, tunnel)
			d.writeMu.Lock()
			d.writeSeq = d.recordLimit()
			d.writeMu.Unlock()
			assertTCP(t, c)
			if d.ready.Load() {
				t.Fatal("exhausted DTLS keys still active")
			}
			next := ocWaitDTLS(t, tunnel)
			if next == d || next.clientRandom == d.clientRandom || next.serverRandom == d.serverRandom {
				t.Fatal("DTLS keys not renewed")
			}
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{1, 4096})
			if next.sent.Load() == 0 || next.received.Load() == 0 {
				t.Fatal("renewed DTLS keys did not transfer IP data")
			}
		})
	}
}

func TestOpenConnectDTLSCipherConfig(t *testing.T) {
	_, c := ocPair(t)
	base := c.config.Outbounds[0]
	for _, names := range [][]string{{}, {"unknown"}, {"TLS_RSA_WITH_AES_128_GCM_SHA256"}, {"PSK-AES128-CCM", "PSK-AES128-CCM"}} {
		o := base
		o.DTLSCipherSuites = names
		raw, _ := json.Marshal(Config{Outbounds: []Outbound{o}})
		if len(names) == 0 {
			var document map[string]json.RawMessage
			json.Unmarshal(raw, &document)
			var outs []map[string]json.RawMessage
			json.Unmarshal(document["outbounds"], &outs)
			outs[0]["dtls_cipher_suites"] = json.RawMessage(`[]`)
			document["outbounds"], _ = json.Marshal(outs)
			raw, _ = json.Marshal(document)
		}
		if _, err := Parse(raw); err == nil {
			t.Fatal("invalid cipher configuration accepted", names)
		}
	}
	for _, kind := range []string{"socks", "http", "trojan"} {
		o := base
		o.Type = kind
		o.Group = ""
		o.Username = ""
		o.DTLSCipherSuites = []string{"PSK-AES128-CCM"}
		raw, _ := json.Marshal(Config{Outbounds: []Outbound{o}})
		if _, err := Parse(raw); err == nil {
			t.Fatal("DTLS cipher on wrong protocol accepted", kind)
		}
	}
	base.DisableDTLS = true
	base.DTLSCipherSuites = []string{"PSK-AES128-CCM"}
	raw, _ := json.Marshal(Config{Outbounds: []Outbound{base}})
	if _, err := Parse(raw); err == nil {
		t.Fatal("disabled DTLS options ignored")
	}
	for _, spec := range ocDTLSSuites {
		if ids, err := ocDTLSCipherIDs([]string{spec.name}); err != nil || !slices.Equal(ids, []uint16{spec.id}) {
			t.Fatal(spec.name, ids, err)
		}
	}
}

func TestOpenConnectDTLSCipherNegotiation(t *testing.T) {
	client := &ocDTLS{client: true, appID: bytes.Repeat([]byte{1}, 32)}
	_, _, _, offered, _, err := ocDTLSClientHello(client.hello(nil))
	if err != nil || !slices.Equal(offered, ocDTLSDefaults) || slices.Contains(offered, uint16(0xc0a8)) || slices.Contains(offered, uint16(0xc0a9)) {
		t.Fatal("default cipher offer", offered, err)
	}
	for _, suite := range []uint16{0xc0a8, 0xdead, 0x008c} {
		body := append([]byte{0xfe, 0xfd}, make([]byte, 32)...)
		body = binary.BigEndian.AppendUint16(append(body, 0), suite)
		body = append(body, 0)
		d := &ocDTLS{client: true, suites: []uint16{0x00a8}}
		if d.message(2, body, nil) == nil {
			t.Fatal("unoffered server cipher accepted", suite)
		}
	}
	d := &ocDTLS{suite: 0xdead}
	if d.keys() == nil {
		t.Fatal("unknown cipher keys created")
	}
}

func TestOpenConnectDTLSRecordBounds(t *testing.T) {
	for _, spec := range ocDTLSSuites {
		t.Run(spec.name, func(t *testing.T) {
			c := &ocDTLS{client: true, suite: spec.id, psk: bytes.Repeat([]byte{3}, 32), writeEpoch: 1, ccs: true}
			s := &ocDTLS{suite: spec.id, psk: bytes.Repeat([]byte{3}, 32), writeEpoch: 1, ccs: true}
			if err := c.keys(); err != nil {
				t.Fatal(err)
			}
			if err := s.keys(); err != nil {
				t.Fatal(err)
			}
			for _, size := range []int{0, 1, 15, 16, 17, 16383, 16384} {
				plain := bytes.Repeat([]byte{byte(size)}, size)
				wire, err := c.record(23, plain)
				if err != nil {
					t.Fatal(err)
				}
				explicit := 8
				if spec.id == 0xccab {
					explicit = 0
				}
				length := 0
				if c.cbc != nil {
					length = 13 + 16 + ((size+c.cbc.writeMAC.Size())/16+1)*16
				} else {
					length = 13 + explicit + size + c.writeKey.Overhead()
				}
				if len(wire) != length {
					t.Fatal("wrong nonce or tag layout")
				}
				for i := range wire {
					bad := bytes.Clone(wire)
					bad[i] ^= 1
					if _, _, ok := s.open(bad); ok {
						t.Fatal("forged byte accepted", size, i)
					}
					if size > 32 && i >= 32 {
						break
					}
				}
				kind, got, ok := s.open(wire)
				if !ok || kind != 23 || !bytes.Equal(got, plain) {
					t.Fatal("boundary plaintext", size, ok)
				}
				if _, _, ok = s.open(wire); ok {
					t.Fatal("replay accepted")
				}
			}
			if _, err := c.record(23, make([]byte, 16385)); err == nil {
				t.Fatal("oversized record accepted")
			}
			c.writeSeq = c.recordLimit() - 1
			wire, err := c.record(23, []byte{7})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, ok := s.open(wire); !ok {
				t.Fatal("last valid record rejected")
			}
			if _, err = c.record(23, []byte{8}); err == nil {
				t.Fatal("per-key limit ignored")
			}
			s.failures = 1 << 16
			if _, _, err = s.read(); err == nil {
				t.Fatal("authentication budget ignored")
			}
		})
	}
}

func TestOpenConnectDTLSCipherServerPreference(t *testing.T) {
	server := &ocDTLS{suites: []uint16{0xccab, 0x00a8}, appID: bytes.Repeat([]byte{1}, 32)}
	client := &ocDTLS{appID: bytes.Clone(server.appID), suites: []uint16{0x00a8, 0xccab}}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	left.SetDeadline(time.Now().Add(time.Second))
	server.conn = left
	done := make(chan error, 1)
	go func() { done <- server.message(1, client.hello(nil), ocDTLSHandshakeMessage(1, 0, client.hello(nil))) }()
	if _, err := right.Read(make([]byte, 2048)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil || server.suite != 0xccab {
		t.Fatal("server cipher order", server.suite, err)
	}
}

func BenchmarkOpenConnectDTLSRecord(b *testing.B) {
	for _, spec := range ocDTLSSuites {
		b.Run(spec.name, func(b *testing.B) {
			d := &ocDTLS{client: true, suite: spec.id, psk: bytes.Repeat([]byte{3}, 32), writeEpoch: 1}
			if err := d.keys(); err != nil {
				b.Fatal(err)
			}
			payload := make([]byte, 1280)
			if _, err := d.record(23, payload); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := d.record(23, payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func FuzzOpenConnectDTLSCipherRecords(f *testing.F) {
	for i := range ocDTLSSuites {
		f.Add([]byte("packet"), byte(i), uint16(13))
		if ocDTLSIsCBC(ocDTLSSuites[i].id) {
			f.Add([]byte("packet"), byte(i)|0x80, uint16(29))
		}
	}
	f.Fuzz(func(t *testing.T, plain []byte, index byte, at uint16) {
		if len(plain) > 16384 {
			return
		}
		spec := ocDTLSSuites[int(index&0x7f)%len(ocDTLSSuites)]
		etm := ocDTLSIsCBC(spec.id) && index&0x80 != 0
		c := &ocDTLS{client: true, suite: spec.id, psk: bytes.Repeat([]byte{5}, 32), writeEpoch: 1, etm: etm}
		s := &ocDTLS{suite: spec.id, psk: bytes.Repeat([]byte{5}, 32), ccs: true, etm: etm}
		if err := c.keys(); err != nil {
			t.Fatal(err)
		}
		if err := s.keys(); err != nil {
			t.Fatal(err)
		}
		wire, err := c.record(23, plain)
		if err != nil {
			t.Fatal(err)
		}
		bad := bytes.Clone(wire)
		bad[int(at)%len(bad)] ^= 1
		if _, _, ok := s.open(bad); ok {
			t.Fatal("modified authenticated record accepted")
		}
		kind, got, ok := s.open(wire)
		if !ok || kind != 23 || !bytes.Equal(got, plain) {
			t.Fatal("valid record rejected after forgery")
		}
		if _, _, ok := s.open(wire); ok {
			t.Fatal("replay accepted")
		}
	})
}
