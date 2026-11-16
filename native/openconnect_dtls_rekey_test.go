package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"
)

func dtls12Pair(t *testing.T, suite uint16) (*ocDTLS, *ocDTLS) {
	t.Helper()
	c, s := dtls13Pair(t, suite)
	c.v13, s.v13 = nil, nil
	if suite == 0 {
		c.suites, s.suites = nil, nil
		for _, spec := range ocDTLSSuites {
			c.suites = append(c.suites, spec.id)
			s.suites = append(s.suites, spec.id)
		}
	}
	c.appID = bytes.Repeat([]byte{3}, 32)
	s.appID = bytes.Clone(c.appID)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.handshake(ctx) }()
	ce, se := c.handshake(ctx), <-done
	if ce != nil || se != nil {
		t.Fatalf("initial handshake client=%v server=%v", ce, se)
	}
	t.Cleanup(func() { clear(c.secret[:]); clear(s.secret[:]) })
	return c, s
}

func dtls12RekeyRound(t *testing.T, sender, receiver *ocDTLS) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	done := make(chan error, 1)
	receiver.conn.SetDeadline(time.Now().Add(5 * time.Second))
	go func() {
		kind, data, err := receiver.read()
		if err == nil && (kind != 3 || string(data) != "rekey") {
			err = fmt.Errorf("wrong post-rekey message %d %q", kind, data)
		}
		if err == nil {
			err = receiver.write(4, data)
		}
		done <- err
	}()
	if err := sender.renegotiate(ctx, nil); err != nil {
		t.Fatal("rekey", err)
	}
	if err := sender.write(3, []byte("rekey")); err != nil {
		t.Fatal(err)
	}
	sender.conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	kind, data, err := sender.read()
	if err != nil || kind != 4 || string(data) != "rekey" {
		t.Fatal("reply", kind, string(data), err)
	}
	if err := <-done; err != nil {
		t.Fatal("receiver", err)
	}
}

func TestDTLS12Renegotiation(t *testing.T) {
	for _, spec := range ocDTLSSuites {
		t.Run(spec.name, func(t *testing.T) {
			c, s := dtls12Pair(t, spec.id)
			for round := range 4 {
				clientRandom, serverRandom := c.clientRandom, c.serverRandom
				clientVerify, serverVerify := c.clientVerify, c.serverVerify
				old, err := c.record(23, []byte{3, 9})
				if err != nil {
					t.Fatal(err)
				}
				old = bytes.Clone(old)
				a, b := c, s
				if round%2 != 0 {
					a, b = s, c
				}
				dtls12RekeyRound(t, a, b)
				if c.writeEpoch != uint16(round+2) || s.writeEpoch != c.writeEpoch || c.generation.Load() != uint64(round+1) || s.generation.Load() != c.generation.Load() {
					t.Fatal("epochs/generation did not advance")
				}
				if c.clientRandom == clientRandom || c.serverRandom == serverRandom || c.clientVerify == clientVerify || c.serverVerify == serverVerify {
					t.Fatal("rekey reused randoms or Finished")
				}
				if c.clientVerify != s.clientVerify || c.serverVerify != s.serverVerify {
					t.Fatal("Finished bindings disagree")
				}
				if _, _, ok := s.open(old); ok {
					t.Fatal("old epoch accepted after rekey")
				}
				if c.conn.RemoteAddr().String() != s.conn.LocalAddr().String() {
					t.Fatal("socket changed")
				}
			}
		})
	}
}

func TestDTLS12RenegotiationBinding(t *testing.T) {
	c, s := dtls12Pair(t, 0xa8)
	for _, client := range []bool{true, false} {
		previous := s
		if client {
			previous = c
		}
		next := &ocDTLS{client: client, previous: previous}
		verify := bytes.Clone(c.clientVerify[:])
		if client {
			verify = append(verify, c.serverVerify[:]...)
		}
		ext := ocDTLSExtensionFlags{ems: previous.ems, renegotiation: verify}
		if err := next.verifyRenegotiation(ext, nil); err != nil {
			t.Fatal(err)
		}
		for _, bad := range [][]byte{nil, {}, verify[:len(verify)-1], append(bytes.Clone(verify), 0), bytes.Repeat([]byte{0}, len(verify))} {
			ext.renegotiation = bad
			if err := next.verifyRenegotiation(ext, nil); err == nil {
				t.Fatal("bad Finished binding accepted")
			}
		}
		ext.renegotiation = verify
		if err := next.verifyRenegotiation(ext, []uint16{0xff}); err == nil {
			t.Fatal("SCSV accepted on renegotiation")
		}
		ext.ems = !previous.ems
		if err := next.verifyRenegotiation(ext, nil); err == nil {
			t.Fatal("EMS changed on renegotiation")
		}
	}
	for _, body := range [][]byte{{0xff, 1, 0, 0}, {0xff, 1, 0, 1, 12}, {0xff, 1, 0, 2, 0, 0}, {0xff, 1, 0, 26, 25}} {
		if _, err := ocDTLSExtensions(append(binary.BigEndian.AppendUint16(nil, uint16(len(body))), body...)); err == nil {
			t.Fatal("malformed renegotiation extension accepted")
		}
	}
	for _, peer := range []*ocDTLS{c, s} {
		peer.secureRenegotiation = false
		if err := peer.renegotiate(context.Background(), nil); err == nil || peer.writeEpoch != 1 {
			t.Fatal("insecure renegotiation accepted")
		}
	}
}

func TestOpenConnectDTLSRenegotiation(t *testing.T) {
	in := Inbound{Type: "openconnect", Tag: "server", Listen: "127.0.0.1", Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t), OpenConnectOptions: OpenConnectOptions{DTLSRekeyTime: "2s", DTLSRekeyMethod: "ssl"}}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	host, port := splitTestAddress(t, s.Address("server"))
	c := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "openconnect", Tag: "proxy", Server: host, ServerPort: port, Username: "client", Password: "private", TLS: TLSOptions{Enabled: true, Insecure: true}}}})
	tunnel, err := c.ocClients["proxy"].session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	d := ocWaitDTLS(t, tunnel)
	address := d.conn.LocalAddr().String()
	probe, err := c.Dial(context.Background(), "tcp", relayEchoTCP(t))
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	deadline := time.Now().Add(4300 * time.Millisecond)
	for time.Now().Before(deadline) {
		probe.SetDeadline(time.Now().Add(time.Second))
		if _, err = io.WriteString(probe, "keep"); err != nil {
			t.Fatal("existing TCP write", err)
		}
		got := make([]byte, 4)
		if _, err = io.ReadFull(probe, got); err != nil || string(got) != "keep" {
			t.Fatal("existing TCP read", err)
		}
		assertUDPSizes(t, c, []int{1, 4096})
		time.Sleep(50 * time.Millisecond)
	}
	if d.generation.Load() < 2 || d.generation.Load() > 3 || !d.ready.Load() || d.conn.LocalAddr().String() != address || ocWaitDTLS(t, tunnel) != d || c.ocClients["proxy"].tunnel.Load() != tunnel {
		t.Fatal("DTLS ssl rekey recreated socket/channel/CSTP or failed")
	}
	assertUDPSizes(t, c, []int{1, 60000})
	if d.sent.Load() == 0 || d.received.Load() == 0 {
		t.Fatal("CSTP concealed DTLS failure")
	}
}

func TestOpenConnectDTLSRenegotiationConfig(t *testing.T) {
	in := Inbound{Type: "openconnect", Tag: "server", Listen: "127.0.0.1", Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t)}
	for _, opt := range []OpenConnectOptions{
		{DTLSRekeyMethod: "ssl"},
		{DTLSRekeyMethod: "invalid", DTLSRekeyTime: "1s"},
		{DTLSRekeyMethod: "ssl", DTLSRekeyTime: "1s", DTLSVersion: "1.3"},
		{DTLSRekeyMethod: "ssl", DTLSRekeyTime: "1s", DisableDTLS: true},
	} {
		in.OpenConnectOptions = opt
		raw, _ := json.Marshal(Config{Inbounds: []Inbound{in}})
		if _, err := Parse(raw); err == nil {
			t.Fatal("bad rekey configuration accepted", opt)
		}
	}
	in.OpenConnectOptions = OpenConnectOptions{DTLSRekeyMethod: "ssl", DTLSRekeyTime: "2s"}
	raw, _ := json.Marshal(Config{Inbounds: []Inbound{in}})
	if _, err := Parse(raw); err != nil {
		t.Fatal(err)
	}
	if got := in.rekeyHeaders()["X-DTLS-Rekey-Method"][0]; got != "ssl" {
		t.Fatal(got)
	}
}

func TestDTLS12RenegotiationExhaustion(t *testing.T) {
	c, _ := dtls12Pair(t, 0xa8)
	c.writeSeq = c.recordLimit()
	if err := c.renegotiate(context.Background(), nil); err == nil || c.ready.Load() {
		t.Fatal("old-key record exhaustion ignored")
	}
	if c.writeEpoch != 1 {
		t.Fatal("epoch changed after a failed record")
	}
}

func TestDTLS12RenegotiationCipherChange(t *testing.T) {
	c, s := dtls12Pair(t, 0)
	for _, spec := range ocDTLSSuites {
		s.suites = []uint16{spec.id}
		dtls12RekeyRound(t, c, s)
		if c.suite != spec.id || s.suite != spec.id {
			t.Fatal("new cipher not selected", spec.name)
		}
	}
}

func FuzzDTLS12Renegotiation(f *testing.F) {
	binding := bytes.Repeat([]byte{3}, 12)
	f.Add(ocDTLSAppendExtensions(nil, true, true, binding))
	f.Add([]byte{0, 5, 255, 1, 0, 1, 0})
	f.Add(ocDTLSRecordHeader(22, 2, 0, 0))
	f.Fuzz(func(t *testing.T, b []byte) {
		ext, err := ocDTLSExtensions(b)
		previous := &ocDTLS{ems: true}
		copy(previous.clientVerify[:], binding)
		next := &ocDTLS{client: true, previous: previous, baseEpoch: 1}
		if err == nil {
			_ = next.verifyRenegotiation(ext, nil)
		}
		_, _, _, _, _, _ = ocDTLSClientHello(b)
		previous.ready.Store(true)
		previous.baseEpoch = 1
		_, _, _ = next.open(b)
	})
}
