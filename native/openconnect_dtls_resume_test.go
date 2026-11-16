package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestOpenConnectDTLSResumeTraffic(t *testing.T) {
	for _, version := range []string{"0.9", "1.2"} {
		for i, spec := range ocDTLSResumeSuites {
			if version == "0.9" && i > 4 || version == "1.2" && i == 4 {
				continue
			}
			t.Run(version+"/"+spec.name, func(t *testing.T) {
				_, c := ocOptionsPair(t, OpenConnectOptions{DTLSMode: "resume", DTLSVersion: version, DTLSCipherSuites: []string{spec.name}})
				tunnel, err := c.ocClients["proxy"].session(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				d := ocWaitDTLS(t, tunnel)
				if d.suite != spec.id || d.resume == nil || d.secret != nil {
					t.Fatal("wrong DTLS channel", d.suite)
				}
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{0, 1, 511, 4096, 60000})
				if d.sent.Load() == 0 || d.received.Load() == 0 {
					t.Fatal("CSTP concealed missing DTLS traffic")
				}
				if d.resume.master != [48]byte{} || c.ocClients["proxy"].connectMaster != [48]byte{} {
					t.Fatal("handshake master retained")
				}
				if spec.id == 0x000a {
					d.writeMu.Lock()
					d.writeSeq = d.recordLimit()
					d.writeMu.Unlock()
					assertTCP(t, c)
				} else {
					d.conn.Close()
				}
				deadline := time.Now().Add(time.Second)
				for d.ready.Load() && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				next := ocWaitDTLS(t, tunnel)
				if next == d || next.clientRandom == d.clientRandom || next.serverRandom == d.serverRandom {
					t.Fatal("DTLS keys not refreshed")
				}
				assertTCP(t, c)
			})
		}
	}
}

func TestOpenConnectDTLSResumeRecords(t *testing.T) {
	for _, version := range []uint16{0x0100, 0xfefd} {
		for i, spec := range ocDTLSResumeSuites {
			if version == 0x0100 && i > 4 || version == 0xfefd && i == 4 {
				continue
			}
			t.Run(hex.EncodeToString(binary.BigEndian.AppendUint16(nil, version))+"/"+spec.name, func(t *testing.T) {
				resume := ocDTLSResume{version: version, suite: spec.id}
				copy(resume.master[:], bytes.Repeat([]byte{7}, 48))
				cp, sp := resume, resume
				c := &ocDTLS{client: true, resume: &cp, writeEpoch: 1, ccs: true}
				s := &ocDTLS{resume: &sp, writeEpoch: 1, ccs: true}
				if err := c.keys(); err != nil {
					t.Fatal(err)
				}
				if err := s.keys(); err != nil {
					t.Fatal(err)
				}
				for _, n := range []int{0, 1, 7, 8, 15, 16, 31, 32, 511, 16384} {
					data := bytes.Repeat([]byte{byte(n)}, n)
					wire, err := c.record(23, data)
					if err != nil {
						t.Fatal(err)
					}
					for _, at := range []int{0, 1, 5, len(wire) - 1} {
						bad := bytes.Clone(wire)
						bad[at] ^= 1
						if _, _, ok := s.open(bad); ok {
							t.Fatal("tamper accepted", at)
						}
					}
					kind, got, ok := s.open(wire)
					if !ok || kind != 23 || !bytes.Equal(data, got) {
						t.Fatal("record mismatch", n, kind, ok)
					}
					if _, _, ok = s.open(wire); ok {
						t.Fatal("replay accepted")
					}
				}
			})
		}
	}
}

func TestOpenConnectDTLSResumeConfig(t *testing.T) {
	tls := TLSOptions{Enabled: true}
	for _, o := range []OpenConnectOptions{
		{DTLSVersion: "0.9", DTLSMode: "psk"}, {DTLSVersion: "1.3", DTLSMode: "resume"}, {DTLSMode: "bad"},
		{DTLSMode: "resume", DTLSCipherSuites: []string{"PSK-AES128-GCM-SHA256"}},
		{DTLSVersion: "0.9", DTLSCipherSuites: []string{"AES128-GCM-SHA256"}},
		{DTLSMode: "resume", DTLSCipherSuites: []string{"DES-CBC3-SHA"}},
		{DTLSMode: "resume", DTLSRekeyTime: "30s", DTLSRekeyMethod: "ssl"},
		{DisableDTLS: true, DTLSMode: "resume"},
	} {
		if o.validate("openconnect", tls, Transport{}, 0, nil) == nil {
			t.Fatal("bad DTLS options accepted", o)
		}
	}
	for _, o := range []OpenConnectOptions{{DTLSVersion: "0.9"}, {DTLSVersion: "1.2", DTLSMode: "resume"}, {DTLSMode: "psk"}, {}} {
		if err := o.validate("openconnect", tls, Transport{}, 0, nil); err != nil {
			t.Fatal(o, err)
		}
	}
	o := OpenConnectOptions{DTLSVersion: "0.9"}
	h := http.Header{}
	h.Set(o.dtlsCipherHeader(), "AES128-SHA")
	if !o.dtlsAccepted(h) {
		t.Fatal("allowed suite rejected")
	}
	h.Set(o.dtlsCipherHeader(), "PSK-NEGOTIATE")
	if o.dtlsAccepted(h) {
		t.Fatal("mode downgrade accepted")
	}
	d := &ocDTLS{resume: &ocDTLSResume{version: 0x0100}, recvNext: 0}
	if d.resumeCCS([]byte{1, 0, 7}) == nil {
		t.Fatal("CCS sequence jump accepted")
	}
}

func TestOpenConnectDTLSResumeLossAndAuthentication(t *testing.T) {
	for _, version := range []uint16{0x0100, 0xfefd} {
		for _, mode := range []string{"drop-hello", "drop-server", "drop-final", "ccs-first", "finished-first", "wrong-master", "wrong-id"} {
			t.Run(hex.EncodeToString(binary.BigEndian.AppendUint16(nil, version))+"/"+mode, func(t *testing.T) {
				c, s := dtls13Pair(t, 0x002f)
				for _, d := range []*ocDTLS{c, s} {
					d.v13 = nil
					d.psk = nil
					d.appID = bytes.Repeat([]byte{3}, 32)
					d.resume = &ocDTLSResume{version: version, suite: 0x002f}
					copy(d.resume.master[:], bytes.Repeat([]byte{7}, 48))
				}
				switch mode {
				case "drop-hello":
					c.conn = &ocDTLSTestConn{Conn: c.conn, mode: mode}
				case "drop-server":
					s.conn = &dtls12RekeyFault{Conn: s.conn, nth: 1, mode: "drop"}
				case "drop-final":
					c.conn = &dtls12RekeyFault{Conn: c.conn, nth: 2, mode: "drop"}
				case "ccs-first", "finished-first":
					s.conn = &dtls12RekeyFault{Conn: s.conn, nth: 1, mode: mode}
				case "wrong-master":
					c.resume.master[0] ^= 1
				case "wrong-id":
					c.appID[0] ^= 1
				}
				budget := 4 * time.Second
				bad := mode == "wrong-master" || mode == "wrong-id"
				if bad {
					budget = 350 * time.Millisecond
				}
				ctx, cancel := context.WithTimeout(context.Background(), budget)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- s.handshake(ctx) }()
				ce := c.handshake(ctx)
				if bad {
					se := <-done
					if ce == nil || se == nil || c.ready.Load() || s.ready.Load() {
						t.Fatal("unauthenticated DTLS accepted", ce, se)
					}
					return
				}
				if ce != nil {
					t.Fatal(ce)
				}
				read := make(chan error, 1)
				go func() {
					c.conn.SetReadDeadline(time.Now().Add(4 * time.Second))
					kind, data, e := c.read()
					if e == nil && (kind != 3 || string(data) != "alive") {
						e = errors.New("wrong resumed payload")
					}
					read <- e
				}()
				se := <-done
				if se != nil {
					t.Fatal(se)
				}
				if err := s.write(3, []byte("alive")); err != nil {
					t.Fatal(err)
				}
				if err := <-read; err != nil {
					t.Fatal(err)
				}
				if !c.ready.Load() || !s.ready.Load() {
					t.Fatal("resumed handshake incomplete")
				}
			})
		}
	}
}

func FuzzOpenConnectDTLSResume(f *testing.F) {
	for _, legacy := range []bool{false, true} {
		version := uint16(0xfefd)
		if legacy {
			version = 0x0100
		}
		d := &ocDTLS{resume: &ocDTLSResume{version: version, suite: 0x002f}, appID: bytes.Repeat([]byte{3}, 32)}
		f.Add(legacy, d.resumeHello(nil))
		f.Add(legacy, []byte{1, 0, 1})
	}
	f.Fuzz(func(t *testing.T, legacy bool, b []byte) {
		version := uint16(0xfefd)
		if legacy {
			version = 0x0100
		}
		_, _, _, _, _, _ = ocDTLSParseHello(b, version)
		d := &ocDTLS{resume: &ocDTLSResume{version: version, suite: 0x002f}, stage: 99, fragments: map[uint16]*ocDTLSFragment{}}
		_, _, _ = d.open(b)
		_ = d.handshakes(b, 0)
		_ = d.handshakes(b, 1)
		_ = d.resumeCCS(b)
	})
}
