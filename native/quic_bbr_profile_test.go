package native

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"testing"
	"time"
)

func TestBBRProfileConfig(t *testing.T) {
	cert := certificate(t)
	for _, kind := range []string{"hysteria2", "hysteria", "tuic", "juicity"} {
		for _, algorithm := range []string{"", "bbr", "bbr2", "bbr3", "cubic", "new_reno"} {
			for _, profile := range []string{"", "standard", "conservative", "aggressive", "BBR", "Standard", "standard ", "unknown"} {
				t.Run(kind+"/"+algorithm+"/"+profile, func(t *testing.T) {
					in := Inbound{Type: kind, Tag: "server", TLS: cert, Users: []User{{UUID: testUUID, Password: "private"}}, CongestionControl: algorithm, BBRProfile: profile}
					out := testOutbound(t, in, "127.0.0.1:12345")
					out.CongestionControl, out.BBRProfile = algorithm, profile
					valid := profile == "" || kind == "hysteria2" && (algorithm == "" || algorithm == "bbr") && (profile == "standard" || profile == "conservative" || profile == "aggressive")
					for _, cfg := range []Config{{Inbounds: []Inbound{in}}, {Outbounds: []Outbound{out}}} {
						raw, err := json.Marshal(cfg)
						if err != nil {
							t.Fatal(err)
						}
						parsed, err := Parse(raw)
						if (err == nil) != valid {
							t.Fatal("profile validation", err, valid)
						}
						if err == nil {
							saved := ""
							if len(parsed.Inbounds) != 0 {
								saved = parsed.Inbounds[0].BBRProfile
							} else {
								saved = parsed.Outbounds[0].BBRProfile
							}
							if saved != profile {
								t.Fatal("saved profile lost", saved, profile)
							}
						}
					}
				})
			}
		}
	}
}

func TestBBRProfilePhases(t *testing.T) {
	now := time.Unix(100, 0)
	for _, tc := range []struct {
		profile                  string
		startup, startCWND, cwnd float64
		rounds                   int
	}{{"conservative", 2.25, 1.75, 1.75, 2}, {"standard", 2.885, 2, 2, 3}, {"aggressive", 3, 2.25, 2.5, 4}} {
		t.Run(tc.profile, func(t *testing.T) {
			b := newQUICBBR(now, tc.profile)
			pace, cwnd := b.gains()
			if pace != tc.startup || cwnd != tc.startCWND {
				t.Fatal("startup gains", pace, cwnd)
			}
			w := 200000
			for i := 0; i <= tc.rounds; i++ {
				sent := now.Add(time.Duration(i) * 100 * time.Millisecond)
				b.firstSent, b.deliveredAt = sent, sent
				w = bbrTestACK(b, sent, sent.Add(40*time.Millisecond), 12000, w, 200000, false, 40*time.Millisecond)
				if b.full != (i == tc.rounds) {
					t.Fatal("wrong plateau length", i, b.full)
				}
			}
			pace, cwnd = b.gains()
			if b.mode != bbrDrain || math.Abs(pace-1/tc.startup) > 1e-12 || cwnd != tc.startCWND {
				t.Fatal("profile did not enter drain", b.mode, pace, cwnd)
			}
			b.mode, b.cycle = bbrProbeBW, 2
			pace, cwnd = b.gains()
			if pace != 1 || cwnd != tc.cwnd {
				t.Fatal("probe window", pace, cwnd)
			}
			b.mode = bbrProbeRTT
			if w := b.lost(now.Add(time.Second), now, 1200, 100000, 100000); w != bbrMinimumWindow {
				t.Fatal("profile bypassed ProbeRTT bound", w)
			}
		})
	}
	if proxyQUICOptions("hysteria2", "").bbrProfile != "standard" || proxyQUICOptions("tuic", "bbr").bbrProfile != "" {
		t.Fatal("profile changed unrelated protocol defaults")
	}
}

func TestBBRProfileDrainAndOvershoot(t *testing.T) {
	now := time.Unix(100, 0)
	for _, profile := range []string{"conservative", "standard", "aggressive"} {
		t.Run(profile, func(t *testing.T) {
			b := newQUICBBR(now, profile)
			b.mode, b.full, b.cycle, b.cycleAt = bbrProbeBW, true, 1, now
			b.bandwidth, b.minRTT = 1000000, 40*time.Millisecond
			b.filter[0].rate = b.bandwidth
			bbrTestACK(b, now, now.Add(60*time.Millisecond), 1200, 200000, 200000, true, 40*time.Millisecond)
			if (b.cycle == 1) != (profile == "conservative") {
				t.Fatal("queue drain policy", b.cycle)
			}
			if profile == "conservative" {
				bbrTestACK(b, now.Add(270*time.Millisecond), now.Add(300*time.Millisecond), 1200, 200000, 200000, true, 40*time.Millisecond)
				if b.cycle != 0 {
					t.Fatal("conservative profile stuck draining", b.cycle)
				}
			}
			b = newQUICBBR(now, profile)
			b.bandwidth, b.minRTT, b.pace, b.busySample = 100000, 100*time.Millisecond, 1000000, true
			b.lost(now.Add(time.Millisecond), now, 1200, 12000, 10800)
			want := uint64(1000000)
			if profile == "conservative" {
				want = 225000
			}
			if b.pace != want {
				t.Fatal("startup overshoot response", b.pace, want)
			}
		})
	}
}

func TestBBRProfileACKAggregation(t *testing.T) {
	now := time.Unix(100, 0)
	a := &bbrACKAggregation{}
	if extra := a.update(now, 1, 100000, 1200, 12000); extra != 1200 {
		t.Fatal(extra)
	}
	if extra := a.update(now.Add(time.Millisecond), 1, 100000, 1200, 12000); extra != 2300 {
		t.Fatal("ACK burst not measured", extra)
	}
	if extra := a.update(now.Add(time.Millisecond), 1, 100000, 100000, 12000); extra != 12000 {
		t.Fatal("ACK aggregation exceeds window", extra)
	}
	if extra := a.update(now.Add(time.Second), 12, 1000000, 1200, 12000); extra != 1200 {
		t.Fatal("old burst did not expire", extra)
	}
	for _, profile := range []string{"conservative", "standard", "aggressive"} {
		b := newQUICBBR(now, profile)
		b.minRTT, b.bandwidth, b.plateauRate, b.delivered = 100*time.Millisecond, 100000, 100000, 12000
		b.pace = uint64(b.tuning.startup * float64(b.bandwidth))
		b.filter[0].rate = 100000
		_, gain := b.gains()
		window := b.inflight(gain) + 100
		got := bbrTestACK(b, now, now.Add(100*time.Millisecond), 1200, window, window, false, 100*time.Millisecond)
		if (got > window) != (profile == "aggressive") {
			t.Fatal("startup aggregation policy", profile, got, window)
		}
		b.sent(now.Add(time.Hour), 0, 1200, true)
		if b.aggregation.bytes != 0 {
			t.Fatal("idle reused ACK burst", profile)
		}
	}
}

func TestBBRProfileIndependent(t *testing.T) {
	for _, tc := range []struct{ name, client, server string }{
		{"default", "", ""}, {"conservative", "conservative", "conservative"}, {"standard", "standard", "standard"}, {"aggressive", "aggressive", "aggressive"}, {"asymmetric", "aggressive", "conservative"},
	} {
		for _, limited := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/limited=%v", tc.name, limited), func(t *testing.T) {
				in := Inbound{Type: "hysteria2", Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{Password: "private"}}, BBRProfile: tc.server}
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out := testOutbound(t, in, server.Address("server"))
				out.BBRProfile = tc.client
				if limited {
					out.UpMbps, out.DownMbps = 20, 20
				}
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 511, 4096, 60000})
				client.resetNetworkTransports()
				assertTCP(t, client)
				session, err := client.quicClients["proxy"].session(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				endpoint := server.quicListeners["server"]
				endpoint.mu.Lock()
				var peer *quicConn
				for _, conn := range endpoint.conns {
					peer = conn
				}
				endpoint.mu.Unlock()
				if peer == nil {
					t.Fatal("missing server connection")
				}
				client.Close()
				server.Close()
				<-session.conn.done
				<-peer.done
				for _, side := range []struct {
					conn    *quicConn
					profile string
				}{{session.conn, tc.client}, {peer, tc.server}} {
					conn, expected := side.conn, side.profile
					if expected == "" {
						expected = "standard"
					}
					want := newQUICBBR(time.Now(), expected).tuning
					if conn.bbr == nil || conn.bbr.tuning != want || (conn.brutal != nil) != limited {
						t.Fatal("profile or Brutal priority not wired", expected, limited)
					}
					if !limited && conn.bbr.bandwidth == 0 {
						t.Fatal("profile did not receive delivery samples", expected)
					}
				}
			})
		}
	}
}

func BenchmarkBBRProfileFeedback(b *testing.B) {
	for _, profile := range []string{"conservative", "standard", "aggressive"} {
		b.Run(profile, func(b *testing.B) {
			now := time.Unix(100, 0)
			s := newQUICBBR(now, profile)
			w := 12000
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p := quicSent{at: now, delivery: s.sent(now, 12000, 1200, false)}
				now = now.Add(time.Millisecond)
				w = s.ack(now, p, 1200, w, 12000, 13200, time.Millisecond)
			}
		})
	}
}
