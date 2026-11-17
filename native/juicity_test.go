package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func juicityInbound(t *testing.T) Inbound {
	return Inbound{Type: "juicity", Tag: "s", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{UUID: testUUID, Password: "private"}}}
}
func TestJuicityIndependent(t *testing.T) {
	in := juicityInbound(t)
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, s.Address("s"))
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	t.Cleanup(func() { logJuicityFailure(t, c, s) })
	assertTCP(t, c)
	assertUDPSizes(t, c, []int{1, 511, 4096, 60000})
}

func logJuicityFailure(t *testing.T, runtimes ...*Runtime) {
	if !t.Failed() {
		return
	}
	var peers []*quicConn
	for _, r := range runtimes {
		for _, p := range r.quicClients {
			p.mu.Lock()
			if p.current != nil {
				peers = append(peers, p.current.conn)
			}
			p.mu.Unlock()
		}
		for _, endpoint := range r.quicListeners {
			endpoint.mu.Lock()
			for _, conn := range endpoint.conns {
				peers = append(peers, conn)
			}
			endpoint.mu.Unlock()
		}
	}
	for _, r := range runtimes {
		r.Close()
	}
	for _, conn := range peers {
		<-conn.done
		t.Logf("QUIC state server=%v cwnd=%d flight=%d retained=%d pto=%d srtt=%v minrtt=%v tokens=%.2f rateNext=%v sent=%d receiveMax=%d consumed=%d pending=%d", conn.server, conn.cwnd, conn.inFlight, conn.retained, conn.ptoCount, conn.srtt, conn.minRTT, conn.rateTokens, conn.rateNext.Sub(conn.rateAt), conn.sendTotal, conn.receiveMax, conn.consumed.Load(), len(conn.pending))
		if b := conn.bbr; b != nil {
			t.Logf("BBR state server=%v mode=%d bandwidth=%d pace=%d quantum=%d rounds=%d full=%v delivered=%d appUntil=%d", conn.server, b.mode, b.bandwidth, b.pacing(false), b.quantum(), b.round, b.full, b.delivered, b.appUntil)
		}
		for level, space := range conn.spaces {
			t.Logf("QUIC space server=%v level=%d nextPN=%d largest=%d sent=%d queued=%d ack=%v", conn.server, level, space.nextPN, space.largest, len(space.sent), len(space.queue), space.ack)
		}
		for id, stream := range conn.streams {
			stream.mu.Lock()
			t.Logf("QUIC stream server=%v id=%d sendOffset=%d sendLimit=%d readOffset=%d highest=%d readLimit=%d holes=%d final=%v", conn.server, id, stream.sendOffset, stream.sendLimit, stream.buffer.position, stream.highest, stream.readLimit, len(stream.buffer.parts), stream.finalKnown)
			stream.mu.Unlock()
		}
	}
}
func TestJuicityWrongCredentialsAndPin(t *testing.T) {
	in := juicityInbound(t)
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	block, _ := pem.Decode([]byte(strings.Join(in.TLS.Certificate, "\n")))
	h := sha256.Sum256(block.Bytes)
	for _, kind := range []string{"correct-pin", "wrong-pin", "wrong-password", "wrong-uuid"} {
		t.Run(kind, func(t *testing.T) {
			o := testOutbound(t, in, s.Address("s"))
			o.PinnedCertchainSHA256 = hex.EncodeToString(h[:])
			o.TLS.Insecure = false
			if kind == "wrong-pin" {
				o.PinnedCertchainSHA256 = strings.Repeat("00", 32)
			}
			if kind == "wrong-password" {
				o.Password = "wrong"
			}
			if kind == "wrong-uuid" {
				o.UUID = "11111111-1111-4111-8111-111111111111"
			}
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			if kind == "correct-pin" {
				assertTCP(t, c)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, e := c.Dial(ctx, "tcp", "127.0.0.1:1")
			if e == nil {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				_, e = conn.Write([]byte("probe"))
				if e == nil {
					var b [1]byte
					_, e = conn.Read(b[:])
				}
			}
			if e == nil {
				t.Fatal("invalid credentials accepted")
			}
		})
	}
}
func TestJuicityOfficialServerInterop(t *testing.T) {
	for _, algorithm := range []string{"new_reno", "cubic", "bbr"} {
		t.Run(algorithm, func(t *testing.T) { testJuicityOfficialServer(t, algorithm) })
	}
}
func testJuicityOfficialServer(t *testing.T, algorithm string) {
	ref := os.Getenv("LANBOAT_TEST_JUICITY")
	if ref == "" {
		t.Skip("LANBOAT_TEST_JUICITY not set")
	}
	in := juicityInbound(t)
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	os.WriteFile(cp, []byte(strings.Join(in.TLS.Certificate, "\n")), 0600)
	os.WriteFile(kp, []byte(strings.Join(in.TLS.Key, "\n")), 0600)
	port := unusedPort(t)
	path := filepath.Join(dir, "server.json")
	config := map[string]any{"listen": portAddress("127.0.0.1", port), "users": map[string]string{testUUID: "private"}, "certificate": cp, "private_key": kp, "log_level": "warn"}
	b, _ := json.Marshal(config)
	os.WriteFile(path, b, 0600)
	cmd := exec.Command(ref, "run", "-c", path)
	log, e := os.Create(filepath.Join(dir, "server.log"))
	if e != nil {
		t.Fatal(e)
	}
	cmd.Stdout, cmd.Stderr = log, log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
		log.Close()
		if t.Failed() {
			b, _ := os.ReadFile(log.Name())
			t.Log(string(b))
		}
	}()
	waitPacketPort(t, portAddress("127.0.0.1", port))
	o := testOutbound(t, in, portAddress("127.0.0.1", port))
	o.CongestionControl = algorithm
	client := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	assertTCP(t, client)
	// This released reference server caps its receive buffer at 2048 bytes.
	// Large datagrams are covered separately by TestJuicityIndependent.
	assertUDPSizes(t, client, []int{1, 511, 1400, 2048})
}

func TestJuicityOfficialClientInterop(t *testing.T) {
	for _, algorithm := range []string{"new_reno", "cubic", "bbr"} {
		t.Run(algorithm, func(t *testing.T) { testJuicityOfficialClient(t, algorithm) })
	}
}
func testJuicityOfficialClient(t *testing.T, algorithm string) {
	ref := os.Getenv("LANBOAT_TEST_JUICITY_CLIENT")
	if ref == "" {
		t.Skip("LANBOAT_TEST_JUICITY_CLIENT not set")
	}
	in := juicityInbound(t)
	in.CongestionControl = algorithm
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	dir, port := t.TempDir(), unusedPort(t)
	config := map[string]any{"listen": portAddress("127.0.0.1", port), "server": server.Address("s"), "uuid": testUUID, "password": "private", "allow_insecure": true, "congestion_control": "new_reno", "log_level": "warn"}
	if algorithm == "bbr" {
		config["congestion_control"] = "bbr"
	}
	b, _ := json.Marshal(config)
	path := filepath.Join(dir, "client.json")
	os.WriteFile(path, b, 0600)
	cmd := exec.Command(ref, "run", "-c", path)
	log, e := os.Create(filepath.Join(dir, "client.log"))
	if e != nil {
		t.Fatal(e)
	}
	cmd.Stdout, cmd.Stderr = log, log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
		log.Close()
		if t.Failed() {
			b, _ := os.ReadFile(log.Name())
			t.Log(string(b))
		}
	}()
	sshWait(t, port)
	client := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "proxy", Server: "127.0.0.1", ServerPort: port}}})
	assertTCP(t, client)
	assertUDPSizes(t, client, []int{1, 511, 1400})
}
func TestJuicityWireAddresses(t *testing.T) {
	for address, want := range map[string]byte{"127.0.0.1:80": 1, "[::1]:443": 4, "example.com:53": 3} {
		b, e := juicityAddress(address)
		if e != nil || b[0] != want {
			t.Fatal(address, e)
		}
		got, e := readJuicityAddress(bytes.NewReader(b))
		if e != nil || got != address {
			t.Fatal(got, e)
		}
	}
	if _, e := readJuicityAddress(bytes.NewReader([]byte{3})); e == nil {
		t.Fatal("invalid address type accepted")
	}
	var b bytes.Buffer
	payload := bytes.Repeat([]byte("p"), 60000)
	if e := writeJuicityPacket(&b, payload, "127.0.0.1:53"); e != nil {
		t.Fatal(e)
	}
	got, a, e := readJuicityPacket(&b)
	if e != nil || a != "127.0.0.1:53" || !bytes.Equal(got, payload) {
		t.Fatal(a, len(got), e)
	}
}

var _ net.Conn = (*juicityPacketConn)(nil)
