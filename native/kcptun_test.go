package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var kcpMethods = []string{"none", "aes", "aes-128", "aes-192", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "salsa20", "blowfish", "twofish", "cast5", "3des", "tea", "xtea", "xor"}

func kcpReference(t *testing.T, args ...string) (*exec.Cmd, *bufio.Reader) {
	t.Helper()
	binary := os.Getenv("LANBOAT_TEST_KCPTUN")
	if binary == "" {
		t.Skip("LANBOAT_TEST_KCPTUN not set")
	}
	cmd := exec.Command(binary, args...)
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	cmd.Stderr = os.Stderr
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd, bufio.NewReader(out)
}
func TestKCPCryptoReference(t *testing.T) {
	binary := os.Getenv("LANBOAT_TEST_KCPTUN")
	if binary == "" {
		t.Skip("LANBOAT_TEST_KCPTUN not set")
	}
	cmd := exec.Command(binary, "-mode=oracle")
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { stdin.Close(); cmd.Wait() }()
	enc, dec := json.NewEncoder(stdin), json.NewDecoder(stdout)
	for _, method := range kcpMethods {
		t.Run(method, func(t *testing.T) {
			c, e := newKCPCrypt(method, "transport-secret")
			if e != nil {
				t.Fatal(e)
			}
			payload := bytes.Repeat([]byte("wire compatible encryption"), 25)
			sealed := c.seal(payload)
			if e = enc.Encode(map[string]string{"Method": method, "Password": "transport-secret", "Encrypted": hex.EncodeToString(sealed)}); e != nil {
				t.Fatal(e)
			}
			var reply map[string]string
			if e = dec.Decode(&reply); e != nil {
				t.Fatal(e)
			}
			plain, _ := hex.DecodeString(reply["plain"])
			prefix := 20
			if c.aead != nil {
				prefix = 12
			}
			if !bytes.Equal(plain[prefix:], payload) {
				t.Fatal("independent ciphertext not decoded by upstream")
			}
			if e = enc.Encode(map[string]string{"Method": method, "Password": "transport-secret", "Plain": reply["plain"]}); e != nil {
				t.Fatal(e)
			}
			if e = dec.Decode(&reply); e != nil {
				t.Fatal(e)
			}
			upstream, _ := hex.DecodeString(reply["encrypted"])
			if !bytes.Equal(upstream, sealed) {
				t.Fatal("ciphertext differs from upstream")
			}
			got, e := c.open(upstream)
			if e != nil || !bytes.Equal(got, payload) {
				t.Fatal("upstream ciphertext", e)
			}
			corrupt := c.seal(payload)
			corrupt[len(corrupt)-1] ^= 1
			if _, e = c.open(corrupt); e == nil {
				t.Fatal("corruption accepted")
			}
		})
	}
}
func TestKCPFECReference(t *testing.T) {
	binary := os.Getenv("LANBOAT_TEST_KCPTUN")
	if binary == "" {
		t.Skip("LANBOAT_TEST_KCPTUN not set")
	}
	for _, counts := range [][2]int{{1, 1}, {3, 2}, {10, 3}, {32, 8}} {
		t.Run(fmt.Sprint(counts), func(t *testing.T) {
			code := newKCPRS(counts[0], counts[1])
			shards := make([][]byte, counts[0]+counts[1])
			for i := range shards {
				shards[i] = make([]byte, 99)
				if i < counts[0] {
					for j := range shards[i] {
						shards[i][j] = byte(i*23 + j*11)
					}
				}
			}
			q, _ := json.Marshal(map[string]any{"Data": counts[0], "Parity": counts[1], "Shards": shards})
			cmd := exec.Command(binary, "-mode=oracle")
			cmd.Stdin = bytes.NewReader(q)
			raw, e := cmd.Output()
			if e != nil {
				t.Fatal(e)
			}
			var reference [][]byte
			if e = json.Unmarshal(raw, &reference); e != nil {
				t.Fatal(e)
			}
			for i := counts[0]; i < len(shards); i++ {
				shards[i] = kcpCombine(code.rows[i], shards[:counts[0]], 99)
				if !bytes.Equal(shards[i], reference[i]) {
					t.Fatal("parity mismatch", i)
				}
			}
			for i := range counts[1] {
				shards[i] = nil
			}
			recovered, e := code.recover(shards, 99)
			if e != nil {
				t.Fatal(e)
			}
			for i := range counts[1] {
				if !bytes.Equal(recovered[i], reference[i]) {
					t.Fatal("recovery mismatch", i)
				}
			}
		})
	}
}
func TestKCPTUNIndependent(t *testing.T) {
	for _, version := range []int{1, 2} {
		for i, method := range kcpMethods {
			t.Run(fmt.Sprintf("v%d/%s", version, method), func(t *testing.T) {
				in := testInbound(t, "shadowsocks")
				in.Plugin = "kcptun"
				in.PluginOpts = fmt.Sprintf("key=transport-secret;crypt=%s;version=%d;nocomp=%t", method, version, i%2 == 0)
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				o := testOutbound(t, in, s.Address(in.Tag))
				o.Plugin, o.PluginOpts = in.Plugin, in.PluginOpts
				c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
				assertTCP(t, c)
				assertTCP(t, c)
				if conn, e := c.Dial(context.Background(), "udp", echoUDP(t)); e == nil {
					conn.Close()
					t.Fatal("raw UDP exposed")
				}
				c.resetNetworkTransports()
				assertTCP(t, c)
				if c.kcpBudget.Load() < 0 || c.kcpFECBudget.Load() < 0 {
					t.Fatal("negative memory accounting")
				}
			})
		}
	}
}
func TestKCPTUNReference(t *testing.T) {
	for _, version := range []int{1, 2} {
		for i, method := range kcpMethods {
			for _, direction := range []string{"client", "server"} {
				t.Run(fmt.Sprintf("v%d/%s/%s", version, method, direction), func(t *testing.T) {
					in := testInbound(t, "shadowsocks")
					options := fmt.Sprintf("key=private;crypt=%s;version=%d;nocomp=%t", method, version, i%2 == 0)
					args := []string{"-mode=" + direction, "-crypt=" + method, "-version=" + strconv.Itoa(version), "-compress=" + strconv.FormatBool(i%2 != 0)}
					if direction == "server" {
						plain := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						args = append(args, "-target="+plain.Address(in.Tag))
						_, reader := kcpReference(t, args...)
						address, e := reader.ReadString('\n')
						if e != nil {
							t.Fatal(e)
						}
						o := testOutbound(t, in, strings.TrimSpace(address))
						o.Plugin, o.PluginOpts = "kcptun", options
						c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
						assertTCP(t, c)
						kcpLargeTransfer(t, c, 500000)
					} else {
						in.Plugin, in.PluginOpts = "kcptun", options
						s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						args = append(args, "-target="+s.Address(in.Tag))
						_, reader := kcpReference(t, args...)
						address, e := reader.ReadString('\n')
						if e != nil {
							t.Fatal(e)
						}
						in.Plugin, in.PluginOpts = "", ""
						o := testOutbound(t, in, strings.TrimSpace(address))
						c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
						assertTCP(t, c)
						kcpLargeTransfer(t, c, 500000)
					}
				})
			}
		}
	}
}
func kcpLargeTransfer(t *testing.T, r *Runtime, size int) {
	t.Helper()
	c, e := r.Dial(context.Background(), "tcp", relayEchoTCP(t))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	want := make([]byte, size)
	for i := range want {
		want[i] = byte(i*43 + i/199)
	}
	done := make(chan error, 1)
	go func() { done <- writeAll(c, want) }()
	got := make([]byte, size)
	_, e = io.ReadFull(c, got)
	if e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(want, got) {
		t.Fatal("large transfer mismatch")
	}
}
func TestSMUXVersion2(t *testing.T) {
	a, b := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, server := newSMUXVersion(ctx, a, true, 2, 0), newSMUXVersion(ctx, b, false, 2, 0)
	defer client.close(net.ErrClosed)
	defer server.close(net.ErrClosed)
	var handlers sync.WaitGroup
	go func() {
		for {
			select {
			case c := <-server.accept:
				handlers.Go(func() { defer c.Close(); io.Copy(c, c) })
			case <-server.done:
				return
			}
		}
	}()
	var workers sync.WaitGroup
	for i := range 8 {
		workers.Go(func() {
			c, e := client.open(ctx)
			if e != nil {
				t.Error(e)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			want := bytes.Repeat([]byte{byte(i)}, 800000)
			done := make(chan error, 1)
			go func() { done <- writeAll(c, want) }()
			got := make([]byte, len(want))
			_, e = io.ReadFull(c, got)
			if e != nil || !bytes.Equal(got, want) {
				t.Error("flow control transfer", e)
			}
			if e = <-done; e != nil {
				t.Error(e)
			}
		})
	}
	workers.Wait()
	client.close(net.ErrClosed)
	server.close(net.ErrClosed)
	handlers.Wait()
}

func TestKCPTUNLossAndConcurrency(t *testing.T) {
	in := testInbound(t, "shadowsocks")
	in.Plugin, in.PluginOpts = "kcptun", "key=private;version=2;nocomp=false;mode=fast3;datashard=3;parityshard=2"
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	server, e := net.ResolveUDPAddr("udp", s.Address(in.Tag))
	if e != nil {
		t.Fatal(e)
	}
	proxy, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	var worker sync.WaitGroup
	var delayed sync.WaitGroup
	var dropped, duplicate, tampered int
	worker.Go(func() {
		buffer := make([]byte, 1501)
		var client *net.UDPAddr
		count := 0
		for {
			n, from, e := proxy.ReadFromUDP(buffer)
			if e != nil {
				return
			}
			to := server
			if from.String() == server.String() {
				to = client
			} else {
				client = from
			}
			if to == nil {
				continue
			}
			count++
			if count%13 == 0 {
				dropped++
				continue
			}
			b := append([]byte(nil), buffer[:n]...)
			if count%29 == 0 {
				b[len(b)-1] ^= 1
				tampered++
			}
			if count%7 == 0 {
				delayed.Go(func() { time.Sleep(3 * time.Millisecond); proxy.WriteToUDP(b, to) })
			} else {
				proxy.WriteToUDP(b, to)
			}
			if count%19 == 0 {
				duplicate++
				proxy.WriteToUDP(b, to)
			}
		}
	})
	t.Cleanup(func() {
		proxy.Close()
		worker.Wait()
		delayed.Wait()
		if dropped == 0 || duplicate == 0 || tampered == 0 {
			t.Error("loss fixture did not exercise all branches")
		}
	})
	o := testOutbound(t, in, proxy.LocalAddr().String())
	o.Plugin, o.PluginOpts = in.Plugin, in.PluginOpts
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	var transfers sync.WaitGroup
	for range 8 {
		transfers.Go(func() { kcpLargeTransfer(t, c, 350000) })
	}
	transfers.Wait()
	c.Close()
	if c.kcpBudget.Load() != 0 || c.kcpFECBudget.Load() != 0 {
		t.Fatal("memory not released", c.kcpBudget.Load(), c.kcpFECBudget.Load())
	}
}
func TestKCPTUNOptionsAndModes(t *testing.T) {
	for _, mode := range []string{"normal", "fast", "fast2", "fast3", "custom"} {
		t.Run(mode, func(t *testing.T) {
			in := testInbound(t, "shadowsocks")
			in.Plugin, in.PluginOpts = "kcptun", "mode="+mode+";key=private;datashard=0;parityshard=0"
			if mode == "custom" {
				in.PluginOpts += ";nodelay=1;interval=10;resend=2;nc=1"
			}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			o := testOutbound(t, in, s.Address(in.Tag))
			o.Plugin, o.PluginOpts = in.Plugin, in.PluginOpts
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			kcpLargeTransfer(t, c, 300000)
			for _, cfg := range []Config{s.config, c.config} {
				b, _ := json.Marshal(cfg)
				if _, e := Parse(b); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
	for _, value := range []string{"crypt=unknown", "mode=unknown", "version=0", "version=3", "mtu=127", "mtu=1501", "sndwnd=0", "rcvwnd=4097", "datashard=128;parityshard=128", "datashard=-1", "dscp=64", "interval=10", "mode=custom;interval=9", "mode=custom;resend=33", "mode=custom;nc=2", "nocomp=bad", "port=0", "port=65536", "server=bad host", "unexpected=yes"} {
		p := SIP003Options{Plugin: "kcptun", PluginOpts: value}
		if p.prepare("shadowsocks", Transport{}, TLSOptions{}, false) == nil {
			t.Error("invalid options accepted", value)
		}
	}
	for _, mode := range []string{"key", "ss-password", "detour"} {
		t.Run("reject/"+mode, func(t *testing.T) {
			in := testInbound(t, "shadowsocks")
			in.Plugin, in.PluginOpts = "kcptun", "key=private"
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			o := testOutbound(t, in, s.Address(in.Tag))
			o.Plugin, o.PluginOpts = in.Plugin, in.PluginOpts
			if mode == "key" {
				o.PluginOpts = "key=wrong"
			}
			if mode == "ss-password" {
				o.Password = "wrong"
			}
			if mode == "detour" {
				o.Detour = "deny"
			}
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o, {Type: "block", Tag: "deny"}}})
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			conn, e := c.Dial(ctx, "tcp", relayEchoTCP(t))
			if e == nil {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(150 * time.Millisecond))
				e = writeAll(conn, []byte("denied"))
				if e == nil {
					_, e = conn.Read(make([]byte, 6))
				}
			}
			if e == nil {
				t.Fatal("invalid configuration forwarded traffic")
			}
		})
	}
}
func TestKCPSnappyReference(t *testing.T) {
	binary := os.Getenv("LANBOAT_TEST_KCPTUN")
	if binary == "" {
		t.Skip("LANBOAT_TEST_KCPTUN not set")
	}
	for _, size := range []int{1, 512, 65536, 180000} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			want := make([]byte, size)
			for i := range want {
				want[i] = byte(i*13 + i/397)
			}
			var wire bytes.Buffer
			c := &kcpSnappyConn{Conn: &kcpBufferConn{Buffer: &wire}}
			if e := writeAll(c, want); e != nil {
				t.Fatal(e)
			}
			q, _ := json.Marshal(map[string]string{"Unsnappy": hex.EncodeToString(wire.Bytes())})
			cmd := exec.Command(binary, "-mode=oracle")
			cmd.Stdin = bytes.NewReader(q)
			raw, e := cmd.Output()
			if e != nil {
				t.Fatal(e)
			}
			var reply map[string]string
			json.Unmarshal(raw, &reply)
			got, _ := hex.DecodeString(reply["plain"])
			if !bytes.Equal(got, want) {
				t.Fatal("upstream decode", reply["error"])
			}
			q, _ = json.Marshal(map[string]string{"Snappy": hex.EncodeToString(want)})
			cmd = exec.Command(binary, "-mode=oracle")
			cmd.Stdin = bytes.NewReader(q)
			raw, e = cmd.Output()
			if e != nil {
				t.Fatal(e)
			}
			json.Unmarshal(raw, &reply)
			b, _ := hex.DecodeString(reply["wire"])
			got, e = io.ReadAll(&kcpSnappyConn{Conn: readerConn(b)})
			if e != nil || !bytes.Equal(got, want) {
				t.Fatal("independent decode", e)
			}
		})
	}
	for _, b := range [][]byte{{0xff, 6, 0, 0, 's', 'N', 'a', 'P', 'x', 'Y'}, {1, 4, 0, 0, 0, 0, 0, 0}, {0xff, 6, 0, 0, 's', 'N', 'a', 'P', 'p', 'Y', 1, 5, 0, 0, 0, 0, 0, 0, 5}} {
		if _, e := io.ReadAll(&kcpSnappyConn{Conn: readerConn(b)}); e == nil {
			t.Fatal("invalid stream accepted")
		}
	}
}

type kcpBufferConn struct {
	net.Conn
	*bytes.Buffer
}

func (c *kcpBufferConn) Write(b []byte) (int, error) { return c.Buffer.Write(b) }
func (c *kcpBufferConn) Read(b []byte) (int, error)  { return c.Buffer.Read(b) }
func FuzzKCPFrames(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 81, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1500 {
			return
		}
		parseKCP(b)
		r := &Runtime{}
		fec := newKCPFEC(r, newKCPRS(3, 2))
		fec.decode(b)
		fec.close()
		if r.kcpFECBudget.Load() != 0 {
			t.Fatal("leaked FEC budget")
		}
	})
}
func FuzzKCPSnappy(f *testing.F) {
	f.Add(encodeSnappy([]byte("compressed")))
	f.Add([]byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 131072 {
			return
		}
		decodeSnappy(b)
	})
}

func TestKCPTUNSessionLifetime(t *testing.T) {
	in := testInbound(t, "shadowsocks")
	in.Plugin, in.PluginOpts = "kcptun", "key=private;autoexpire=1;keepalive=1;version=2"
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := testOutbound(t, in, s.Address(in.Tag))
	o.Plugin, o.PluginOpts = in.Plugin, in.PluginOpts
	o.PluginOpts += ";server=127.0.0.1;port=" + strings.Split(s.Address(in.Tag), ":")[1]
	o.Server = "invalid.test"
	o.ServerPort = 1
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	first, e := c.Dial(context.Background(), "tcp", relayEchoTCP(t))
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	first.SetDeadline(time.Now().Add(3 * time.Second))
	pool := c.kcpClients[o.Tag]
	pool.mu.Lock()
	old := pool.session
	pool.born = time.Now().Add(-2 * time.Second)
	pool.mu.Unlock()
	assertTCP(t, c)
	pool.mu.Lock()
	changed := pool.session != old && len(pool.retired) == 1
	pool.mu.Unlock()
	if !changed {
		t.Fatal("autoexpire did not rotate session")
	}
	if e = writeAll(first, []byte("preserved")); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, 9)
	if _, e = io.ReadFull(first, got); e != nil || string(got) != "preserved" {
		t.Fatal("active expired session lost", e)
	}
	first.Close()
	assertTCP(t, c)
	pool.mu.Lock()
	retired := len(pool.retired)
	pool.mu.Unlock()
	if retired != 0 {
		t.Fatal("unused expired session not reclaimed")
	}
	c.Close()
	if c.kcpBudget.Load() != 0 || c.kcpFECBudget.Load() != 0 {
		t.Fatal("close leaked memory")
	}
}
func TestKCPDeadlineRecovery(t *testing.T) {
	s := newTestRuntime(t, Config{})
	p := SIP003Options{Plugin: "kcptun", PluginOpts: "key=private;rcvwnd=1;sndwnd=1;datashard=0;parityshard=0"}
	if e := p.prepare("shadowsocks", Transport{}, TLSOptions{}, true); e != nil {
		t.Fatal(e)
	}
	in := testInbound(t, "shadowsocks")
	in.SIP003Options = p
	l, e := s.listenKCP(in, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	r := newTestRuntime(t, Config{})
	o := testOutbound(t, in, l.Addr().String())
	c, e := r.dialKCP(context.Background(), o, p.plugin.kcp)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, e = c.Read(make([]byte, 1)); !os.IsTimeout(e) {
		t.Fatal("missing read deadline", e)
	}
	c.SetReadDeadline(time.Time{})
	want := bytes.Repeat([]byte("backpressure"), 5000)
	c.SetWriteDeadline(time.Now().Add(40 * time.Millisecond))
	n, e := c.Write(want)
	if !os.IsTimeout(e) || n == 0 || n == len(want) {
		t.Fatal("missing send window backpressure", n, e)
	}
	peer, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	peer.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() {
		b := make([]byte, len(want))
		_, e := io.ReadFull(peer, b)
		if e == nil && !bytes.Equal(b, want) {
			e = fmt.Errorf("stream differs")
		}
		if e == nil {
			e = writeAll(peer, []byte("ok"))
		}
		done <- e
	}()
	if _, e = c.Write(want[n:]); e != nil {
		t.Fatal("write did not recover", e)
	}
	got := make([]byte, 2)
	if _, e = io.ReadFull(c, got); e != nil || string(got) != "ok" {
		t.Fatal("read did not recover", e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}
func TestKCPTUNIPv6AndSS2022(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			in := testInbound(t, "shadowsocks")
			in.Listen = host
			in.Method = "2022-blake3-aes-128-gcm"
			in.Password = "BwcHBwcHBwcHBwcHBwcHBw=="
			in.Plugin, in.PluginOpts = "kcptun", "key=private;dscp=8;version=2;nocomp=false"
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			o := testOutbound(t, in, s.Address(in.Tag))
			o.Password = in.Password
			o.Plugin, o.PluginOpts = in.Plugin, in.PluginOpts
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			assertTCP(t, c)
		})
	}
}
func TestSMUXVersion2HalfClose(t *testing.T) {
	a, b := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, server := newSMUXVersion(ctx, a, true, 2, 0), newSMUXVersion(ctx, b, false, 2, 0)
	defer client.close(net.ErrClosed)
	defer server.close(net.ErrClosed)
	done := make(chan error, 1)
	go func() {
		c := <-server.accept
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		got, e := io.ReadAll(c)
		if e == nil {
			e = writeAll(c, got)
		}
		if e == nil {
			e = c.CloseWrite()
		}
		done <- e
	}()
	c, e := client.open(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if e = writeAll(c, []byte("half-close")); e != nil {
		t.Fatal(e)
	}
	if e = c.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(c)
	if e != nil || string(got) != "half-close" {
		t.Fatal(string(got), e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestKCPFECRecoveryAndBounds(t *testing.T) {
	r := &Runtime{}
	code := newKCPRS(3, 2)
	enc, dec := newKCPFEC(r, code), newKCPFEC(r, code)
	defer enc.close()
	defer dec.close()
	var packets [][]byte
	var want [][]byte
	for i := range 3 {
		b := appendKCP(nil, kcpFrame{conv: 7, cmd: 81, seq: uint32(i), window: 32, body: bytes.Repeat([]byte{byte(i)}, 30+i*17)})
		want = append(want, b)
		packets = append(packets, enc.encode(b)...)
	}
	var got [][]byte
	for _, i := range []int{4, 1, 3} {
		got = append(got, dec.decode(packets[i])...)
	}
	seen := map[uint32]bool{}
	for _, b := range got {
		frames, e := parseKCP(b)
		if e != nil || len(frames) != 1 {
			t.Fatal("recovered invalid frame", e)
		}
		i := frames[0].seq
		if int(i) >= len(want) || !bytes.Equal(b, want[i]) {
			t.Fatal("recovered wrong data")
		}
		seen[i] = true
	}
	if len(seen) != 3 {
		t.Fatal("lost erasures", seen)
	}
	for i := range 10000 {
		b := appendKCP(nil, kcpFrame{conv: 9, cmd: 81, seq: uint32(i), body: make([]byte, 1200)})
		for _, packet := range enc.encode(b) {
			dec.decode(packet)
		}
		if dec.bytes > 256<<10 || len(dec.groups) > 8 || r.kcpFECBudget.Load() > 8<<20 {
			t.Fatal("FEC cache unbounded")
		}
	}
	enc.close()
	dec.close()
	if r.kcpFECBudget.Load() != 0 {
		t.Fatal("FEC budget leaked")
	}
}
func TestKCPRuntimeBudget(t *testing.T) {
	r := newTestRuntime(t, Config{})
	p := SIP003Options{Plugin: "kcptun", PluginOpts: "sndwnd=4096;rcvwnd=4096;datashard=0;parityshard=0"}
	if e := p.prepare("shadowsocks", Transport{}, TLSOptions{}, false); e != nil {
		t.Fatal(e)
	}
	for i := range 20 {
		c, e := r.newKCP(p.plugin.kcp, uint32(i), &net.UDPAddr{}, &net.UDPAddr{}, nil, func([]byte) error { return nil }, nil)
		if e != nil {
			t.Fatal(e)
		}
		c.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
		c.Write(make([]byte, 1<<20))
		if r.kcpBudget.Load() > 16<<20 {
			t.Fatal("runtime budget exceeded")
		}
	}
	r.closeKCP(true)
	if r.kcpBudget.Load() != 0 || r.kcpFECBudget.Load() != 0 {
		t.Fatal("runtime budget leaked", r.kcpBudget.Load(), r.kcpFECBudget.Load())
	}
}

func TestSMUXVersion2QueuedDeadlineCredit(t *testing.T) {
	a, b := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, server := newSMUXVersion(ctx, a, true, 2, 0), newSMUXVersion(ctx, b, false, 2, 0)
	defer client.close(net.ErrClosed)
	defer server.close(net.ErrClosed)
	c, e := client.open(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	peer := <-server.accept
	defer peer.Close()
	client.gate <- struct{}{}
	c.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	if _, e = c.Write(make([]byte, 16384)); !os.IsTimeout(e) {
		t.Fatal(e)
	}
	<-client.gate
	c.mu.Lock()
	lost := c.written
	c.mu.Unlock()
	if lost != 0 {
		t.Fatal("queued timeout consumed unsent SMUX credits", lost)
	}
	c.SetWriteDeadline(time.Now().Add(time.Second))
	peer.SetReadDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { b := make([]byte, 300000); _, e := io.ReadFull(peer, b); done <- e }()
	if _, e = c.Write(make([]byte, 300000)); e != nil {
		t.Fatal("retry lost credits", e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestKCPConcurrentConstructionAndShutdown(t *testing.T) {
	p := SIP003Options{Plugin: "kcptun"}
	if e := p.prepare("shadowsocks", Transport{}, TLSOptions{}, false); e != nil {
		t.Fatal(e)
	}
	for range 16 {
		r := newTestRuntime(t, Config{})
		var work sync.WaitGroup
		start := make(chan struct{})
		for i := range 16 {
			work.Go(func() {
				<-start
				c, e := r.newKCP(p.plugin.kcp, uint32(i), &net.UDPAddr{}, &net.UDPAddr{}, nil, func([]byte) error { return nil }, nil)
				if e == nil {
					c.Close()
					c.workers.Wait()
				}
			})
		}
		close(start)
		r.Close()
		work.Wait()
		if r.kcpBudget.Load() != 0 || r.kcpFECBudget.Load() != 0 {
			t.Fatal("shutdown budget leaked")
		}
	}
}

func TestKCPTUNDisabledFECReference(t *testing.T) {
	for _, direction := range []string{"client", "server"} {
		t.Run(direction, func(t *testing.T) {
			in := testInbound(t, "shadowsocks")
			args := []string{"-mode=" + direction, "-data=10", "-parity=0"}
			if direction == "server" {
				plain := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				_, reader := kcpReference(t, append(args, "-target="+plain.Address(in.Tag))...)
				address, e := reader.ReadString('\n')
				if e != nil {
					t.Fatal(e)
				}
				o := testOutbound(t, in, strings.TrimSpace(address))
				o.Plugin, o.PluginOpts = "kcptun", "key=private;parityshard=0"
				c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
				assertTCP(t, c)
			} else {
				in.Plugin, in.PluginOpts = "kcptun", "key=private;parityshard=0"
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				_, reader := kcpReference(t, append(args, "-target="+s.Address(in.Tag))...)
				address, e := reader.ReadString('\n')
				if e != nil {
					t.Fatal(e)
				}
				in.Plugin, in.PluginOpts = "", ""
				o := testOutbound(t, in, strings.TrimSpace(address))
				c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
				assertTCP(t, c)
			}
		})
	}
}
