package native

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChromiumHTTP3ReferenceProfile(t *testing.T) {
	reference := os.Getenv("LANBOAT_TEST_NAIVE")
	if reference == "" {
		t.Fatal("LANBOAT_TEST_NAIVE required")
	}
	fixture := newMutualTLSFixture(t)
	options := fixture.server()
	options.ClientAuthentication = ""
	options.ClientCertificate = nil
	options.ALPN = []string{"h3"}
	config, err := options.config(true, "")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	listener, err := listenQUIC(ctx, packet, config)
	if err != nil {
		packet.Close()
		t.Fatal(err)
	}
	defer listener.Close()
	type record struct {
		Stream  uint64            `json:"stream"`
		Kind    uint64            `json:"kind"`
		Payload string            `json:"payload"`
		Fields  map[string]string `json:"fields,omitempty"`
	}
	records := make(chan record, 16)
	serverErr := make(chan error, 1)
	go func() {
		q, err := listener.Accept(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		if err = h3Start(ctx, q); err != nil {
			serverErr <- err
			return
		}
		for {
			s, err := q.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func() {
				if s.id&2 != 0 {
					kind, err := readQUICVar(s)
					if err != nil {
						return
					}
					if kind == 0 {
						frame, b, err := h3ReadFrame(s)
						if err != nil {
							return
						}
						records <- record{Stream: s.id, Kind: frame, Payload: hex.EncodeToString(b)}
					}
					_, _ = io.CopyN(io.Discard, s, 65536)
					return
				}
				defer s.Close()
				kind, b, err := h3ReadFrame(s)
				if err != nil || kind != 1 {
					return
				}
				h, err := h3Decode(b)
				if err != nil {
					serverErr <- err
					return
				}
				records <- record{Stream: s.id, Kind: kind, Payload: hex.EncodeToString(b), Fields: h}
				if err = h3WriteFrame(s, 1, h3Encode([][2]string{{":status", "200"}})); err != nil {
					return
				}
				if h[":method"] == "GET" {
					_ = h3FinishRequest(s)
					return
				}
				stream := &trustH3Conn{quicStream: s}
				_, _ = io.Copy(stream, stream)
			}()
		}
	}()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err = os.WriteFile(ca, []byte(fixture.ca), 0600); err != nil {
		t.Fatal(err)
	}
	local := portAddress("127.0.0.1", unusedPort(t))
	_, port, _ := net.SplitHostPort(packet.LocalAddr().String())
	log, err := os.Create(filepath.Join(dir, "naive.log"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, reference, "--listen=socks://"+local, "--proxy=quic://client:private@example.com:"+port, "--host-resolver-rules=MAP example.com 127.0.0.1", "--log")
	command.Env = append(os.Environ(), "SSL_CERT_FILE="+ca)
	command.Stdout, command.Stderr = log, log
	if err = command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	defer func() {
		_ = command.Process.Kill()
		_ = command.Wait()
		log.Close()
		if t.Failed() {
			b, _ := os.ReadFile(log.Name())
			t.Log(string(b))
		}
	}()
	waitPort(t, local)
	out := testOutbound(t, Inbound{Type: "socks"}, local)
	out.Username, out.Password = "", ""
	probe := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	conn, err := probe.Dial(ctx, "tcp", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err = writeAll(conn, []byte("profile-check")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("profile-check"))
	if _, err = io.ReadFull(conn, got); err != nil || string(got) != "profile-check" {
		t.Fatal(string(got), err)
	}
	var captured []record
	for len(captured) < 3 {
		select {
		case r := <-records:
			captured = append(captured, r)
			t.Logf("%+v", r)
		case err := <-serverErr:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	data, err := json.MarshalIndent(captured, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if output := os.Getenv("LANBOAT_CAPTURE_HTTP3"); output != "" {
		if err = os.WriteFile(output, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var get, connect bool
	for _, r := range captured {
		get = get || r.Fields[":method"] == "GET"
		connect = connect || r.Fields[":method"] == "CONNECT"
		if strings.Contains(fmt.Sprint(r.Fields), "private") {
			t.Fatal("plaintext credential leak")
		}
	}
	if !get || !connect {
		t.Fatal("missing browser preamble or CONNECT")
	}
}
