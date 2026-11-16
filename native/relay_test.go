package native

import (
	"encoding/binary"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func startGOST(t *testing.T, args ...string) {
	t.Helper()
	binary := os.Getenv("LANBOAT_TEST_GOST")
	if binary == "" {
		t.Skip("LANBOAT_TEST_GOST is required for GOST interoperability")
	}
	log, err := os.Create(filepath.Join(t.TempDir(), "gost.log"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, args...)
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		command.Process.Kill()
		_ = command.Wait()
		log.Close()
		if t.Failed() {
			data, _ := os.ReadFile(log.Name())
			t.Log(string(data))
		}
	})
	// GOST3.3.2 loads its authentication map asynchronously after opening listeners.
	// Readiness probes are separate from real interoperability requests, which never retry.
	for i, arg := range args {
		if arg != "-L" || i+1 >= len(args) {
			continue
		}
		u, e := url.Parse(args[i+1])
		if e != nil || u.Scheme != "relay" || u.User == nil {
			continue
		}
		password, _ := u.User.Password()
		waitGOSTRelayAuthentication(t, u.Host, u.User.Username(), password)
	}
}
func waitGOSTRelayAuthentication(t *testing.T, address, user, password string) {
	t.Helper()
	_, portText, _ := net.SplitHostPort(tcpEcho(t))
	port, _ := strconv.ParseUint(portText, 10, 16)
	// Independent fixed IPv4 wire probe: auth feature, address feature, then echo payload.
	auth := append([]byte{byte(len(user))}, user...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, password...)
	features := []byte{1, 0, byte(len(auth))}
	features = append(features, auth...)
	features = append(features, 2, 0, 7, 1, 127, 0, 0, 1)
	features = binary.BigEndian.AppendUint16(features, uint16(port))
	packet := binary.BigEndian.AppendUint16([]byte{1, 1}, uint16(len(features)))
	packet = append(packet, features...)
	packet = append(packet, 'r')
	for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
		conn, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if e == nil {
			conn.SetDeadline(time.Now().Add(time.Second))
			e = writeAll(conn, packet)
			var response [4]byte
			if e == nil {
				_, e = io.ReadFull(conn, response[:])
			}
			conn.Close()
			if e == nil && response[0] == 1 && response[1] == 0 {
				return
			}
			if e == nil && (response[0] != 1 || response[1] != 2) {
				t.Fatalf("GOST readiness unexpected status %x", response)
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("GOST authentication map did not become ready")
}
func waitPort(t *testing.T, address string, startupTimeout ...time.Duration) {
	t.Helper()
	budget := 3 * time.Second
	if len(startupTimeout) != 0 {
		budget = startupTimeout[0]
	}
	until := time.Now().Add(budget)
	for time.Now().Before(until) {
		c, err := net.DialTimeout("tcp", address, 20*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("reference listener did not start", address)
}

func TestRelayGOSTReference(t *testing.T) {
	for _, direction := range []string{"client", "server"} {
		t.Run(direction, func(t *testing.T) {
			var client *Runtime
			if direction == "client" {
				address := portAddress("127.0.0.1", unusedPort(t))
				startGOST(t, "-L", "relay://client:private@"+address)
				waitPort(t, address)
				out := testOutbound(t, Inbound{Type: "relay"}, address)
				client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			} else {
				in := testInbound(t, "relay")
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				address := portAddress("127.0.0.1", unusedPort(t))
				startGOST(t, "-L", "socks5://"+address+"?udp=true", "-F", "relay://client:private@"+server.Address("server")+"?nodelay=true")
				waitPort(t, address)
				out := testOutbound(t, Inbound{Type: "socks"}, address)
				out.Username, out.Password = "", ""
				client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			}
			assertTCP(t, client)
			if direction == "client" {
				assertUDPSizes(t, client, []int{1, 511, 4096})
			} else {
				in := testInbound(t, "relay")
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				address := portAddress("127.0.0.1", unusedPort(t))
				target := echoUDP(t)
				// Keep the reference association alive across all three request/response pairs.
				startGOST(t, "-L", "udp://"+address+"/"+target+"?keepalive=true", "-F", "relay://client:private@"+server.Address("server")+"?nodelay=true")
				time.Sleep(50 * time.Millisecond)
				direct := newTestRuntime(t, Config{})
				assertUDPAddress(t, direct, []int{1, 511, 4096}, address)
			}
		})
	}
}
