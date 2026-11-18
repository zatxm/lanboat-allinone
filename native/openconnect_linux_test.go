//go:build linux

package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestOpenConnectReferenceNamespace(t *testing.T) {
	testOpenConnectReferenceNamespace(t, false, false, false)
}

func TestOpenConnectBrowserReferenceNamespace(t *testing.T) {
	for _, profile := range []string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"} {
		for _, version := range []string{"1.2", "1.3"} {
			for _, dtls := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/TLS%s/DTLS=%t", profile, version, dtls), func(t *testing.T) {
					t.Setenv("LANBOAT_OC_BROWSER", profile)
					rekey := ""
					if version == "1.2" {
						rekey = "cstp-ssl"
					}
					t.Setenv("LANBOAT_OC_REKEY", rekey)
					testOpenConnectReferenceNamespace(t, dtls, false, false)
				})
			}
		}
	}
}

func TestOpenConnectDTLSReferenceNamespace(t *testing.T) {
	testOpenConnectReferenceNamespace(t, true, false, false)
}

func TestOpenConnectOTPReferenceNamespace(t *testing.T) {
	testOpenConnectReferenceNamespace(t, false, true, false)
}
func TestOpenConnectOTPDTLSReferenceNamespace(t *testing.T) {
	testOpenConnectReferenceNamespace(t, true, true, false)
}

func TestOpenConnectDTLSCipherReferenceNamespace(t *testing.T) {
	for _, suite := range ocDTLSSuites {
		t.Run(suite.name, func(t *testing.T) { testOpenConnectReferenceNamespace(t, true, false, false, suite.name) })
	}
}

func TestOpenConnectRekeyReferenceNamespace(t *testing.T) {
	t.Setenv("LANBOAT_OC_REKEY", "1")
	t.Run("cstp", func(t *testing.T) { testOpenConnectReferenceNamespace(t, false, false, false) })
	t.Run("dtls", func(t *testing.T) { testOpenConnectReferenceNamespace(t, true, false, false) })
}

func TestOpenConnectDTLSSSLRekeyReferenceNamespace(t *testing.T) {
	t.Setenv("LANBOAT_OC_REKEY", "ssl")
	testOpenConnectReferenceNamespace(t, true, false, false)
}

func TestOpenConnectCSTPSSLRekeyReferenceNamespace(t *testing.T) {
	t.Setenv("LANBOAT_OC_REKEY", "cstp-ssl")
	t.Run("cstp", func(t *testing.T) { testOpenConnectReferenceNamespace(t, false, false, false) })
	t.Run("with-dtls", func(t *testing.T) { testOpenConnectReferenceNamespace(t, true, false, false) })
}

func TestOpenConnectDTLSCBCMtEReferenceNamespace(t *testing.T) {
	for _, suite := range ocDTLSSuites {
		if ocDTLSIsCBC(suite.id) {
			t.Run(suite.name, func(t *testing.T) { testOpenConnectReferenceNamespace(t, true, false, true, suite.name) })
		}
	}
}

func TestOpenConnectDTLSResumeReferenceNamespace(t *testing.T) {
	for _, version := range []string{"0.9", "1.2"} {
		t.Run(version, func(t *testing.T) {
			t.Setenv("LANBOAT_OC_RESUME", version)
			cipher := "AES128-SHA"
			if version == "1.2" {
				cipher = "AES128-GCM-SHA256"
			}
			testOpenConnectReferenceNamespace(t, true, false, false, cipher)
		})
	}
}

func testOpenConnectReferenceNamespace(t *testing.T, dtls, otp, noEtM bool, cipherName ...string) {
	cstpSSL := os.Getenv("LANBOAT_OC_REKEY") == "cstp-ssl"
	var ciphers []string
	if len(cipherName) != 0 {
		ciphers = cipherName
	}
	if os.Getenv("LANBOAT_OC_CHILD") != "1" {
		cmd := exec.Command("unshare", "--user", "--map-auto", "--map-root-user", "--setgroups", "allow", "--net", os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v", "-test.timeout=90s")
		cmd.Env = append(os.Environ(), "LANBOAT_OC_CHILD=1")
		b, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("OpenConnect isolated namespace: %v\n%s", e, b)
		}
		t.Log(string(b))
		return
	}
	lo, e := net.InterfaceByName("lo")
	if e != nil {
		t.Fatal(e)
	}
	if e = configureLink(lo.Index, 65536); e != nil {
		t.Fatal(e)
	}
	root := os.Getenv("LANBOAT_TEST_OPENCONNECT")
	if root == "" {
		root, e = filepath.Abs("../.cache/openconnect-reference/root")
		if e != nil {
			t.Fatal(e)
		}
	}
	lib := "LD_LIBRARY_PATH=" + filepath.Join(root, "usr/lib/x86_64-linux-gnu")
	resumeVersion := os.Getenv("LANBOAT_OC_RESUME")
	options := OpenConnectOptions{DisableDTLS: !dtls, DTLSCipherSuites: ciphers}
	if resumeVersion != "" {
		options.DTLSMode = "resume"
		options.DTLSVersion = resumeVersion
	}

	t.Run("native-client-to-ocserv", func(t *testing.T) {
		dir := t.TempDir()
		cert := certificate(t)
		write := func(name, content string) string {
			path := filepath.Join(dir, name)
			if e := os.WriteFile(path, []byte(content), 0600); e != nil {
				t.Fatal(e)
			}
			return path
		}
		certPath := write("cert.pem", strings.Join(cert.Certificate, "\n"))
		keyPath := write("key.pem", strings.Join(cert.Key, "\n"))
		passwd := filepath.Join(dir, "passwd")
		cmd := exec.Command(filepath.Join(root, "usr/bin/ocpasswd"), "-c", passwd, "client")
		cmd.Env = append(os.Environ(), lib)
		cmd.Stdin = strings.NewReader("private\nprivate\n")
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("ocpasswd: %v %s", e, b)
		}
		port := unusedPort(t)
		udpPort := uint16(0)
		if dtls {
			udpPort = port
		}
		config := fmt.Sprintf("auth = \"plain[passwd=%s]\"\nlisten-host = 127.0.0.1\ntcp-port = %d\nudp-port = %d\nrun-as-user = root\nrun-as-group = root\nsocket-file = %s\npid-file = %s\nserver-cert = %s\nserver-key = %s\nisolate-workers = false\ndevice = ocvpn\nipv4-network = 10.66.0.0/24\nipv6-network = fd66::/64\nipv6-subnet-prefix = 128\nmtu = 1500\nmax-clients = 8\nmax-same-clients = 4\ntry-mtu-discovery = false\nkeepalive = 20\ndpd = 30\ndtls-legacy = false\n", passwd, port, udpPort, filepath.Join(dir, "oc.sock"), filepath.Join(dir, "pid"), certPath, keyPath)
		if os.Getenv("LANBOAT_OC_REKEY") == "1" {
			config += "rekey-time = 4\nrekey-method = new-tunnel\n"
		}
		if os.Getenv("LANBOAT_OC_REKEY") == "ssl" {
			config += "rekey-time = 4\nrekey-method = ssl\n"
		}
		if cstpSSL {
			config += "rekey-time = 4\nrekey-method = ssl\ntls-priorities = \"NORMAL:-VERS-TLS1.3\"\n"
		}
		config += "dns = 10.66.0.1\ndns = fd66::1\ndefault-domain = corp.test\nsplit-dns = private.test\n"
		if ciphers != nil {
			priority := "NORMAL:+AES-128-CCM:+AES-256-CCM:+AES-128-CCM-8:+AES-256-CCM-8:+SHA256:+SHA384"
			if noEtM {
				priority += ":%NO_ETM"
			}
			config += "tls-priorities = \"" + priority + "\"\n"
		}
		if resumeVersion != "" {
			config = strings.Replace(config, "dtls-legacy = false", "dtls-legacy = true", 1)
			config += "tls-priorities = \"NORMAL:+VERS-DTLS0.9:+AES-128-CBC:+SHA1\"\n"
		}
		if otp {
			// RFC4226 counter0; only the unmodified ocserv/liboath reference validates it.
			path := write("users.otp", "HOTP client - 3132333435363738393031323334353637383930 0\n")
			config = strings.Replace(config, "plain[passwd="+passwd+"]", "plain[passwd="+passwd+",otp="+path+"]", 1)
		}
		ocDNSFixture(t, 53)
		path := write("ocserv.conf", config)
		log, _ := os.Create(filepath.Join(dir, "ocserv.log"))
		defer log.Close()
		cmd = exec.Command(filepath.Join(root, "usr/sbin/ocserv"), "-f", "--log-stderr", "-d", "2", "-c", path)
		cmd.Env = append(os.Environ(), lib)
		if resumeVersion != "" {
			cmd.Env = append(cmd.Env, "GNUTLS_SYSTEM_PRIORITY_FILE=/dev/null")
		}
		cmd.Stdout, cmd.Stderr = log, log
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		defer func() {
			cmd.Process.Kill()
			cmd.Wait()
			if t.Failed() {
				b, _ := os.ReadFile(log.Name())
				t.Log(string(b))
			}
		}()
		ocWaitListening(t, portAddress("127.0.0.1", port))
		browserTLS := TLSOptions{Enabled: true, Insecure: true}
		if profile := os.Getenv("LANBOAT_OC_BROWSER"); profile != "" {
			browserTLS.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
		}
		coreConfig := Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "openconnect", Tag: "assigned", Endpoint: "proxy", AcceptSearchDomain: true}}, Timeout: "5s"}}
		var client *Runtime
		if os.Getenv("LANBOAT_OC_ENDPOINT") == "1" {
			client = ocEndpointRuntime(t, ocEndpointOptions{Tag: "proxy", Server: "https://" + portAddress("127.0.0.1", port), Username: "client", Password: "private", OnDemand: true, OpenConnectOptions: options, TLS: ocEndpointTLS{CertificateAuthority: cert.Certificate, SystemTrustDisabled: true, TLSOptions: TLSOptions{ServerName: "example.com"}}}, coreConfig)
		} else {
			coreConfig.Outbounds = []Outbound{{Type: "openconnect", Tag: "proxy", Server: "127.0.0.1", ServerPort: port, Username: "client", Password: "private", TLS: browserTLS, OpenConnectOptions: options}}
			client = newTestRuntime(t, coreConfig)
		}
		prompts := 0
		if otp {
			client.SetOpenConnectAuthHandler(func(ctx context.Context, form OpenConnectAuthForm) (map[string]string, error) {
				prompts++
				answers := map[string]string{}
				for _, field := range form.Fields {
					if field.Name == "username" {
						answers[field.Name] = "client"
					}
					if field.Type == "password" {
						answers[field.Name] = "755224"
					}
				}
				return answers, nil
			})
		}
		var channel *ocDTLS
		if dtls {
			tunnel, err := client.ocClients["proxy"].session(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			channel = ocWaitDTLS(t, tunnel)
			t.Logf("DTLS cipher 0x%04x, EtM %v", channel.suite, channel.etm)
			if ciphers != nil {
				ids, _ := options.dtlsCipherIDs()
				if channel.suite != ids[0] || channel.etm != (ocDTLSIsCBC(ids[0]) && !noEtM) {
					t.Fatal("wrong reference DTLS cipher", channel.suite, ciphers)
				}
			}
		}
		for _, host := range []string{"www.corp.test", "www.private.test", "trunc.corp.test", "node"} {
			ocDNSQuery(t, client.resolver, host, 1, 0)
		}
		ocDNSQuery(t, client.resolver, "external.test", 1, 3)
		state := client.resolver.dnsNetwork("assigned")
		addresses := 2
		hosts := []string{"10.66.0.1", "fd66::1"}
		// ocserv's legacy Cisco negotiation intentionally disables IPv6.
		if resumeVersion == "0.9" {
			addresses = 1
			hosts = hosts[:1]
		}
		if len(state.addresses) != addresses || len(state.domains) != 1 || state.domains[0] != "corp.test" {
			t.Fatal("ocserv pushed DNS metadata", state)
		}
		for _, host := range hosts {
			tcp, e := net.Listen("tcp", ":0")
			if e != nil {
				t.Fatal(e)
			}
			defer tcp.Close()
			go func() {
				for {
					c, e := tcp.Accept()
					if e != nil {
						return
					}
					go func() { defer c.Close(); io.Copy(c, c) }()
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			conn, e := client.Dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(tcp.Addr().(*net.TCPAddr).Port)))
			cancel()
			if e != nil {
				t.Fatal(e)
			}
			wgRoundtripTCP(t, conn)
			udp, e := net.ListenPacket("udp", ":0")
			if e != nil {
				t.Fatal(e)
			}
			defer udp.Close()
			go func() {
				b := make([]byte, 65535)
				for {
					n, a, e := udp.ReadFrom(b)
					if e != nil {
						return
					}
					udp.WriteTo(b[:n], a)
				}
			}()
			conn, e = client.Dial(context.Background(), "udp", net.JoinHostPort(host, strconv.Itoa(udp.LocalAddr().(*net.UDPAddr).Port)))
			if e != nil {
				t.Fatal(e)
			}
			wgRoundtripUDP(t, conn)
			tunnel, e := client.ocClients["proxy"].session(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			kind, reply := byte(8), byte(0)
			if strings.Contains(host, ":") {
				kind, reply = 128, 129
			}
			ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
			response, e := tunnel.stack.exchangeICMP(ctx, netip.MustParseAddr(host), []byte{kind, 0, 0, 0, 0, 17, 0, 9, 1, 2, 3}, 63)
			cancel()
			if e != nil || len(response.data) < 8 || response.data[0] != reply {
				t.Fatal("reference ICMP", host, response, e)
			}
		}
		if dtls && (channel.sent.Load() == 0 || channel.received.Load() == 0) {
			t.Fatal("reference traffic did not use DTLS")
		}
		if cstpSSL {
			previous := client.ocClients["proxy"].tunnel.Load()
			secured := ocCSTPTLS(previous.conn)
			if secured == nil || previous.rekeyMethod != "ssl" {
				t.Fatal("reference did not negotiate TLS1.2 CSTP ssl rekey")
			}
			conn, err := client.Dial(context.Background(), "tcp", masqueEcho(t, "tcp", "10.66.0.1:0"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			deadline := time.Now().Add(2*previous.rekeyAfter + 3*time.Second)
			for secured.generation.Load() < 2 && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if secured.generation.Load() < 2 || client.ocClients["proxy"].tunnel.Load() != previous {
				t.Fatal("CSTP ssl did not preserve the tunnel", secured.generation.Load())
			}
			wgRoundtripTCP(t, conn)
			for _, host := range hosts {
				assertUDPAddress(t, client, []int{1, 4096, 60000}, masqueEcho(t, "udp", net.JoinHostPort(host, "0")))
			}
			if dtls && ocWaitDTLS(t, previous) != channel {
				t.Fatal("CSTP rekey replaced DTLS")
			}
			t.Log("ocserv TLS1.2 CSTP original connection rekeyed", secured.generation.Load())
		}
		if os.Getenv("LANBOAT_OC_REKEY") == "ssl" {
			previous := client.ocClients["proxy"].tunnel.Load()
			t.Log("ocserv DTLS rekey advice", previous.dtlsRekeyAfter, previous.dtlsRekeyMethod)
			if previous.dtlsRekeyMethod != "ssl" || previous.dtlsRekeyAfter <= 0 || previous.dtlsRekeyAfter > 20*time.Second {
				t.Fatal("unexpected reference rekey advice")
			}
			deadline := time.Now().Add(previous.dtlsRekeyAfter + 3*time.Second)
			for channel.generation.Load() == 0 && channel.ready.Load() && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if channel.generation.Load() == 0 || !channel.ready.Load() || ocWaitDTLS(t, previous) != channel || client.ocClients["proxy"].tunnel.Load() != previous {
				t.Fatal("ocserv ssl rekey replaced the authenticated association")
			}
			conn, err := client.Dial(context.Background(), "tcp", masqueEcho(t, "tcp", "10.66.0.1:0"))
			if err != nil {
				t.Fatal(err)
			}
			wgRoundtripTCP(t, conn)
			assertUDPAddress(t, client, []int{1, 4096, 60000}, masqueEcho(t, "udp", "10.66.0.1:0"))
		}
		if os.Getenv("LANBOAT_OC_REKEY") == "1" {
			previous := client.ocClients["proxy"].tunnel.Load()
			cookie := client.ocClients["proxy"].cookie
			select {
			case <-previous.finished:
			case <-time.After(6 * time.Second):
				t.Fatal("reference rekey advice ignored")
			}
			next, err := client.ocClients["proxy"].session(context.Background())
			if err != nil || next == previous || client.ocClients["proxy"].cookie != cookie {
				t.Fatal("reference cookie renewal failed", err)
			}
			if dtls {
				ocWaitDTLS(t, next)
			}
			conn, err := client.Dial(context.Background(), "tcp", masqueEcho(t, "tcp", "10.66.0.1:0"))
			if err != nil {
				t.Fatal(err)
			}
			wgRoundtripTCP(t, conn)
			assertUDPAddress(t, client, []int{1, 4096}, masqueEcho(t, "udp", "10.66.0.1:0"))
		}
		client.resetNetworkTransports()
		if _, e = client.ocClients["proxy"].session(context.Background()); e != nil {
			t.Fatal("cookie reconnect", e)
		}
		if otp && prompts != 1 {
			t.Fatal("expected one OTP prompt", prompts)
		}
	})
	if otp || noEtM || os.Getenv("LANBOAT_OC_REKEY") == "1" || os.Getenv("LANBOAT_OC_BROWSER") != "" {
		return
	}
	// OpenConnect9.21's default policy omits CCM8 and PSK-AES256-CBC-SHA384.
	// Its server direction is exercised with the public GnuTLS API fixture instead.
	if ciphers != nil && (strings.HasSuffix(ciphers[0], "CCM8") || ciphers[0] == "PSK-AES256-CBC-SHA384") {
		return
	}
	t.Run("openconnect-to-native-server", func(t *testing.T) {
		proxy := socksEchoProxy(t)
		out := testOutbound(t, Inbound{Type: "socks"}, proxy)
		out.Username, out.Password = "", ""
		in := Inbound{Type: "openconnect", Tag: "server", Listen: "127.0.0.1", MTU: 16376, TLS: certificate(t), Users: []User{{Username: "client", Password: "private"}}, OpenConnectOptions: options}
		if os.Getenv("LANBOAT_OC_REKEY") == "ssl" {
			in.DTLSRekeyTime = "2s"
			in.DTLSRekeyMethod = "ssl"
		}
		if cstpSSL {
			in.RekeyTime, in.RekeyMethod, in.TLS.MaxVersion = "2s", "ssl", "1.2"
		}
		dnsPort, _ := ocDNSFixture(t)
		in.OpenConnectOptions.DNS = []string{"192.0.2.53", "2001:db8::53"}
		in.SearchDomains = []string{"corp.test", "lab.test"}
		in.SplitDNS = []string{"private.test"}
		in.TunnelAllDNS = true
		in.SplitInclude = []string{"192.0.2.0/24", "2001:db8::/64"}
		in.SplitExclude = []string{"192.0.2.99/32", "2001:db8::99/128"}
		cfg := Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{out, {Type: "direct", Tag: "dns-direct"}}, Route: Route{Rules: []Rule{{Port: []uint16{53}, OverrideAddress: "127.0.0.1", OverridePort: dnsPort, Outbound: "dns-direct"}}}}
		var server *Runtime
		var rekeyLogs *observer.ObservedLogs
		if cstpSSL {
			core, logs := observer.New(zap.DebugLevel)
			rekeyLogs = logs
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			server, err = New(context.Background(), data, zap.New(core))
			if err != nil {
				t.Fatal(err)
			}
			if err = server.Start(); err != nil {
				server.Close()
				t.Fatal(err)
			}
			t.Cleanup(func() {
				server.Close()
				if t.Failed() {
					for _, entry := range logs.All() {
						t.Log(entry.Message, entry.ContextMap())
					}
				}
			})
		} else {
			server = newTestRuntime(t, cfg)
		}
		block, _ := pem.Decode([]byte(in.TLS.Certificate[0]))
		parsed, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			t.Fatal(e)
		}
		pin := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
		dir := t.TempDir()
		script := filepath.Join(dir, "vpnc-script")
		ready := filepath.Join(dir, "ready")
		dnsEnv := filepath.Join(dir, "pushed-dns")
		text := "#!/bin/sh\nset -eu\nif [ \"$reason\" = connect ]; then\n ip address add \"$INTERNAL_IP4_ADDRESS/32\" dev \"$TUNDEV\"\n ip -6 address add fd44::2/128 dev \"$TUNDEV\" nodad\n ip link set \"$TUNDEV\" mtu 1280 up\n ip route add 192.0.2.9/32 dev \"$TUNDEV\"\n ip -6 route add 2001:db8::9/128 dev \"$TUNDEV\"\n ip route add 192.0.2.53/32 dev \"$TUNDEV\"\n ip -6 route add 2001:db8::53/128 dev \"$TUNDEV\"\n printf '%s\\n' \"${INTERNAL_IP4_DNS-}\" \"${INTERNAL_IP6_DNS-}\" \"${CISCO_DEF_DOMAIN-}\" \"${CISCO_SPLIT_DNS-}\" \"${CISCO_SPLIT_INC_0_ADDR-}\" \"${CISCO_IPV6_SPLIT_INC_0_ADDR-}\" \"${CISCO_SPLIT_EXC_0_ADDR-}\" \"${CISCO_IPV6_SPLIT_EXC_0_ADDR-}\" > '" + dnsEnv + "'\n touch '" + ready + "'\nfi\n"
		if e = os.WriteFile(script, []byte(text), 0700); e != nil {
			t.Fatal(e)
		}
		log, _ := os.Create(filepath.Join(dir, "openconnect.log"))
		defer log.Close()
		args := []string{"--mtu=16376", "--base-mtu=16456", "--protocol=anyconnect", "--user=client", "--passwd-on-stdin", "--non-inter", "--servercert=pin-sha256:" + base64.StdEncoding.EncodeToString(pin[:]), "--interface=ocnative", "--script=" + script, "https://" + server.Address("server")}
		if cstpSSL {
			args = append([]string{"--gnutls-priority=NORMAL:-VERS-TLS1.3"}, args...)
		}
		if resumeVersion != "" {
			name := ""
			if resumeVersion == "1.2" {
				name = ciphers[0]
			}
			args = append([]string{"--dtls-ciphers=AES128-SHA", "--dtls12-ciphers=" + name}, args...)
		}
		if !dtls {
			args = append([]string{"--no-dtls"}, args...)
		}
		cmd := exec.Command(filepath.Join(root, "usr/sbin/openconnect"), args...)
		cmd.Env = append(os.Environ(), lib)
		if resumeVersion != "" {
			cmd.Env = append(cmd.Env, "GNUTLS_SYSTEM_PRIORITY_FILE=/dev/null")
		}
		cmd.Stdin = strings.NewReader("private\n")
		cmd.Stdout, cmd.Stderr = log, log
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		defer func() {
			cmd.Process.Kill()
			cmd.Wait()
			if t.Failed() {
				b, _ := os.ReadFile(log.Name())
				t.Log(string(b))
			}
		}()
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, e := os.Stat(ready); e == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("official OpenConnect did not configure tunnel")
			}
			time.Sleep(20 * time.Millisecond)
		}
		pushed, err := os.ReadFile(dnsEnv)
		if err != nil || !strings.Contains(string(pushed), "192.0.2.53") || !strings.Contains(string(pushed), "2001:db8::53") || !strings.Contains(string(pushed), "corp.test lab.test") || !strings.Contains(string(pushed), "private.test") {
			t.Fatal("official client did not parse pushed DNS", string(pushed), err)
		}
		for _, route := range []string{"192.0.2.0", "2001:db8::", "192.0.2.99", "2001:db8::99"} {
			if !strings.Contains(string(pushed), route) {
				t.Fatal("official client did not parse pushed split routes", string(pushed))
			}
		}
		for _, ip := range []string{"192.0.2.53", "2001:db8::53"} {
			for _, network := range []string{"udp", "tcp"} {
				call, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				r := resolver{tunnelDial: func(ctx context.Context, _ DNSServer, netw string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, netw, net.JoinHostPort(ip, "53"))
				}}
				q, _ := makeDNSQuery("www.private.test", 1)
				b, err := r.exchangeOn(call, DNSServer{Type: network, Server: ip}, q)
				cancel()
				if err != nil {
					t.Fatal("official TUN DNS", network, ip, err)
				}
				if _, _, _, err := validateDNSQuestionResponse(q, b); err != nil {
					t.Fatal(err)
				}
			}
		}
		var channel *ocDTLS
		if dtls {
			deadline := time.Now().Add(8 * time.Second)
			for time.Now().Before(deadline) && channel == nil {
				listener := server.ocServers["server"].dtls
				listener.mu.Lock()
				for _, binding := range listener.bindings {
					binding.tunnel.dtlsMu.Lock()
					channel = binding.tunnel.dtls
					binding.tunnel.dtlsMu.Unlock()
					if channel != nil {
						break
					}
				}
				listener.mu.Unlock()
				if channel == nil {
					time.Sleep(5 * time.Millisecond)
				}
			}
			if channel == nil || !channel.ready.Load() {
				t.Fatal("official OpenConnect did not establish DTLS")
			}
			t.Logf("DTLS cipher 0x%04x, EtM %v", channel.suite, channel.etm)
			if ciphers != nil {
				ids, _ := options.dtlsCipherIDs()
				if channel.suite != ids[0] || channel.etm {
					t.Fatal("wrong reference DTLS cipher", channel.suite, ciphers)
				}
			}
		}
		for _, host := range []string{"192.0.2.9", "2001:db8::9"} {
			c, e := net.DialTimeout("tcp", net.JoinHostPort(host, "443"), 5*time.Second)
			if e != nil {
				t.Fatal(e)
			}
			wgRoundtripTCP(t, c)
			c, e = net.Dial("udp", net.JoinHostPort(host, "9000"))
			if e != nil {
				t.Fatal(e)
			}
			wgRoundtripUDP(t, c)
		}
		if dtls && (channel.sent.Load() == 0 || channel.received.Load() == 0) {
			t.Fatal("official client traffic did not use DTLS")
		}
		if cstpSSL {
			conn, err := net.DialTimeout("tcp", "192.0.2.9:443", 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			deadline := time.Now().Add(7 * time.Second)
			for rekeyLogs.FilterMessageSnippet("openconnect: CSTP rekeyed").Len() < 2 && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if rekeyLogs.FilterMessageSnippet("openconnect: CSTP rekeyed").Len() < 2 {
				t.Fatal("official client did not complete two CSTP rekeys")
			}
			wgRoundtripTCP(t, conn)
			for _, host := range []string{"192.0.2.9", "2001:db8::9"} {
				conn, err := net.Dial("udp", net.JoinHostPort(host, "9000"))
				if err != nil {
					t.Fatal(err)
				}
				wgRoundtripUDP(t, conn)
			}
			if dtls {
				listener := server.ocServers["server"].dtls
				listener.mu.Lock()
				ready := false
				for _, binding := range listener.bindings {
					binding.tunnel.dtlsMu.Lock()
					current := binding.tunnel.dtls
					ready = ready || current != nil && current.ready.Load()
					binding.tunnel.dtlsMu.Unlock()
				}
				listener.mu.Unlock()
				if !ready {
					t.Fatal("CSTP rekey did not restore the reference client's renewed DTLS channel")
				}
			}
			content, err := os.ReadFile(log.Name())
			if err != nil || strings.Count(string(content), "Got CONNECT response:") != 1 {
				t.Fatal("reference recreated CSTP", err)
			}
			t.Log("official OpenConnect TLS1.2 CSTP original connection rekeyed twice")
		}
		if os.Getenv("LANBOAT_OC_REKEY") == "ssl" {
			deadline := time.Now().Add(5 * time.Second)
			for channel.generation.Load() == 0 && channel.ready.Load() && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if channel.generation.Load() == 0 || !channel.ready.Load() {
				t.Fatal("official client did not renegotiate DTLS")
			}
			for _, host := range []string{"192.0.2.9", "2001:db8::9"} {
				conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "443"), 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				wgRoundtripTCP(t, conn)
				conn, err = net.Dial("udp", net.JoinHostPort(host, "9000"))
				if err != nil {
					t.Fatal(err)
				}
				wgRoundtripUDP(t, conn)
			}
		}
	})
}

func TestOpenConnectICMPNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_OC_ICMP_CHILD") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^TestOpenConnectICMPNamespace$", "-test.timeout=20s")
		cmd.Env = append(os.Environ(), "LANBOAT_OC_ICMP_CHILD=1")
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("ICMP namespace: %v %s", e, b)
		}
		return
	}
	lo, _ := net.InterfaceByName("lo")
	if e := configureLink(lo.Index, 65536); e != nil {
		t.Fatal(e)
	}
	_, client := ocPair(t)
	tunnel, e := client.ocClients["proxy"].session(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	ocWaitDTLS(t, tunnel)
	for _, host := range []string{"127.0.0.1", "::1"} {
		kind, reply := byte(8), byte(0)
		if host == "::1" {
			kind, reply = 128, 129
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		request := append([]byte{kind, 0, 0, 0, 0, 7, 0, 9}, bytes.Repeat([]byte("icmp"), 32)...)
		response, e := tunnel.stack.exchangeICMP(ctx, netip.MustParseAddr(host), request, 63)
		cancel()
		if e != nil || len(response.data) != len(request) || response.data[0] != reply || !bytes.Equal(response.data[4:], request[4:]) {
			t.Fatal(host, response, e)
		}
	}
}

func ocWaitListening(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if e == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("reference did not listen", e)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
