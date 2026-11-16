//go:build linux

package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type ocGSSReply struct {
	Token     string
	Complete  bool
	Error     string
	Principal string
}
type ocGSSReference struct {
	cmd       *exec.Cmd
	input     io.WriteCloser
	output    *json.Decoder
	once      sync.Once
	principal string
}

func ocGSSProcess(t *testing.T, env []string, role string, info OpenConnectNegotiateRequest) *ocGSSReference {
	t.Helper()
	source, _ := filepath.Abs("../tests/kerberos-reference/gss.py")
	cmd := exec.Command("python3", source, role)
	cmd.Env = env
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &ocGSSReference{cmd: cmd, input: input, output: json.NewDecoder(output)}
	t.Cleanup(func() { p.Close() })
	if err = json.NewEncoder(input).Encode(map[string]string{"service": info.Service, "binding": base64.StdEncoding.EncodeToString(info.ChannelBinding)}); err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *ocGSSReference) Next(ctx context.Context, token []byte) ([]byte, bool, error) {
	if err := json.NewEncoder(p.input).Encode(map[string]string{"token": base64.StdEncoding.EncodeToString(token)}); err != nil {
		return nil, false, err
	}
	type result struct {
		reply ocGSSReply
		err   error
	}
	ready := make(chan result, 1)
	go func() { var r ocGSSReply; e := p.output.Decode(&r); ready <- result{r, e} }()
	select {
	case r := <-ready:
		if r.err != nil {
			return nil, false, r.err
		}
		if r.reply.Error != "" {
			return nil, false, errors.New(r.reply.Error)
		}
		p.principal = r.reply.Principal
		b, e := base64.StdEncoding.DecodeString(r.reply.Token)
		return b, r.reply.Complete, e
	case <-ctx.Done():
		p.cmd.Process.Kill()
		<-ready
		return nil, false, ctx.Err()
	}
}
func (p *ocGSSReference) Close() error {
	p.once.Do(func() {
		_ = json.NewEncoder(p.input).Encode(map[string]bool{"close": true})
		p.input.Close()
		_ = p.cmd.Wait()
	})
	return nil
}

func TestOpenConnectNegotiateKerberosNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_GSS_CHILD") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v", "-test.timeout=90s")
		cmd.Env = append(os.Environ(), "LANBOAT_GSS_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated Kerberos:%v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = configureLink(lo.Index, 65536); err != nil {
		t.Fatal(err)
	}
	root := os.Getenv("LANBOAT_TEST_KERBEROS")
	if root == "" {
		root, _ = filepath.Abs("../.cache/kerberos-reference/root")
	}
	dir := t.TempDir()
	port := unusedPort(t)
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	conf := write("krb5.conf", fmt.Sprintf("[libdefaults]\n default_realm = LANBOAT.TEST\n dns_lookup_kdc = false\n dns_lookup_realm = false\n rdns = false\n dns_canonicalize_hostname = false\n[realms]\n LANBOAT.TEST = {\n  kdc = 127.0.0.1:%d\n }\n[domain_realm]\n localhost = LANBOAT.TEST\n[dbmodules]\n db_module_dir = %s/usr/lib/x86_64-linux-gnu/krb5/plugins/kdb\n[logging]\n kdc = STDERR\n", port, root))
	keytab := filepath.Join(dir, "service.keytab")
	kdcConf := write("kdc.conf", fmt.Sprintf("[kdcdefaults]\n kdc_listen = 127.0.0.1:%d\n kdc_tcp_listen = 127.0.0.1:%d\n[realms]\n LANBOAT.TEST = {\n  database_name = %s/principal\n  key_stash_file = %s/stash\n  supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal\n }\n", port, port, dir, dir))
	env := append(os.Environ(), "LANBOAT_TEST_KERBEROS="+root, "KRB5_CONFIG="+conf, "KRB5_KDC_PROFILE="+kdcConf, "KRB5CCNAME=FILE:"+filepath.Join(dir, "ccache"), "KRB5_KTNAME=FILE:"+keytab, "KRB5RCACHEDIR="+dir, "KRB5_TRACE=/dev/null", "LD_LIBRARY_PATH="+filepath.Join(root, "usr/lib/x86_64-linux-gnu"))
	run := func(name string, args ...string) {
		cmd := exec.Command(filepath.Join(root, name), args...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Kerberos setup %s:%v %s", filepath.Base(name), err, out)
		}
	}
	run("usr/sbin/kdb5_util", "create", "-s", "-P", "fixture-master-secret", "-r", "LANBOAT.TEST")
	run("usr/sbin/kadmin.local", "-r", "LANBOAT.TEST", "-q", "addprinc -pw fixture-client-password alice")
	run("usr/sbin/kadmin.local", "-r", "LANBOAT.TEST", "-q", "addprinc -randkey HTTP/vpn.lanboat.test")
	run("usr/sbin/kadmin.local", "-r", "LANBOAT.TEST", "-q", "ktadd -k "+keytab+" HTTP/vpn.lanboat.test")
	kdc := exec.Command(filepath.Join(root, "usr/sbin/krb5kdc"), "-n", "-r", "LANBOAT.TEST", "-P", filepath.Join(dir, "kdc.pid"))
	kdc.Env = env
	var kdcLog bytes.Buffer
	kdc.Stdout = &kdcLog
	kdc.Stderr = &kdcLog
	if err = kdc.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		kdc.Process.Kill()
		exit := kdc.Wait()
		if t.Failed() {
			t.Log("KDC exit:", exit)
		}
		if t.Failed() {
			t.Log(kdcLog.String())
		}
	}()
	ocWaitListening(t, portAddress("127.0.0.1", port))
	cmd := exec.Command(filepath.Join(root, "usr/bin/kinit.mit"), "alice@LANBOAT.TEST")
	cmd.Env = env
	cmd.Stdin = strings.NewReader("fixture-client-password\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("kinit:%v %s", err, out)
	}
	for _, mode := range []string{"cstp", "dtls", "wrong-channel-binding"} {
		t.Run(mode, func(t *testing.T) {
			in := Inbound{Type: "openconnect", Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{Username: "alice", Password: "unused"}}, OpenConnectOptions: OpenConnectOptions{DisableDTLS: mode != "dtls"}}
			backend := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			var acceptor *ocGSSReference
			var bindingRejected atomic.Bool
			front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method == "CONNECT" {
					raw, buffer, e := w.(http.Hijacker).Hijack()
					if e != nil {
						t.Error(e)
						return
					}
					defer raw.Close()
					var header bytes.Buffer
					if e = req.Write(&header); e != nil {
						t.Error(e)
						return
					}
					if e = backend.serveOpenConnect(in, &bufferedConn{Conn: raw, reader: bufio.NewReader(io.MultiReader(&header, buffer.Reader))}); e != nil {
						t.Error(e)
					}
					return
				}
				defer req.Body.Close()
				_, _ = io.Copy(io.Discard, req.Body)
				parts := strings.Fields(req.Header.Get("Authorization"))
				if len(parts) == 0 {
					w.Header().Set("WWW-Authenticate", "Negotiate")
					w.WriteHeader(401)
					return
				}
				if len(parts) != 2 || parts[0] != "Negotiate" {
					w.WriteHeader(401)
					return
				}
				b, e := base64.StdEncoding.DecodeString(parts[1])
				if e != nil {
					w.WriteHeader(401)
					return
				}
				token, complete, e := acceptor.Next(req.Context(), b)
				if e != nil {
					bindingRejected.Store(true)
					t.Log("reference rejected context:", e)
					w.WriteHeader(401)
					return
				}
				if len(token) > 0 {
					w.Header().Set("WWW-Authenticate", "Negotiate "+base64.StdEncoding.EncodeToString(token))
				}
				if !complete {
					w.WriteHeader(401)
					return
				}
				if acceptor.principal != "alice@LANBOAT.TEST" {
					t.Error("unbound principal", acceptor.principal)
					w.WriteHeader(401)
					return
				}
				ocAuthReply(t, w, ocXML{Type: "complete", Token: backend.ocServers["server"].cookie("alice", time.Now())})
			}))
			defer front.Close()
			binding := sha256.Sum256(front.Certificate().Raw)
			if mode == "wrong-channel-binding" {
				binding[0] ^= 1
			}
			acceptor = ocGSSProcess(t, env, "server", OpenConnectNegotiateRequest{ChannelBinding: binding[:]})
			u, _ := url.Parse(front.URL)
			p, _ := shadowPort(u.Port())
			client := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "openconnect", Tag: "proxy", Server: u.Hostname(), ServerPort: p, TLS: TLSOptions{Enabled: true, Insecure: true, ServerName: "vpn.lanboat.test"}, OpenConnectOptions: OpenConnectOptions{DisableDTLS: in.DisableDTLS}}}})
			client.SetOpenConnectNegotiateHandler(func(ctx context.Context, info OpenConnectNegotiateRequest) (OpenConnectNegotiateSession, error) {
				return ocGSSProcess(t, env, "client", info), nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if err := client.AuthenticateOpenConnect(ctx, "proxy"); mode == "wrong-channel-binding" {
				if err == nil || client.ocClients["proxy"].cookie != "" || !bindingRejected.Load() {
					t.Fatal("GSS channel binding mismatch accepted")
				}
				return
			} else if err != nil {
				t.Fatal(err)
			}
			var dtls *ocDTLS
			if mode == "dtls" {
				dtls = ocWaitDTLS(t, client.ocClients["proxy"].tunnel.Load())
			}
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 511, 4096, 60000})
			if dtls != nil && (dtls.sent.Load() == 0 || dtls.received.Load() == 0) {
				t.Fatal("authenticated connection did not carry DTLS traffic")
			}
			client.Close()
		})
	}
}
