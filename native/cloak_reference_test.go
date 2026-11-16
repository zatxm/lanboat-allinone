package native

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func startCloakReference(t *testing.T, role string, config map[string]any, args ...string) {
	t.Helper()
	dir := os.Getenv("LANBOAT_TEST_CLOAK")
	if dir == "" {
		t.Skip("LANBOAT_TEST_CLOAK must contain official2.12.0 binaries")
	}
	work := t.TempDir()
	path := filepath.Join(work, "config.json")
	b, e := json.Marshal(config)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	log, e := os.Create(filepath.Join(work, "reference.log"))
	if e != nil {
		t.Fatal(e)
	}
	command := exec.Command(filepath.Join(dir, "ck-"+role+"-linux-amd64-v2.12.0"), append([]string{"-c", path, "-verbosity", "debug"}, args...)...)
	command.Stdout, command.Stderr = log, log
	if e = command.Start(); e != nil {
		log.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() {
		command.Process.Kill()
		command.Wait()
		log.Close()
		if t.Failed() {
			b, _ := os.ReadFile(log.Name())
			t.Log(string(b))
		}
	})
}
func cloakReferenceServer(t *testing.T, target, mode string) (string, string) {
	t.Helper()
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	uid := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))
	address := portAddress("127.0.0.1", unusedPort(t))
	config := map[string]any{"BindAddr": []string{address}, "PrivateKey": base64.StdEncoding.EncodeToString(key.Bytes()), "BypassUID": []string{uid}, "ProxyBook": map[string]any{"shadowsocks": []string{"tcp", target}}, "RedirAddr": "127.0.0.1:1"}
	startCloakReference(t, "server", config)
	waitPort(t, address)
	options := "UID=" + uid + ";PublicKey=" + base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()) + ";ProxyMethod=shadowsocks;Transport=" + mode + ";ServerName=example.com;NumConn=4"
	return address, options
}
func cloakTLSEdge(t *testing.T, target string) string {
	t.Helper()
	proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		dst, e := net.Dial("tcp", target)
		if e != nil {
			http.Error(w, "upstream unavailable", 502)
			return
		}
		hijacker := w.(http.Hijacker)
		src, buffer, e := hijacker.Hijack()
		if e != nil {
			dst.Close()
			return
		}
		defer src.Close()
		defer dst.Close()
		request.RequestURI = ""
		if e = request.Write(dst); e != nil {
			return
		}
		done := make(chan struct{})
		go func() { io.Copy(dst, buffer); dst.Close(); close(done) }()
		io.Copy(src, dst)
		src.Close()
		<-done
	}))
	t.Cleanup(proxy.Close)
	return strings.TrimPrefix(proxy.URL, "https://")
}
func TestCloakOfficialReference(t *testing.T) {
	for _, transport := range []string{"direct", "cdn", "websocket"} {
		for _, method := range []string{"plain", "aes-gcm", "aes-128-gcm", "chacha20-poly1305"} {
			for _, direction := range []string{"client", "server"} {
				t.Run(transport+"/"+method+"/"+direction, func(t *testing.T) {
					if direction == "server" {
						in := testInbound(t, "shadowsocks")
						backend := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						address, options := cloakReferenceServer(t, backend.Address(in.Tag), transport)
						tlsOptions := TLSOptions{}
						if transport != "direct" {
							address = cloakTLSEdge(t, address)
							tlsOptions = TLSOptions{Enabled: true, Insecure: true}
						}
						o := cloakTestOutbound(t, in, address, options+";EncryptionMethod="+method)
						o.TLS = tlsOptions
						c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
						assertTCP(t, c)
						kcpLargeTransfer(t, c, 400000)
					} else {
						in, options := cloakTestInbound(t, transport, method)
						if transport != "websocket" {
							in.TLS = TLSOptions{}
						}
						s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						values, _ := sip003Options(options)
						host, port, _ := net.SplitHostPort(s.Address(in.Tag))
						config := map[string]any{"UID": values["UID"], "PublicKey": values["PublicKey"], "ProxyMethod": "shadowsocks", "EncryptionMethod": method, "ServerName": "example.com", "BrowserSig": "chrome", "Transport": transport, "NumConn": 4}
						if transport == "cdn" {
							edge := cloakTLSEdge(t, s.Address(in.Tag))
							host, port, _ = net.SplitHostPort(edge)
							config["ServerName"] = host
							config["CDNOriginHost"] = "example.com"
							config["Transport"] = "CDN"
						}
						if transport == "websocket" {
							config["Transport"] = "CDN"
							config["CDNOriginHost"] = "example.com"
						}
						localPort := unusedPort(t)
						startCloakReference(t, "client", config, "-s", host, "-p", port, "-l", strconv.Itoa(int(localPort)), "-proxy", "shadowsocks")
						local := portAddress("127.0.0.1", localPort)
						waitPort(t, local)
						o := testOutbound(t, in, local)
						// ck-client accepts plain SIP003 input; the outer WSS TLS belongs to Cloak.
						o.TLS = TLSOptions{}
						c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
						assertTCP(t, c)
						kcpLargeTransfer(t, c, 400000)
					}
				})
			}
		}
	}
}
