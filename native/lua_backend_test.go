package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func luaOutbound(t *testing.T, in Inbound, address, file string) Outbound {
	t.Helper()
	out := testOutbound(t, in, address)
	out.Type = "lua"
	out.File = file
	return out
}
func TestLuaBuiltins(t *testing.T) {
	for _, kind := range []string{"http", "trojan"} {
		for _, tlsEnabled := range []bool{false, true} {
			if kind == "trojan" && !tlsEnabled {
				continue
			}
			t.Run(fmt.Sprint(kind, "/", tlsEnabled), func(t *testing.T) {
				in := testInbound(t, kind)
				if tlsEnabled {
					in.TLS = certificate(t)
				}
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out := luaOutbound(t, in, server.Address("server"), kind+"-backend.lua")
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, client)
				var wg sync.WaitGroup
				for range 8 {
					wg.Add(1)
					go func() { defer wg.Done(); assertTCP(t, client) }()
				}
				wg.Wait()
				conn, e := client.Dial(context.Background(), "udp", echoUDP(t))
				if conn != nil {
					conn.Close()
				}
				if e == nil {
					t.Error("UDP accepted without a script datagram API")
				}
			})
		}
	}
}
func TestLuaImportedCallbackScripts(t *testing.T) {
	for _, file := range []string{"trojan-backend.lua", "lightsword-backend.lua"} {
		t.Run(file, func(t *testing.T) {
			raw, e := os.ReadFile(filepath.Join("testdata", "lua-callback", file))
			if e != nil {
				t.Fatal(e)
			}
			in := testInbound(t, "trojan")
			var address string
			if file == "trojan-backend.lua" {
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				address = s.Address("server")
			} else {
				address = luaLightswordFixture(t, "aes-256-cfb")
				in.TLS = TLSOptions{}
			}
			out := luaOutbound(t, in, address, "")
			out.Script = string(raw)
			out.Method = "aes-256-cfb"
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
		})
	}
}
func luaLightswordFixture(t *testing.T, method string) string {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				size, ivs, _ := ssStreamParameters(method)
				password := "private"
				key := []byte(strings.Repeat(password, (size+len(password)-1)/len(password)))[:size]
				k, _ := newSSKey(method, password)
				k.master = key
				k.streamBlock, _ = newSSStreamBlock(method, key)
				if method == "table" {
					enc, dec := ssTable(string(key))
					k.tableEnc, k.tableDec = &enc, &dec
				}
				iv := make([]byte, ivs)
				if _, e = io.ReadFull(conn, iv); e != nil {
					return
				}
				decoder, _ := k.stream(iv, true)
				head := make([]byte, 2)
				if _, e = io.ReadFull(conn, head); e != nil {
					return
				}
				decoder.XORKeyStream(head, head)
				if head[0] != 5 {
					return
				}
				padding := make([]byte, int(head[1])+3)
				if _, e = io.ReadFull(conn, padding); e != nil {
					return
				}
				decoder.XORKeyStream(padding, padding)
				reader := &luaCipherReader{Reader: conn, stream: decoder, iv: append([]byte{}, iv...)}
				target, e := readAddress(reader)
				if e != nil {
					return
				}
				dst, e := net.Dial("tcp", target)
				if e != nil {
					return
				}
				defer dst.Close()
				targetBytes, _ := encodeAddress(target)
				reply := append([]byte{0, 5, 0, 0}, targetBytes...)
				rand.Read(iv)
				encoder, _ := k.stream(iv, false)
				encoder.XORKeyStream(reply, reply)
				response := append(append([]byte{}, iv...), reply...)
				// Split every header byte, then restart stream ciphers for application data.
				for _, c := range response {
					if _, e = conn.Write([]byte{c}); e != nil {
						return
					}
				}
				encoder, _ = k.stream(iv, false)
				// Client outbound IV is retained separately by the fixture's reader.
				reader.stream, _ = k.stream(readerIV(reader, ivs), true)
				done := make(chan struct{})
				go func() {
					io.Copy(dst, reader)
					if tcp, ok := dst.(*net.TCPConn); ok {
						tcp.CloseWrite()
					}
					close(done)
				}()
				writer := &luaCipherWriter{Writer: conn, stream: encoder}
				io.Copy(writer, dst)
			}()
		}
	}()
	return listener.Addr().String()
}

type luaCipherReader struct {
	io.Reader
	stream interface{ XORKeyStream([]byte, []byte) }
	iv     []byte
}

func (r *luaCipherReader) Read(p []byte) (int, error) {
	n, e := r.Reader.Read(p)
	r.stream.XORKeyStream(p[:n], p[:n])
	return n, e
}
func readerIV(r *luaCipherReader, n int) []byte {
	if r.iv == nil {
		return make([]byte, n)
	}
	return r.iv
}

type luaCipherWriter struct {
	io.Writer
	stream interface{ XORKeyStream([]byte, []byte) }
}

func (w *luaCipherWriter) Write(p []byte) (int, error) {
	out := make([]byte, len(p))
	w.stream.XORKeyStream(out, p)
	return w.Writer.Write(out)
}
func TestLuaLightswordCiphers(t *testing.T) {
	for _, method := range ShadowsocksMethods() {
		if _, _, ok := ssStreamParameters(method); !ok {
			continue
		}
		t.Run(method, func(t *testing.T) {
			address := luaLightswordFixture(t, method)
			out := luaOutbound(t, Inbound{Type: "http"}, address, "lightsword-backend.lua")
			out.Method = method
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, c)
		})
	}
}
func TestLuaHandshakeTailAndErrors(t *testing.T) {
	for _, response := range []string{"HTTP/1.1 200 OK\r\n\r\ntail", "HTTP/1.1 407 Rejected\r\n\r\n", "HTTP/1.1 200 OK\r\n"} {
		t.Run(fmt.Sprint(len(response)), func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			o := Outbound{LuaOptions: LuaOptions{File: "http-backend.lua"}, Password: "private"}
			if e := o.LuaOptions.prepare("lua"); e != nil {
				t.Fatal(e)
			}
			c, e := newLuaBackend(a, o, "[::1]:443")
			if e != nil {
				t.Fatal(e)
			}
			go func() {
				r := bufio.NewReader(b)
				req, e := http.ReadRequest(r)
				if e != nil {
					return
				}
				if req.Host != "[::1]:443" {
					t.Error("IPv6 CONNECT target", req.Host)
				}
				for _, x := range []byte(response) {
					if _, e = b.Write([]byte{x}); e != nil {
						return
					}
				}
				b.Close()
			}()
			a.SetDeadline(time.Now().Add(time.Second))
			e = c.handshake()
			if strings.HasSuffix(response, "tail") {
				if e != nil {
					t.Fatal(e)
				}
				p := make([]byte, 4)
				if _, e = io.ReadFull(c, p); e != nil || string(p) != "tail" {
					t.Fatal("tail lost", string(p), e)
				}
			} else if e == nil {
				t.Fatal("bad or truncated response accepted")
			}
		})
	}
}
func TestLuaScriptFileAndCancellation(t *testing.T) {
	in := testInbound(t, "trojan")
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := luaOutbound(t, in, s.Address("server"), "")
	out.ScriptPath = filepath.Join(t.TempDir(), "backend.lua")
	if e := os.WriteFile(out.ScriptPath, []byte(luaTrojanScript), 0600); e != nil {
		t.Fatal(e)
	}
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	assertTCP(t, c)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, e := listener.Accept()
		if e == nil {
			accepted <- conn
		}
	}()
	out = luaOutbound(t, Inbound{Type: "http"}, listener.Addr().String(), "http-backend.lua")
	c = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		conn, e := c.Dial(ctx, "tcp", "example.com:80")
		if conn != nil {
			conn.Close()
		}
		done <- e
	}()
	conn := <-accepted
	defer conn.Close()
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancelled Lua handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Lua cancellation blocked")
	}
}
func TestLuaRuntimeCloseAndHalfClose(t *testing.T) {
	in := testInbound(t, "trojan")
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := luaOutbound(t, in, s.Address("server"), "trojan-backend.lua")
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	payload := bytes.Repeat([]byte("lua-half-close"), 1000)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		if bytes.Equal(data, payload) {
			conn.Write([]byte("accepted"))
		}
	}()
	conn, e := c.Dial(context.Background(), "tcp", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write(payload)
	if e = conn.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
		t.Fatal(e)
	}
	body, e := io.ReadAll(conn)
	if e != nil || string(body) != "accepted" {
		t.Fatal(string(body), e)
	}
	conn, e = c.Dial(context.Background(), "tcp", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := conn.Read(make([]byte, 1)); done <- e }()
	c.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runtime close did not interrupt Lua read")
	}
}
func TestLuaConfiguration(t *testing.T) {
	for _, o := range []Outbound{
		{Type: "lua", File: "unknown"}, {Type: "lua", Script: "return true"}, {Type: "lua", Script: "while true do end"}, {Type: "lua", Script: "local ="}, {Type: "lua", File: "http-backend.lua", Script: "return true"}, {Type: "lua", ScriptPath: "/not/a/file"}, {Type: "direct", Script: "return true"},
	} {
		o.Tag = "proxy"
		if o.Type == "lua" {
			o.Server = "127.0.0.1"
			o.ServerPort = 443
			o.Password = "private"
		}
		raw, _ := json.Marshal(Config{Outbounds: []Outbound{o}})
		if _, e := Parse(raw); e == nil {
			t.Error("bad Lua configuration accepted", o.File)
		}
	}
}
func TestLuaTLSVerification(t *testing.T) {
	in := testInbound(t, "trojan")
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := luaOutbound(t, in, s.Address("server"), "trojan-backend.lua")
	out.TLS.Insecure = false
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	conn, e := c.Dial(context.Background(), "tcp", "example.com:443")
	if conn != nil {
		conn.Close()
	}
	if e == nil {
		t.Fatal("untrusted certificate accepted")
	}
}
func TestLuaTrojanOfficialReference(t *testing.T) {
	in := testInbound(t, "trojan")
	port := unusedPort(t)
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(cert, []byte(strings.Join(in.TLS.Certificate, "\n")), 0600)
	os.WriteFile(key, []byte(strings.Join(in.TLS.Key, "\n")), 0600)
	trojanGoReference(t, map[string]any{"run_type": "server", "local_addr": "127.0.0.1", "local_port": port, "remote_addr": "127.0.0.1", "remote_port": 80, "password": []string{"private"}, "disable_http_check": true, "ssl": map[string]any{"cert": cert, "key": key, "alpn": []string{"http/1.1"}}}, port)
	out := luaOutbound(t, in, portAddress("127.0.0.1", port), "trojan-backend.lua")
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	assertTCP(t, c)
	visionHTTPS(t, c, tls.VersionTLS13, false)
}

func TestLuaRetainedHeapLimits(t *testing.T) {
	for _, source := range []string{
		`local t={} for i=1,120 do t[i]=string.rep('x',100000)end function wa_lua_on_handshake_cb(c)return true end`,
		`local t={} for i=1,120 do local s=string.rep('x',100000)..i;t[i]=string.gmatch(s,'.')end function wa_lua_on_handshake_cb(c)return true end`,
		`local t={} for i=1,1800 do t[i]=crypto.encrypt.new('aes-256-cfb',string.rep('x',32),string.rep('y',16))end function wa_lua_on_handshake_cb(c)return true end`,
	} {
		o := Outbound{LuaOptions: LuaOptions{Script: source}, Password: "private"}
		if e := o.LuaOptions.prepare("lua"); e != nil {
			t.Fatal(e)
		}
		if _, e := newLuaBackend(nil, o, "example.com:443"); e == nil || !strings.Contains(e.Error(), "heap") {
			t.Fatal("heap limit not applied", e)
		}
	}
}
func TestLuaPluginIntegration(t *testing.T) {
	const script = `local b=require 'backend';local n=require 'network';function wa_lua_on_handshake_cb(c)local host=b.get_address_host(c);local kind=b.get_address_type(c);local addr=b.get_address_bytes(c);if kind==3 then addr=string.char(#host)..host end;b.write(c,string.char(kind)..addr..n.htons(b.get_address_port(c)));return true end`
	for _, plugin := range []SIP003Options{
		{Plugin: "obfs-local", PluginOpts: "obfs=http;obfs-host=example.com"},
		{Plugin: "obfs-local", PluginOpts: "obfs=tls;obfs-host=example.com"},
		{Plugin: "v2ray-plugin", PluginOpts: "mode=websocket;path=/lua;host=example.com;mux=0"},
		{Plugin: "gost", PluginOpts: gostPluginOptions("ws")},
	} {
		t.Run(plugin.Plugin+plugin.PluginOpts, func(t *testing.T) {
			in := testInbound(t, "shadowsocks")
			in.Method = "none"
			in.SIP003Options = plugin
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := luaOutbound(t, in, s.Address("server"), "")
			out.Script = script
			out.SIP003Options = plugin
			out.Method = ""
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, c)
		})
	}
}

func TestLuaEmptyScriptFileRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.lua")
	if e := os.WriteFile(path, nil, 0600); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(Config{Outbounds: []Outbound{{Type: "lua", Tag: "proxy", Server: "127.0.0.1", ServerPort: 443, Password: "private", LuaOptions: LuaOptions{ScriptPath: path}}}})
	if _, e := Parse(raw); e == nil || !strings.Contains(e.Error(), "empty") {
		t.Fatal("empty custom file fell back to builtin", e)
	}
}
