package native

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSimpleObfsIndependent(t *testing.T) {
	for _, mask := range []string{"http", "tls"} {
		for _, method := range []string{"aes-256-cfb", "aes-128-gcm", "2022-blake3-aes-128-gcm"} {
			t.Run(mask+"/"+method, func(t *testing.T) {
				in := testInbound(t, "shadowsocks")
				in.Method = method
				if isSS2022(method) {
					in.Password = "BwcHBwcHBwcHBwcHBwcHBw=="
				}
				in.SIP003Options = SIP003Options{Plugin: "obfs-local", PluginOpts: "obfs=" + mask + ";obfs-host=cdn.example;obfs-uri=/proxy"}
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out := testOutbound(t, in, s.Address("server"))
				out.Password = in.Password
				out.SIP003Options = in.SIP003Options
				c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{1, 511, 4096, 60000})
				data, err := json.Marshal(c.config)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = Parse(data); err != nil {
					t.Fatal("normalized config cannot reload", err)
				}
			})
		}
	}
}

func TestV2rayQUICPluginIdentityAndReload(t *testing.T) {
	cert := certificate(t)
	dir := t.TempDir()
	ca := filepath.Join(dir, "server.crt")
	key := filepath.Join(dir, "server.key")
	if err := os.WriteFile(ca, []byte(cert.Certificate[0]), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte(cert.Key[0]), 0600); err != nil {
		t.Fatal(err)
	}
	in := testInbound(t, "shadowsocks")
	in.SIP003Options = SIP003Options{Plugin: "v2ray-plugin", PluginOpts: "server;mode=quic;host=example.com;cert=" + ca + ";key=" + key}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, s.Address("server"))
	out.SIP003Options = SIP003Options{Plugin: "v2ray-plugin", PluginOpts: "mode=quic;host=example.com;cert=" + ca}
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	assertTCP(t, c)
	data, err := json.Marshal(c.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Parse(data); err != nil {
		t.Fatal("plugin client configuration cannot reload", err)
	}
	data, err = json.Marshal(s.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Parse(data); err != nil {
		t.Fatal("plugin server configuration cannot reload", err)
	}
	out.PluginOpts = "mode=quic;host=wrong.example;cert=" + ca
	bad := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	if conn, err := bad.Dial(context.Background(), "tcp", relayEchoTCP(t)); err == nil {
		conn.Close()
		t.Fatal("plugin bypassed certificate hostname verification")
	}
}

func TestSimpleObfsAuthentication(t *testing.T) {
	for _, mask := range []string{"http", "tls"} {
		t.Run(mask, func(t *testing.T) {
			in := testInbound(t, "shadowsocks")
			in.SIP003Options = SIP003Options{Plugin: "obfs-local", PluginOpts: "obfs=" + mask}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, s.Address("server"))
			out.SIP003Options = in.SIP003Options
			out.Password = "wrong"
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			conn, err := c.Dial(context.Background(), "tcp", relayEchoTCP(t))
			if err != nil {
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(time.Second))
			if err := writeAll(conn, []byte("auth-probe")); err != nil {
				return
			}
			if _, err := io.ReadFull(conn, make([]byte, 10)); err == nil {
				t.Fatal("wrong Shadowsocks password accepted through camouflage")
			}
		})
	}
}

func TestSIP003ValidationAndEscaping(t *testing.T) {
	value, err := sip003Options(`obfs=http;obfs-uri=/a\;b\=c\\d;obfs-host=cdn.example`)
	if err != nil || value["obfs-uri"] != `/a;b=c\d` {
		t.Fatal("SIP003 escaping", value, err)
	}
	for _, text := range []string{"obfs=http;obfs=tls", "=value", "a=1;;b=2", "a=trailing\\", "a=bad\\x", "a=bad\r\n"} {
		if _, err := sip003Options(text); err == nil {
			t.Fatal("accepted malformed options", text)
		}
	}
	for _, p := range []SIP003Options{{Plugin: "sh"}, {PluginOpts: "obfs=http"}, {Plugin: "obfs-local", PluginOpts: "obfs=ws"}, {Plugin: "obfs-local", PluginOpts: "obfs=tls;unknown=1"}, {Plugin: "obfs-local", PluginOpts: "obfs=http;obfs-host=bad host"}, {Plugin: "obfs-local", PluginOpts: "obfs=http;obfs-uri=relative"}} {
		if p.prepare("shadowsocks", Transport{}, TLSOptions{}, false) == nil {
			t.Fatal("accepted plugin configuration", p)
		}
	}
	p := SIP003Options{Plugin: "obfs-local", PluginOpts: "obfs=http"}
	if p.prepare("http", Transport{}, TLSOptions{}, false) == nil || p.prepare("shadowsocks", Transport{Type: "ws"}, TLSOptions{}, false) == nil {
		t.Fatal("accepted invalid plugin scope or layering")
	}
}

func FuzzSIP003Options(f *testing.F) {
	f.Add("obfs=http;obfs-host=cdn.example")
	f.Add(`key=a\;b\=c\\d;flag`)
	f.Add("mode=hysteria2;password=transport-secret;host=example.com")
	f.Fuzz(func(t *testing.T, text string) { _, _ = sip003Options(text) })
}
