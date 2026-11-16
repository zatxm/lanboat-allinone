package native

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func jsonTestConfig() Config {
	return Config{
		Outbounds: []Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: "vmess", Tag: "日本<&>", Server: "example.com", ServerPort: 443, UUID: "12345678-1234-5678-1234-567812345678", TLS: TLSOptions{Enabled: true, ServerName: "example.com", ALPN: []string{"h2", "http/1.1"}}, Transport: Transport{Type: "ws", Path: "/proxy", Headers: map[string]headerValues{"Host": {"example.com"}}}},
			{Type: "hysteria2", Tag: "hy2", Server: "example.com", ServerPort: 443, Password: "secret", TLS: TLSOptions{Enabled: true}, Obfs: Obfuscation(`{"type":"salamander","password":"obfs-key"}`)},
		},
		DNS:   DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"example.com": {"192.0.2.1", "2001:db8::1"}}}}, Final: "hosts"},
		Route: Route{Final: "direct", Rules: []Rule{{DomainSuffix: []string{"example.com"}, Outbound: "direct"}}},
	}
}

func TestJSONConfigurationCompatibility(t *testing.T) {
	cfg := jsonTestConfig()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Outbounds[0].Transport.Type != "" || parsed.Outbounds[1].Transport.Headers["Host"][0] != "example.com" || parsed.Outbounds[2].Obfs != cfg.Outbounds[2].Obfs {
		t.Fatal("custom fields changed during configuration round trip")
	}
	// omitzero must omit unused transport/multiplex, while preserving real values.
	var node map[string]json.RawMessage
	b, _ := json.Marshal(cfg.Outbounds[0])
	if err := json.Unmarshal(b, &node); err != nil || node["transport"] != nil || node["multiplex"] != nil {
		t.Fatal("empty transport or multiplex emitted", string(b), err)
	}
}

func TestJSONStrictConfiguration(t *testing.T) {
	for _, raw := range []string{
		`{"outbounds":{"type":"direct","tag":"d","unknown":1}}`,
		`{"outbounds":{"type":"direct","tag":"d","tls":{"enabled":false,"unknown":1}}}`,
		`{"dns":{"servers":{"type":"hosts","tag":"h","unknown":1}}}`,
		`{"route":{"rules":{"domain":"example.com","outbound":"direct","unknown":1}}}`,
		`{"outbounds":{"type":"direct","server_port":65536}}`,
		`{"outbounds":{"type":"direct","server_port":-1}}`,
		`{"outbounds":{"type":"direct","server_port":1.5}}`,
		`{}null`, `{} {}`, `{} false`, `{"route":`, `{"outbounds":[}`, `[]`, `null`,
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	var options struct {
		ID     int64             `json:"id"`
		Values []uint64          `json:"values"`
		Raw    json.RawMessage   `json:"raw"`
		Fields map[string]string `json:"fields"`
	}
	raw := []byte(`{"id":9007199254740993,"values":18446744073709551615,"raw":{"timestamp":9007199254740993},"fields":{"name":"中文<&>"}}`)
	if err := decodeOptions(raw, &options); err != nil {
		t.Fatal(err)
	}
	if options.ID != 9007199254740993 || !reflect.DeepEqual(options.Values, []uint64{^uint64(0)}) || !bytes.Contains(options.Raw, []byte("9007199254740993")) {
		t.Fatal("numeric precision or scalar-list normalization changed", options)
	}
}

func FuzzJSONOptions(f *testing.F) {
	for _, seed := range []string{`{}`, `{"id":9007199254740993,"ports":65535}`, `{"id":-1,"ports":[1,65535],"raw":{"x":[null,true,"中文"]}}`, `{"ports":-1}`, `{} {}`, `{"id":1,"unknown":true}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 8192 {
			return
		}
		type options struct {
			ID    int64           `json:"id"`
			Ports []uint16        `json:"ports"`
			Raw   json.RawMessage `json:"raw"`
		}
		var value options
		if err := decodeOptions(raw, &value); err != nil {
			return
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var again options
		if err := json.Unmarshal(encoded, &again); err != nil {
			t.Fatalf("accepted options did not round trip: %s: %v", encoded, err)
		}
		canonical, err := json.Marshal(again)
		if err != nil || !bytes.Equal(encoded, canonical) {
			t.Fatalf("option JSON changed on round trip: %s -> %s: %v", encoded, canonical, err)
		}
	})
}

func BenchmarkJSONConfig(b *testing.B) {
	cfg := jsonTestConfig()
	raw, err := json.Marshal(cfg)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("encode", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(raw)))
		for b.Loop() {
			if _, err := json.Marshal(&cfg); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("decode", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(raw)))
		for b.Loop() {
			var cfg Config
			if err := json.Unmarshal(raw, &cfg); err != nil {
				b.Fatal(err)
			}
		}
	})
}
