package nativecmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zatxm/lanboat-allinone/v26/native"
)

func TestOpenConnectBrowserOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"outbounds":[{"type":"direct","tag":"direct"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"check", "-c", path, "--auth-browser", "browser"}, {"run", "-c", path, "--auth-browser", "browser", "--auth-stdio"}} {
		if err := Execute(context.Background(), args, &bytes.Buffer{}); err == nil {
			t.Fatal("accepted invalid browser flags")
		}
	}
	handler := openConnectBrowser("/not-a-browser")
	for _, form := range []native.OpenConnectAuthForm{
		{},
		{SSO: &native.OpenConnectSSO{Mode: "webview"}},
		{SSO: &native.OpenConnectSSO{Mode: "external"}, Fields: []native.OpenConnectAuthField{{Name: "password", Type: "password"}}},
	} {
		_, err := handler(context.Background(), form)
		var required *native.OpenConnectAuthRequiredError
		if !errors.As(err, &required) {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	form := native.OpenConnectAuthForm{SSO: &native.OpenConnectSSO{Mode: "external", LoginURL: "https://vpn.example/login"}, Fields: []native.OpenConnectAuthField{{Name: "sso-token", Type: "sso"}}}
	if _, err := handler(ctx, form); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := handler(context.Background(), form); err == nil {
		t.Fatal("missing browser executable accepted")
	}
}

func TestOpenConnectSSOStdio(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	handler := openConnectStdio(ctx, strings.NewReader("{\"request_id\":1,\"values\":{}}\n"), &out)
	form := native.OpenConnectAuthForm{SSO: &native.OpenConnectSSO{Mode: "external", LoginURL: "https://vpn.example/login", FinalURL: "https://vpn.example/success"}, Fields: []native.OpenConnectAuthField{{Name: "sso-token", Type: "sso"}}}
	if _, err := handler(ctx, form); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"sso":{"mode":"external"`)) {
		t.Fatal("browser metadata missing")
	}
}

func TestOpenConnectStdio(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	input, write := io.Pipe()
	defer input.Close()
	defer write.Close()
	read, out := io.Pipe()
	defer read.Close()
	defer out.Close()
	handler := openConnectStdio(ctx, input, out)
	done := make(chan error, 1)
	go func() {
		values, e := handler(ctx, native.OpenConnectAuthForm{Endpoint: "vpn", ID: "otp", Fields: []native.OpenConnectAuthField{{Name: "token", Type: "password"}}})
		if e == nil && values["token"] != "654321" {
			e = errors.New("wrong reply")
		}
		done <- e
	}()
	var prompt struct {
		RequestID uint64                     `json:"request_id"`
		Type      string                     `json:"type"`
		Form      native.OpenConnectAuthForm `json:"form"`
	}
	if e := json.NewDecoder(read).Decode(&prompt); e != nil {
		t.Fatal(e)
	}
	if prompt.Type != "openconnect-auth" || prompt.RequestID != 1 || prompt.Form.ID != "otp" {
		t.Fatal(prompt)
	}
	io.WriteString(write, `{"request_id":0,"values":{"token":"stale"}}`+"\n")
	io.WriteString(write, `{"request_id":1,"values":{"token":"654321"}}`+"\n")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestOpenConnectStdioCancellation(t *testing.T) {
	for _, test := range []struct {
		input string
		want  error
	}{{`{"request_id":1,"cancel":true}` + "\n", context.Canceled}, {"", io.EOF}} {
		ctx, cancel := context.WithCancel(context.Background())
		handler := openConnectStdio(ctx, strings.NewReader(test.input), io.Discard)
		_, err := handler(ctx, native.OpenConnectAuthForm{})
		cancel()
		if !errors.Is(err, test.want) {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	handler := openConnectStdio(ctx, reader, io.Discard)
	call, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	defer stop()
	if _, err := handler(call, native.OpenConnectAuthForm{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
