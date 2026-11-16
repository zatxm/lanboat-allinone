package nativecmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zatxm/lanboat-allinone/native"
)

func TestOpenConnectBrowserExecutable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "browser with spaces")
	result := filepath.Join(dir, "args")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '%s\\n' \"$#\" \"$1\" > '"+result+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	login := "https://vpn.example/login?state=a&not-a-command=$(false)"
	form := native.OpenConnectAuthForm{SSO: &native.OpenConnectSSO{Mode: "external", LoginURL: login}, Fields: []native.OpenConnectAuthField{{Type: "sso", Name: "sso-token"}}}
	if _, err := openConnectBrowser(path)(context.Background(), form); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(result)
		if err == nil && string(b) == "1\n"+login+"\n" {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("browser URL was not passed as one literal argument")
}
