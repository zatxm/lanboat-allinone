package allinone

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

func TestIndependentPublicAPI(t *testing.T) {
	raw := []byte(`{"log":{"disabled":true},"inbounds":[{"type":"mixed","tag":"local","listen":"127.0.0.1","listen_port":0}]}`)
	if err := Check(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	r, err := NewWithLogger(context.Background(), raw, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	handler := OpenConnectAuthHandler(func(ctx context.Context, form OpenConnectAuthForm) (map[string]string, error) { return nil, ctx.Err() })
	r.SetOpenConnectAuthHandler(handler)
	if err := r.AuthenticateOpenConnect(WithOpenConnectAuth(context.Background(), handler), "missing"); err == nil {
		t.Fatal("unknown OpenConnect endpoint accepted")
	}
	r.SetOpenConnectAuthHandler(nil)
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	if r.Address("local") == "" {
		t.Fatal("public runtime did not start an independent listener")
	}
	if err := Check(context.Background(), []byte(`{"inbounds":[{"type":"hysteria2"}]}`)); err == nil {
		t.Fatal("public API silently fell back to the legacy engine")
	}
}
