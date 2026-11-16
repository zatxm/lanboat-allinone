package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration/testcontrol"
)

// Official testcontrol authenticates Noise, the node/machine binding and the
// authorized certificate domain before publishing a real Pebble DNS01 proof.
func certificateOracle() {
	var domains []string
	must(json.Unmarshal([]byte(os.Getenv("LANBOAT_TS_CERTIFICATE_DOMAINS")), &domains))
	control := &testcontrol.Server{
		RequireAuthKey: "test-only-auth", AllNodesSameUser: true,
		MagicDNSDomain: "test.ts.net", DNSConfig: &tailcfg.DNSConfig{CertDomains: domains},
		Logf: func(string, ...any) {},
	}
	callback := os.Getenv("LANBOAT_TS_CERTIFICATE_CALLBACK")
	client := &http.Client{Timeout: 5 * time.Second}
	control.OnSetDNS = func(req *tailcfg.SetDNSRequest) error {
		data, err := json.Marshal(req)
		if err != nil {
			return err
		}
		resp, err := client.Post(callback, "application/json", bytes.NewReader(data))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusOK {
			return errors.New("test DNS publication refused")
		}
		return nil
	}
	cs := httptest.NewServer(control)
	control.HTTPTestServer = cs
	defer cs.Close()
	json.NewEncoder(os.Stdout).Encode(map[string]string{"control_url": cs.URL})
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var req struct {
			Op, Hostname string
			DNS          *tailcfg.DNSConfig
		}
		must(json.Unmarshal(scanner.Bytes(), &req))
		ok := false
		if req.Op == "dns" {
			for _, node := range control.AllNodes() {
				if req.Hostname == "" || node.Hostinfo.Hostname() == req.Hostname {
					ok = control.AddRawMapResponse(node.Key, &tailcfg.MapResponse{DNSConfig: req.DNS}) || ok
				}
			}
		}
		fmt.Fprintf(os.Stdout, "{\"ok\":%v}\n", ok)
	}
}
