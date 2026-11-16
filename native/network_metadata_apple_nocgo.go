//go:build darwin && !cgo

package native

import (
	"context"
	"encoding/json"
)

func appleNetworkMetadata(ctx context.Context, m *Metadata) {
	if m.NetworkType != "wifi" {
		return
	}
	script := `ObjC.import('CoreWLAN'); var w=$.CWWiFiClient.sharedWiFiClient.interface; JSON.stringify({ssid:ObjC.unwrap(w.ssid)||'',bssid:ObjC.unwrap(w.bssid)||''})`
	data, err := metadataCommand(ctx, "/usr/bin/osascript", "-l", "JavaScript", "-e", script)
	if err != nil {
		return
	}
	var result struct{ SSID, BSSID string }
	if json.Unmarshal([]byte(data), &result) == nil {
		if result.SSID != "" {
			m.WiFiSSID = result.SSID
		}
		m.WiFiBSSID = result.BSSID
	}
}
