package native

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type masqueConnectionOptions struct {
	InitialPacketSize       int          `json:"initial_packet_size,omitempty"`
	DisablePathMTUDiscovery bool         `json:"disable_path_mtu_discovery,omitempty"`
	IdleTimeout             string       `json:"idle_timeout,omitempty"`
	KeepAlivePeriod         string       `json:"keep_alive_period,omitempty"`
	StreamReceiveWindow     masqueWindow `json:"stream_receive_window,omitempty"`
	ConnectionReceiveWindow masqueWindow `json:"connection_receive_window,omitempty"`
	MaxConcurrentStreams    int          `json:"max_concurrent_streams,omitempty"`
}

type masqueWindow int

func (n *masqueWindow) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var text string
		if err := json.Unmarshal(b, &text); err != nil {
			return err
		}
		value, err := masqueWindowSize(text)
		*n = masqueWindow(value)
		return err
	}
	var value int
	if err := json.Unmarshal(b, &value); err != nil {
		return err
	}
	if value < 0 || value > 64<<20 {
		return errors.New("receive window must be0-64MiB")
	}
	*n = masqueWindow(value)
	return nil
}

type masqueConnectionSettings struct {
	initial                  int
	disablePMTU              bool
	idle, keepAlive          time.Duration
	streamWindow, connWindow int
	streams                  int
}

func (o masqueConnectionOptions) settings() (*masqueConnectionSettings, error) {
	if o == (masqueConnectionOptions{}) {
		return nil, nil
	}
	s := &masqueConnectionSettings{idle: -1, keepAlive: -1}
	if o.InitialPacketSize != 0 && (o.InitialPacketSize < 1200 || o.InitialPacketSize > 1472) {
		return nil, errors.New("MASQUE initial_packet_size must be0 or1200-1472")
	}
	s.initial, s.disablePMTU = o.InitialPacketSize, o.DisablePathMTUDiscovery
	for _, v := range []struct {
		name, raw string
		value     *time.Duration
	}{{"idle_timeout", o.IdleTimeout, &s.idle}, {"keep_alive_period", o.KeepAlivePeriod, &s.keepAlive}} {
		if v.raw == "" {
			continue
		}
		d, err := time.ParseDuration(v.raw)
		if err != nil || d < 0 || d > 24*time.Hour || d > 0 && d < time.Millisecond {
			return nil, fmt.Errorf("MASQUE %s must be0 or1ms-24h", v.name)
		}
		*v.value = d
	}
	for _, v := range []struct {
		name    string
		raw     masqueWindow
		value   *int
		minimum int
	}{{"stream_receive_window", o.StreamReceiveWindow, &s.streamWindow, 1}, {"connection_receive_window", o.ConnectionReceiveWindow, &s.connWindow, 65535}} {
		if v.raw == 0 {
			continue
		}
		n := int(v.raw)
		if n < v.minimum || n > 64<<20 {
			return nil, fmt.Errorf("MASQUE %s must be%d bytes to64MiB", v.name, v.minimum)
		}
		*v.value = n
	}
	if o.MaxConcurrentStreams < 0 || o.MaxConcurrentStreams > 128 {
		return nil, errors.New("MASQUE max_concurrent_streams must be0-128")
	}
	s.streams = o.MaxConcurrentStreams
	return s, nil
}

func masqueWindowSize(raw string) (int, error) {
	value := strings.ToUpper(strings.TrimSpace(raw))
	if value == "" {
		return 0, nil
	}
	multiplier := float64(1)
	for _, unit := range []struct {
		name string
		size float64
	}{{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30}, {"KB", 1 << 10}, {"MB", 1 << 20}, {"GB", 1 << 30}, {"B", 1}} {
		if strings.HasSuffix(value, unit.name) {
			value = strings.TrimSpace(strings.TrimSuffix(value, unit.name))
			multiplier = unit.size
			break
		}
	}
	n, err := strconv.ParseFloat(value, 64)
	n *= multiplier
	if err != nil || !(n >= 0 && n <= 64<<20) || n != float64(int(n)) {
		return 0, errors.New("invalid receive window size")
	}
	return int(n), nil
}

func (s *masqueConnectionSettings) http2(c *http.HTTP2Config) {
	if s == nil {
		return
	}
	if s.streamWindow != 0 {
		c.MaxReceiveBufferPerStream = s.streamWindow
	}
	if s.connWindow != 0 {
		c.MaxReceiveBufferPerConnection = s.connWindow
	}
	if s.streams != 0 {
		c.MaxConcurrentStreams = s.streams
	}
	if s.keepAlive >= 0 {
		c.SendPingTimeout = s.keepAlive
	}
}

func (s *masqueConnectionSettings) quic() quicOptions {
	o := quicOptions{initial: 1400, packetSize: 1400, discoverMTU: true}
	if s == nil {
		return o
	}
	if s.initial != 0 {
		o.initial = s.initial
		o.packetSize = s.initial
	}
	o.discoverMTU = !s.disablePMTU
	o.streamWindow, o.connectionWindow, o.streams = uint64(s.streamWindow), uint64(s.connWindow), uint64(s.streams)
	if s.idle > 0 {
		o.idleTimeout = s.idle
	}
	if s.keepAlive >= 0 {
		o.keepAlive = s.keepAlive
		if s.keepAlive == 0 {
			o.keepAlive = -1
		}
	}
	return o
}
