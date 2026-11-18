package native

import (
	"errors"
	"time"
)

func (o quicOptions) defaults() quicOptions {
	if o.idleTimeout == 0 {
		o.idleTimeout = 120 * time.Second
	}
	if o.streamWindow == 0 {
		o.streamWindow = quicStreamWindow
	}
	if o.connectionWindow == 0 {
		o.connectionWindow = quicConnWindow
	}
	if o.streams == 0 {
		o.streams = 128
	}
	if o.receiveMTU == 0 {
		o.receiveMTU = 1472
	}
	return o
}

func (c *quicConn) receiveWindows() (uint64, uint64) {
	connection, stream := c.connectionWindow, c.streamWindow
	if connection == 0 {
		connection = quicConnWindow
	}
	if stream == 0 {
		stream = quicStreamWindow
	}
	return connection, stream
}

func (c *quicConn) idleDuration() time.Duration {
	idle := c.idleTimeout
	if idle == 0 {
		idle = 120 * time.Second
	}
	if c.peer.idle > 0 {
		idle = min(idle, c.peer.idle)
	}
	return idle
}

func (c *quicConn) keepAliveDuration() time.Duration {
	return min(c.keepAlive, c.idleDuration()/2)
}

// QUICReceiveWindows sets how much unread data QUIC peers may send before the
// local reader consumes it. Zero keeps the defaults (1MiB per stream, 4MiB per
// connection). Larger windows raise single-connection throughput on
// high-latency paths; they only cost memory while a reader falls behind,
// bounded per connection by connection_receive_window.
type QUICReceiveWindows struct {
	StreamReceiveWindow     masqueWindow `json:"stream_receive_window,omitempty"`
	ConnectionReceiveWindow masqueWindow `json:"connection_receive_window,omitempty"`
}

func (w QUICReceiveWindows) validate() error {
	stream, connection := int(w.StreamReceiveWindow), int(w.ConnectionReceiveWindow)
	if stream != 0 && (stream < 16<<10 || stream > 64<<20) {
		return errors.New("stream_receive_window must be0 or16KiB-64MiB")
	}
	if connection != 0 && (connection < 64<<10 || connection > 64<<20) {
		return errors.New("connection_receive_window must be0 or64KiB-64MiB")
	}
	if stream == 0 {
		stream = quicStreamWindow
	}
	if connection == 0 {
		connection = quicConnWindow
	}
	if stream > connection {
		return errors.New("stream_receive_window cannot exceed connection_receive_window")
	}
	return nil
}

func (w QUICReceiveWindows) apply(o quicOptions) quicOptions {
	if w.StreamReceiveWindow != 0 {
		o.streamWindow = uint64(w.StreamReceiveWindow)
	}
	if w.ConnectionReceiveWindow != 0 {
		o.connectionWindow = uint64(w.ConnectionReceiveWindow)
	}
	return o
}
