package native

import "time"

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
