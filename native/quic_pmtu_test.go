package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func pmtuFixture(t *testing.T, size int) *quicConn {
	t.Helper()
	_, key, err := quicInitialKeys([]byte("12345678"), false)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c := &quicConn{confirmed: true, established: true, pmtu: &quicPMTU{upper: 1472, next: now}, cwnd: 12000, srtt: 10 * time.Millisecond, dcid: []byte("12345678"), send: func([]byte) error { return nil }}
	c.peer.maxUDPPayload = 1472
	c.sendMTU.Store(int64(size))
	for i := range c.spaces {
		c.spaces[i].sent = map[uint64]quicSent{}
	}
	c.spaces[2].write = key
	return c
}

func TestQUICPMTUState(t *testing.T) {
	t.Run("ack-and-peer-limit", func(t *testing.T) {
		c := pmtuFixture(t, 1200)
		c.peer.maxUDPPayload = 1350
		now := time.Now()
		sent := 0
		c.send = func(b []byte) error { sent = len(b); return nil }
		if err := c.servicePMTU(now); err != nil {
			t.Fatal(err)
		}
		if sent != 1350 || !c.pmtu.active || c.inFlight != 1350 {
			t.Fatal(sent, c.inFlight, c.pmtu)
		}
		pn := c.pmtu.pn
		c.acknowledge(2, pn, 0, []quicPNRange{{pn, pn}}, now.Add(time.Millisecond))
		if c.sendMTU.Load() != 1350 || c.inFlight != 0 || c.cwnd != 12000 || c.srtt != 10*time.Millisecond {
			t.Fatal("probe altered congestion/RTT", c.sendMTU.Load(), c.inFlight, c.cwnd, c.srtt)
		}
		c.servicePMTU(now.Add(time.Second))
		if c.pmtu.next.Before(now.Add(9 * time.Minute)) {
			t.Fatal("discovery keeps polling a completed range")
		}
	})
	t.Run("probe-loss-is-not-congestion", func(t *testing.T) {
		c := pmtuFixture(t, 1200)
		for range 3 {
			now := c.pmtu.next
			if err := c.servicePMTU(now); err != nil {
				t.Fatal(err)
			}
			if level, _ := c.probeSpace(); level != -1 {
				t.Fatal("MTU probe armed application PTO")
			}
			if err := c.servicePMTU(c.pmtu.expires); err != nil {
				t.Fatal(err)
			}
		}
		if c.cwnd != 12000 || c.inFlight != 0 || c.retained != 0 || len(c.spaces[2].sent) != 0 || c.pmtu.target >= 1472 {
			t.Fatal(c.pmtu, c.cwnd, c.inFlight)
		}
	})
	t.Run("local-message-too-large", func(t *testing.T) {
		c := pmtuFixture(t, 1200)
		c.send = func([]byte) error { return os.NewSyscallError("sendto", syscall.EMSGSIZE) }
		if err := c.servicePMTU(time.Now()); err != nil {
			t.Fatal(err)
		}
		if c.spaces[2].nextPN != 1 || c.inFlight != 0 || c.pmtu.active || c.pmtu.target >= 1472 {
			t.Fatal(c.pmtu, c.spaces[2].nextPN)
		}
		c.send = func([]byte) error { return io.ErrClosedPipe }
		if err := c.servicePMTU(c.pmtu.next); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
	})
	t.Run("path-reset-and-late-ack", func(t *testing.T) {
		c := pmtuFixture(t, 1400)
		now := time.Now()
		c.servicePMTU(now)
		pn := c.pmtu.pn
		c.resetPMTU(now)
		c.acknowledge(2, pn, 0, []quicPNRange{{pn, pn}}, now.Add(time.Millisecond))
		if c.sendMTU.Load() != 1200 || c.inFlight != 0 || c.pmtu.active {
			t.Fatal("old path raised new path MTU")
		}
		c.sendMTU.Store(1400)
		for range 3 {
			c.lostPMTUData(1300, now)
		}
		if c.sendMTU.Load() != 1200 {
			t.Fatal("black hole retained large MTU")
		}
	})
	t.Run("queued-datagram-after-shrink", func(t *testing.T) {
		c := pmtuFixture(t, 1400)
		c.keepAlive = -1
		c.wake = make(chan struct{}, 1)
		c.enqueue(quicFrame{level: 2, data: make([]byte, 1250)})
		c.enqueue(quicFrame{level: 2, data: []byte{1}, reliable: true})
		c.resetPMTU(time.Now())
		n := 0
		c.send = func(b []byte) error {
			if len(b) > 1200 {
				t.Fatal("oversize after shrink", len(b))
			}
			n++
			return nil
		}
		if err := c.flush(time.Now()); err != nil {
			t.Fatal(err)
		}
		if n != 1 || c.retained != 1 || len(c.spaces[2].queue) != 0 {
			t.Fatal("UDP blocked reliable queue", n, c.retained)
		}
	})
	t.Run("data-message-too-large-retries-reliable-frames", func(t *testing.T) {
		c := pmtuFixture(t, 1400)
		c.wake = make(chan struct{}, 1)
		for _, n := range []int{1000, 240} {
			c.enqueue(quicFrame{level: 2, data: make([]byte, n), reliable: true})
		}
		attempts, delivered := 0, 0
		c.send = func(b []byte) error {
			attempts++
			if len(b) > 1200 {
				return syscall.EMSGSIZE
			}
			delivered++
			return nil
		}
		if err := c.flush(time.Now()); err != nil {
			t.Fatal(err)
		}
		if attempts != 3 || delivered != 2 || c.retained != 1240 || c.spaces[2].nextPN != 3 || c.sendMTU.Load() != 1200 {
			t.Fatal("failed send lost reliable data or reused nonce", attempts, delivered, c.retained, c.spaces[2].nextPN)
		}
		if _, reused := c.spaces[2].sent[0]; reused {
			t.Fatal("failed packet number reused")
		}
	})
	t.Run("disabled", func(t *testing.T) {
		c := pmtuFixture(t, 1400)
		c.pmtu = nil
		c.send = func([]byte) error { t.Fatal("disabled discovery sent probe"); return nil }
		c.servicePMTU(time.Now())
		c.resetPMTU(time.Now())
		if c.sendMTU.Load() != 1400 || !c.pmtuDeadline().IsZero() {
			t.Fatal("disabled discovery changed size")
		}
	})
}

type pmtuTestConn struct {
	*net.UDPConn
	limit        atomic.Int64
	firstInitial atomic.Int64
	probes       atomic.Int64
	localError   bool
}

func (c *pmtuTestConn) Write(b []byte) (int, error) {
	if b[0]&0xf0 == 0xc0 {
		c.firstInitial.CompareAndSwap(0, int64(len(b)))
	}
	if b[0]&0x80 == 0 && len(b) > 1200 {
		c.probes.Add(1)
	}
	if int64(len(b)) > c.limit.Load() {
		if c.localError {
			return 0, os.NewSyscallError("sendto", syscall.EMSGSIZE)
		}
		return len(b), nil
	}
	return c.UDPConn.Write(b)
}
func waitPMTU(t *testing.T, c *quicConn, minSize, maxSize int) {
	t.Helper()
	deadline := time.Now().Add(7 * time.Second)
	for time.Now().Before(deadline) {
		n := int(c.sendMTU.Load())
		if n >= minSize && n <= maxSize {
			return
		}
		select {
		case <-c.done:
			t.Fatal("QUIC closed during discovery", c.err())
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("path size did not converge", c.sendMTU.Load(), minSize, maxSize)
}
func TestQUICPMTUTransfer(t *testing.T) {
	for _, mode := range []string{"drop", "message-too-large", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			o := quicOptions{initial: 1200, packetSize: 1200, discoverMTU: mode != "disabled"}
			l := testQUICListener(t, o)
			raw, err := net.DialUDP("udp", nil, l.packet.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			wire := &pmtuTestConn{UDPConn: raw, localError: mode == "message-too-large"}
			wire.limit.Store(1400)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c, err := dialQUIC(ctx, context.Background(), wire, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"lanboat-quic-test"}}, o)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			s, err := l.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if wire.firstInitial.Load() != 1200 {
				t.Fatal("configured initial not used", wire.firstInitial.Load())
			}
			if mode != "disabled" {
				waitPMTU(t, c, 1384, 1400)
			} else {
				time.Sleep(400 * time.Millisecond)
				if wire.probes.Load() != 0 || c.sendMTU.Load() != 1200 {
					t.Fatal("disabled probe", wire.probes.Load())
				}
			}
			stream, err := c.OpenStream(ctx, false)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			want := bytes.Repeat([]byte("path-mtu-stream"), 10000)
			result := make(chan error, 1)
			go func() {
				peer, e := s.AcceptStream(ctx)
				if e == nil {
					defer peer.Close()
					peer.SetDeadline(time.Now().Add(3 * time.Second))
					got := make([]byte, len(want))
					_, e = io.ReadFull(peer, got)
					if e == nil && !bytes.Equal(want, got) {
						e = fmt.Errorf("stream changed")
					}
				}
				result <- e
			}()
			stream.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if _, err = stream.Write(want); err != nil {
				t.Fatal(err)
			}
			if err = <-result; err != nil {
				t.Fatal(err)
			}
			data := bytes.Repeat([]byte{0x73}, c.datagramLimit())
			if err = c.SendDatagram(ctx, data); err != nil {
				t.Fatal(err)
			}
			got, err := s.ReceiveDatagram(ctx)
			if err != nil || !bytes.Equal(data, got) {
				t.Fatal("MTU datagram", len(got), err)
			}
			if mode != "disabled" {
				wire.limit.Store(1200)
				for range 3 {
					if err = c.SendDatagram(ctx, data); err != nil && !errors.Is(err, errQUICDatagramSize) {
						t.Fatal(err)
					}
				}
				// Small packets still reach the peer and expose the preceding
				// large-packet losses to ACK-based black-hole recovery.
				for range 3 {
					if err = c.SendDatagram(ctx, []byte("small")); err != nil {
						t.Fatal(err)
					}
					if _, err = s.ReceiveDatagram(ctx); err != nil {
						t.Fatal(err)
					}
				}
				waitPMTU(t, c, 1200, 1200)
				data = bytes.Repeat([]byte{0x52}, c.datagramLimit())
				if err = c.SendDatagram(ctx, data); err != nil {
					t.Fatal(err)
				}
				got, err = s.ReceiveDatagram(ctx)
				if err != nil || !bytes.Equal(got, data) {
					t.Fatal("datagram failed after path shrink", len(got), err)
				}
			}
		})
	}
}
