package native

import (
	"bytes"
	"testing"
	"time"
)

func TestQUICPTOProbePastCongestionWindow(t *testing.T) {
	now := time.Now()
	_, key, err := quicInitialKeys([]byte("12345678"), false)
	if err != nil {
		t.Fatal(err)
	}
	var packets [][]byte
	c := &quicConn{cid: []byte("abcdefgh"), dcid: []byte("12345678"), cwnd: 2400, inFlight: 3600, srtt: time.Millisecond, retained: 1, wake: make(chan struct{}, 1), send: func(b []byte) error { packets = append(packets, bytes.Clone(b)); return nil }}
	frame := quicFrame{data: []byte{1}, level: 2, reliable: true}
	original := quicSent{at: now.Add(-time.Second), size: 3600, frames: []quicFrame{frame}, eliciting: true}
	c.spaces[2] = quicSpace{write: key, nextPN: 1, sent: map[uint64]quicSent{0: original}}
	c.onPTO(now)
	if c.cwnd != 2400 || c.inFlight != 3600 || len(c.spaces[2].sent) != 1 || c.ptoCount != 1 || c.retained != 2 {
		t.Fatal("PTO falsely declared loss or failed to account probe")
	}
	if err = c.flush(now); err != nil {
		t.Fatal(err)
	}
	if len(packets) != 1 || c.probes[2] != 0 || len(c.spaces[2].sent) != 2 {
		t.Fatal("probe blocked by congestion window", len(packets))
	}
	if c.inFlight <= 3600 {
		t.Fatal("probe missing from bytes-in-flight")
	}
	if deadline := c.lossDeadline(); !deadline.Equal(now.Add(c.pto())) {
		t.Fatal("PTO did not use most recent ack-eliciting send", deadline)
	}
	// Repeated flushes must not send more congestion-exempt data without a PTO.
	c.enqueue(frame)
	if err = c.flush(now); err != nil || len(packets) != 1 {
		t.Fatal("probe budget leaked", err)
	}
}

func TestQUICLossRetransmissionPriority(t *testing.T) {
	first := quicFrame{data: []byte("lost header"), level: 2, reliable: true}
	later := quicFrame{data: []byte("queued payload"), level: 2, reliable: true}
	now := time.Now()
	c := &quicConn{cwnd: 12000, inFlight: 1000, retained: len(first.data) + len(later.data)}
	p := quicSent{at: now.Add(-time.Millisecond), size: 1000, frames: []quicFrame{first}, eliciting: true}
	c.spaces[2] = quicSpace{sent: map[uint64]quicSent{0: p}, queue: []quicFrame{later}}
	c.losePacket(2, 0, p, now)
	if len(c.spaces[2].queue) != 2 || !bytes.Equal(c.spaces[2].queue[0].data, first.data) {
		t.Fatal("lost header delayed behind later payload")
	}
	if c.retained != len(first.data)+len(later.data) || c.inFlight != 0 {
		t.Fatal("retransmission changed retained-byte accounting")
	}
}

func TestQUICPathResponsePrecedesRecoveryData(t *testing.T) {
	for _, recovery := range []string{"PTO", "loss"} {
		t.Run(recovery, func(t *testing.T) {
			now := time.Now()
			_, key, err := quicInitialKeys([]byte("12345678"), false)
			if err != nil {
				t.Fatal(err)
			}
			var packets [][]byte
			c := &quicConn{cid: []byte("abcdefgh"), dcid: []byte("12345678"), cwnd: 2400, inFlight: 3600, srtt: time.Millisecond, wake: make(chan struct{}, 1), send: func(b []byte) error { packets = append(packets, bytes.Clone(b)); return nil }}
			data := quicVar([]byte{0x0a}, 0)
			data = quicVar(data, 1096)
			data = append(data, make([]byte, 1096)...)
			frame := quicFrame{data: data, level: 2, reliable: true}
			original := quicSent{at: now.Add(-time.Second), size: 3600, frames: []quicFrame{frame}, eliciting: true}
			c.spaces[2] = quicSpace{write: key, nextPN: 1, sent: map[uint64]quicSent{0: original}}
			c.retained = len(data)
			c.enqueue(frame)
			token := []byte("response")
			if err = c.handleFrames(2, 0, append([]byte{26}, token...)); err != nil {
				t.Fatal(err)
			}
			if err = c.flush(now); err != nil || len(packets) != 0 {
				t.Fatal("response bypassed congestion", err, len(packets))
			}
			if recovery == "PTO" {
				c.onPTO(now)
			} else {
				c.losePacket(2, 0, original, now)
			}
			if err = c.flush(now); err != nil || len(packets) == 0 {
				t.Fatal("no recovery packet", err)
			}
			header, err := parseQUICHeader(packets[0])
			if err != nil {
				t.Fatal(err)
			}
			plain, _, _, err := openQUICPacket(packets[0], header, key, -1)
			if err != nil || len(plain) < 9 || plain[0] != 27 || !bytes.Equal(plain[1:9], token) {
				t.Fatal("path validation response stalled behind application retransmission", err)
			}
			if len(packets[0]) != 1200 {
				t.Fatal("path validation response not padded", len(packets[0]))
			}
			before := len(packets)
			if recovery == "PTO" {
				if err = c.flush(now); err != nil || len(packets) != before {
					t.Fatal("PTO credit leaked", err)
				}
			}
		})
	}
}
