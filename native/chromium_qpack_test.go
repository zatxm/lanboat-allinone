package native

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestChromiumQPACKRFC9204(t *testing.T) {
	table := chromiumQPACKTable{capacity: 220}
	for _, field := range [][2]string{{":authority", "www.example.com"}, {":path", "/sample/path"}} {
		if err := table.insert(field); err != nil {
			t.Fatal(err)
		}
	}
	wire, _ := hex.DecodeString("03811011")
	required, base, fields, err := qpackBase(wire, table.inserted, 220)
	if err != nil || required != 2 || base != 0 {
		t.Fatal(required, base, err)
	}
	decoded, err := table.decode(fields, base, required)
	if err != nil || !reflect.DeepEqual(decoded, [][2]string{{":authority", "www.example.com"}, {":path", "/sample/path"}}) {
		t.Fatal(decoded, err)
	}
	wire, _ = hex.DecodeString("0000510b2f696e6465782e68746d6c")
	required, base, fields, err = qpackBase(wire, table.inserted, 220)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = table.decode(fields, base, required)
	if err != nil || !reflect.DeepEqual(decoded, [][2]string{{":path", "/index.html"}}) {
		t.Fatal(decoded, err)
	}
	for count := uint64(1); count < 4097; count++ {
		required, err := qpackRequired(count%12+1, count, 220)
		if err != nil || required != count {
			t.Fatalf("wrapped count %d: %d %v", count, required, err)
		}
	}
}

func TestChromiumQPACKEncoderAndEviction(t *testing.T) {
	for _, blocked := range []uint64{0, 2} {
		encoder := chromiumQPACKEncoder{maximum: 220, blocked: blocked, table: chromiumQPACKTable{capacity: 220}}
		fields := [][2]string{{":method", "CONNECT"}, {":authority", "example.com:443"}, {"authorization", "private"}, {"x-profile", "repeat"}}
		wire, instructions := encoder.encode(0, fields)
		if len(instructions) == 0 {
			t.Fatal("dynamic insertions not emitted")
		}
		for _, entry := range encoder.table.entries {
			if entry.field[0] == "authorization" {
				t.Fatal("credential indexed")
			}
		}
		if blocked == 0 && wire[0] != 0 {
			t.Fatal("zero-blocking peer received unacknowledged references")
		}
		if err := encoder.acknowledge(0, encoder.table.inserted); err != nil {
			t.Fatal(err)
		}
		if _, ok := encoder.sections[0]; ok {
			if err := encoder.acknowledge(0x80, 0); err != nil {
				t.Fatal(err)
			}
		}
		wire, _ = encoder.encode(4, fields)
		required, base, body, err := qpackBase(wire, encoder.table.inserted, encoder.maximum)
		if err != nil || required == 0 {
			t.Fatal("acknowledged table was not reused", err)
		}
		got, err := encoder.table.decode(body, base, required)
		if err != nil || !reflect.DeepEqual(got, fields) {
			t.Fatal(got, err)
		}
		if err = encoder.acknowledge(0x80, 4); err != nil {
			t.Fatal(err)
		}
		if err = encoder.acknowledge(0, 1); err == nil {
			t.Fatal("invalid increment accepted")
		}
	}
	table := chromiumQPACKTable{capacity: 40}
	if err := table.insert([2]string{"a", "one"}); err != nil {
		t.Fatal(err)
	}
	if err := table.insert([2]string{"b", "two"}); err != nil {
		t.Fatal(err)
	}
	if _, err := table.at(0); err == nil {
		t.Fatal("evicted entry survived")
	}
	if _, err := table.at(1); err != nil {
		t.Fatal(err)
	}
}

func TestChromiumHTTP3DynamicResponse(t *testing.T) {
	listener := testQUICListener(t)
	q := testQUICDial(t, listener.packet.LocalAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peer, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n, err := newChromiumH3(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	owner := &trustClient{naiveH3Sessions: map[*chromiumH3Session]struct{}{n: {}}}
	go n.peerStreams(owner)
	errorsCh := make(chan error, 8)
	acks := make(chan byte, 16)
	go func() {
		control, err := peer.OpenStream(ctx, true)
		if err == nil {
			err = writeAll(control, []byte{0})
		}
		if err == nil {
			err = h3WriteFrame(control, 4, []byte{1, 0})
		}
		if err != nil {
			errorsCh <- err
			return
		}
		encoder, err := peer.OpenStream(ctx, true)
		if err == nil {
			err = writeAll(encoder, []byte{2})
		}
		if err != nil {
			errorsCh <- err
			return
		}
		for {
			s, err := peer.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func() {
				if s.id&2 != 0 {
					kind, err := readQUICVar(s)
					if err != nil {
						errorsCh <- err
						return
					}
					if kind == 3 {
						var b [1]byte
						for {
							if _, err = io.ReadFull(s, b[:]); err != nil {
								return
							}
							acks <- b[0]
						}
					} else {
						_, _ = io.Copy(io.Discard, s)
					}
					return
				}
				kind, b, err := h3ReadFrame(s)
				if err != nil || kind != 1 {
					errorsCh <- errors.New("missing request headers")
					return
				}
				if _, err = h3Decode(b); err != nil {
					errorsCh <- err
					return
				}
				if err = h3WriteFrame(s, 1, chromiumQPACK([][2]string{{":status", "103"}})); err != nil {
					errorsCh <- err
					return
				}
				block := append([]byte{5, 0}, chromiumQPACK([][2]string{{":status", "200"}})[2:]...)
				block = append(block, 0x80)
				if err = h3WriteFrame(s, 1, block); err != nil {
					errorsCh <- err
					return
				}
				// Header block arrives before its encoder-stream insertions.
				time.Sleep(10 * time.Millisecond)
				instructions, _ := hex.DecodeString("3fbd01c00f7777772e6578616d706c652e636f6d")
				instructions = httpHeaderText(instructions, "x-profile", 5, 0x40)
				instructions = httpHeaderText(instructions, "dynamic", 7, 0)
				instructions = h3Int(instructions, 6, 0x80, 0)
				instructions = httpHeaderText(instructions, "other", 7, 0)
				instructions = append(instructions, 0)
				if err = writeAll(encoder, instructions); err != nil {
					errorsCh <- err
					return
				}
				if err = h3WriteFrame(control, 7, quicVar(nil, 4)); err != nil {
					errorsCh <- err
					return
				}
				if err = h3WriteFrame(s, 0, []byte("dynamic-body")); err != nil {
					errorsCh <- err
					return
				}
				if err = h3WriteFrame(s, 1, []byte{5, 0, 0x80}); err != nil {
					errorsCh <- err
					return
				}
				if err = s.CloseWrite(); err != nil {
					errorsCh <- err
				}
			}()
		}
	}()
	body, headers, err := n.request(ctx, [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "example.com"}, {":path", "/"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	if headers[":status"] != "200" || headers["x-profile"] != "other" {
		t.Fatal(headers)
	}
	got, err := io.ReadAll(body)
	if err != nil || string(got) != "dynamic-body" {
		t.Fatal(string(got), err)
	}
	var received []byte
	acknowledged, sections := byte(0), 0
	for sections < 2 {
		select {
		case b := <-acks:
			received = append(received, b)
			if b == 0x80 {
				acknowledged = 4
				sections++
			} else if b > 0 && b < 0x40 {
				acknowledged += b
				if acknowledged > 4 {
					t.Fatal("QPACK insert count acknowledged twice", received)
				}
			} else {
				t.Fatal("unexpected decoder instruction", b)
			}
		case err := <-errorsCh:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal(ctx.Err(), received)
		}
	}
	if acknowledged != 4 || len(received) > 6 {
		t.Fatal("insert/section/trailer acknowledgements", received)
	}
	until := time.Now().Add(time.Second)
	for {
		n.mu.Lock()
		draining := n.draining
		n.mu.Unlock()
		if draining {
			break
		}
		if time.Now().After(until) {
			t.Fatal("GOAWAY not processed")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err = n.open(ctx); !errors.Is(err, errChromiumH3Draining) {
		t.Fatal("GOAWAY accepted new stream", err)
	}
	if err = body.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-q.done:
	case <-time.After(time.Second):
		t.Fatal("drained HTTP3 connection not closed")
	}
}

func TestChromiumHTTP3BlockedCancellation(t *testing.T) {
	listener := testQUICListener(t)
	q := testQUICDial(t, listener.packet.LocalAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	peer, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	n, err := newChromiumH3(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := q.OpenStream(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err = n.decodeHeaders(ctx, stream, []byte{2, 0, 0x80}, false)
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("blocked headers ignored deadline", err)
	}
	if n.blocked != 0 {
		t.Fatal("blocked stream count leaked")
	}
}

func FuzzChromiumQPACK(f *testing.F) {
	for _, hexValue := range []string{"0000d9", "03811011", "ff00", "020080"} {
		b, _ := hex.DecodeString(hexValue)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 4096 {
			return
		}
		table := chromiumQPACKTable{capacity: 220}
		_ = table.insert([2]string{":status", "200"})
		_ = table.insert([2]string{"x-profile", "test"})
		required, base, fields, err := qpackBase(wire, table.inserted, 220)
		if err == nil && required <= table.inserted {
			_, _ = table.decode(fields, base, required)
		}
	})
}
