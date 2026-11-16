package native

import (
	"bytes"
	"context"
	"crypto/hmac"
	"errors"
	"slices"
	"time"
)

// Bind each new handshake to both Finished values from the previous one.
func (d *ocDTLS) verifyRenegotiation(ext ocDTLSExtensionFlags, suites []uint16) error {
	if d.previous == nil {
		if len(ext.renegotiation) != 0 {
			return errors.New("nonempty initial DTLS renegotiation binding")
		}
		d.secureRenegotiation = ext.renegotiation != nil || !d.client && slices.Contains(suites, 0x00ff)
		return nil
	}
	want := bytes.Clone(d.previous.clientVerify[:])
	if d.client {
		want = append(want, d.previous.serverVerify[:]...)
	}
	if !hmac.Equal(ext.renegotiation, want) || slices.Contains(suites, 0x00ff) || ext.ems != d.previous.ems {
		return errors.New("DTLS secure renegotiation binding or EMS changed")
	}
	d.secureRenegotiation = true
	return nil
}

// The receive worker owns the handshake; writers wait for the new Finished.
func (d *ocDTLS) renegotiate(ctx context.Context, first []byte) (err error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if d.v13 != nil || !d.ready.Load() || !d.secureRenegotiation || d.secret == nil || d.writeEpoch == 65535 {
		return errors.New("DTLS secure renegotiation unavailable")
	}
	stop := context.AfterFunc(ctx, func() { d.conn.Close() })
	defer stop()
	next := &ocDTLS{conn: d.conn, client: d.client, appID: d.appID, psk: bytes.Clone(d.secret[:]), secret: d.secret, suites: d.suites, previous: d, baseEpoch: d.writeEpoch, writeEpoch: d.writeEpoch, pending: d.pending, queued: d.queued, queuedBytes: d.queuedBytes}
	d.pending = nil
	defer func() {
		if err != nil {
			d.ready.Store(false)
			clear(d.secret[:])
			d.conn.Close()
		}
	}()
	if err = next.handshakeFrom(ctx, first); err != nil {
		if cause := ctx.Err(); cause != nil {
			return cause
		}
		return err
	}
	d.clientRandom, d.serverRandom = next.clientRandom, next.serverRandom
	d.suite, d.ems, d.etm, d.ccs = next.suite, next.ems, next.etm, next.ccs
	d.newHash = next.newHash
	d.readKey, d.writeKey, d.cbc = next.readKey, next.writeKey, next.cbc
	d.readIV, d.writeIV = next.readIV, next.writeIV
	d.failures, d.baseEpoch = next.failures, next.baseEpoch
	d.writeEpoch, d.writeSeq = next.writeEpoch, next.writeSeq
	d.window = next.window
	d.sendNext, d.recvNext, d.stage = next.sendNext, next.recvNext, next.stage
	d.clientVerify, d.serverVerify = next.clientVerify, next.serverVerify
	d.pending = bytes.Clone(next.pending)
	d.plain, d.writeBuffer = next.plain, next.writeBuffer
	d.flight, d.peerFinished, d.lastFlight = next.flight, next.peerFinished, next.lastFlight
	d.queued, d.queuedBytes = next.queued, next.queuedBytes
	d.lastReceive.Store(time.Now().UnixNano())
	d.generation.Add(1)
	if !d.readDeadline.IsZero() {
		_ = d.conn.SetReadDeadline(d.readDeadline)
	}
	return nil
}
