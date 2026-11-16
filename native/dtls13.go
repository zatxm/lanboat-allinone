package native

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"time"
)

type dtls13Number struct{ epoch, seq uint64 }
type dtls13Flight struct {
	epoch   uint64
	message []byte
	records []dtls13Number
}

type dtls13 struct {
	owner                                  *ocDTLS
	identity                               []byte
	suite                                  stCipherSuite
	offered                                []stCipherSuite
	private                                *ecdh.PrivateKey
	random                                 [32]byte
	transcript, master, clientHS, serverHS []byte
	readKeys                               map[uint64]*dtls13Epoch
	writeKeys                              map[uint64]*dtls13Epoch
	readEpoch, writeEpoch                  uint64
	plainSequence                          uint64
	fragments                              map[uint16]*ocDTLSFragment
	fragmentEpoch                          map[uint16]uint64
	sendNext, recvNext                     uint16
	stage                                  int
	retried                                bool
	flight                                 []dtls13Flight // Protected with owner.writeMu, including its timer.
	flightTimer                            *time.Timer
	lastFlight                             time.Time
	retries                                int
	updatePending, updateRequested         bool
	pending                                []byte
	buffer                                 [18432]byte
	failures                               uint32
}

func (d *dtls13) init(owner *ocDTLS) {
	d.owner = owner
	d.readKeys = map[uint64]*dtls13Epoch{}
	d.writeKeys = map[uint64]*dtls13Epoch{}
	d.fragments = map[uint16]*ocDTLSFragment{}
	d.fragmentEpoch = map[uint16]uint64{}
}

func (d *dtls13) writeRecord(epoch uint64, kind byte, body []byte) (dtls13Number, error) {
	id := dtls13Number{epoch: epoch}
	var wire []byte
	var err error
	if epoch == 0 {
		id.seq = d.plainSequence
		if d.plainSequence >= 1<<48 {
			return id, errors.New("DTLS1.3 plaintext sequence limit")
		}
		wire = append(ocDTLSRecordHeader(kind, 0, d.plainSequence, len(body)), body...)
		d.plainSequence++
	} else {
		k := d.writeKeys[epoch]
		if k == nil {
			return id, errors.New("missing DTLS1.3 write keys")
		}
		id.seq = k.sequence
		wire, err = k.seal(kind, body)
	}
	if err == nil {
		err = dtls13Write(d.owner.conn, wire)
	}
	return id, err
}

func (d *dtls13) clearFlight() {
	if d.flightTimer != nil {
		d.flightTimer.Stop()
		d.flightTimer = nil
	}
	d.flight = nil
	d.retries = 0
}

func (d *dtls13) transmit() error {
	d.lastFlight = time.Now()
	for i := range d.flight {
		f := &d.flight[i]
		id, err := d.writeRecord(f.epoch, 22, f.message)
		if err != nil {
			return err
		}
		if len(f.records) >= 16 {
			return errors.New("DTLS1.3 retransmission limit")
		}
		f.records = append(f.records, id)
	}
	return nil
}

func (d *dtls13) queueMessage(epoch uint64, kind byte, body []byte) {
	message := ocDTLSHandshakeMessage(kind, d.sendNext, body)
	d.sendNext++
	// Keep every record below the IPv6 minimum MTU, even for a large PSK identity.
	for offset := 0; offset < len(body) || offset == 0; {
		n := min(1100, len(body)-offset)
		fragment := bytes.Clone(message[:12])
		putUint24(fragment[6:9], uint32(offset))
		putUint24(fragment[9:12], uint32(n))
		fragment = append(fragment, body[offset:offset+n]...)
		d.flight = append(d.flight, dtls13Flight{epoch: epoch, message: fragment})
		offset += n
		if n == 0 {
			break
		}
	}
}

func (d *dtls13) armFlight() {
	if len(d.flight) == 0 || !d.owner.ready.Load() {
		return
	}
	delay := min(time.Second<<min(d.retries, 6), 60*time.Second)
	d.flightTimer = time.AfterFunc(delay, func() {
		d.owner.writeMu.Lock()
		defer d.owner.writeMu.Unlock()
		if !d.owner.ready.Load() || len(d.flight) == 0 {
			d.clearFlight()
			return
		}
		d.retries++
		if d.retries > 8 || d.transmit() != nil {
			d.clearFlight()
			d.owner.ready.Store(false)
			d.owner.conn.Close()
			return
		}
		d.armFlight()
	})
}

func (d *dtls13) acknowledge(id dtls13Number) error {
	if id.epoch == 0 {
		return nil
	}
	body := binary.BigEndian.AppendUint16(nil, 16)
	body = binary.BigEndian.AppendUint64(body, id.epoch)
	body = binary.BigEndian.AppendUint64(body, id.seq)
	d.owner.writeMu.Lock()
	defer d.owner.writeMu.Unlock()
	_, err := d.writeRecord(d.writeEpoch, 26, body)
	return err
}

func (d *dtls13) ack(body []byte) error {
	if len(body) < 2 || int(binary.BigEndian.Uint16(body)) != len(body)-2 || (len(body)-2)%16 != 0 || len(body) > 2+32*16 {
		return errors.New("invalid DTLS1.3 ACK")
	}
	d.owner.writeMu.Lock()
	defer d.owner.writeMu.Unlock()
	for body = body[2:]; len(body) > 0; body = body[16:] {
		id := dtls13Number{binary.BigEndian.Uint64(body), binary.BigEndian.Uint64(body[8:])}
		d.flight = slices.DeleteFunc(d.flight, func(f dtls13Flight) bool { return f.epoch != 0 && slices.Contains(f.records, id) })
	}
	if len(d.flight) == 0 {
		d.clearFlight()
		if d.owner.ready.Load() {
			if old := d.writeKeys[2]; old != nil {
				clear(old.key.secret)
				delete(d.writeKeys, 2)
			}
		}
		if d.updatePending {
			current := d.writeKeys[d.writeEpoch]
			secret := dtls13Expand(d.suite, current.key.secret, "traffic upd", nil, d.suite.hash.Size())
			next, err := newDTLS13Epoch(d.suite, secret, d.writeEpoch+1)
			clear(secret)
			if err != nil {
				return err
			}
			clear(current.key.secret)
			delete(d.writeKeys, d.writeEpoch)
			d.writeEpoch++
			d.writeKeys[d.writeEpoch] = next
			d.updatePending = false
		}
		if d.updateRequested {
			d.updateRequested = false
			return d.keyUpdateLocked(false)
		}
	}
	return nil
}

func (d *dtls13) keyUpdateLocked(request bool) error {
	if d.writeEpoch < 3 || d.writeEpoch >= (1<<48)-1 {
		return errors.New("DTLS1.3 key update epoch limit")
	}
	if d.updatePending || len(d.flight) > 0 {
		d.updateRequested = true
		return nil
	}
	flag := byte(0)
	if request {
		flag = 1
	}
	d.queueMessage(d.writeEpoch, 24, []byte{flag})
	d.updatePending = true
	if err := d.transmit(); err != nil {
		return err
	}
	d.armFlight()
	return nil
}

func (d *dtls13) open(wire []byte) (byte, []byte, dtls13Number, bool, bool) {
	if wire[0]&0xe0 != 0x20 {
		if d.owner.ready.Load() || wire[0] != 22 && wire[0] != 21 {
			return 0, nil, dtls13Number{}, false, false
		}
		return wire[0], wire[13:], dtls13Number{0, binary.BigEndian.Uint64(wire[3:11]) & ((1 << 48) - 1)}, false, true
	}
	for epoch, k := range d.readKeys {
		if byte(epoch&3) != wire[0]&3 {
			continue
		}
		kind, data, seq, duplicate, ok := k.open(wire)
		if !ok {
			d.failures++
			return 0, nil, dtls13Number{}, false, false
		}
		if epoch == d.readEpoch && epoch > 3 {
			for old, key := range d.readKeys {
				if old < epoch {
					clear(key.key.secret)
					delete(d.readKeys, old)
				}
			}
		}
		return kind, data, dtls13Number{epoch, seq}, duplicate, true
	}
	return 0, nil, dtls13Number{}, false, false
}

func (d *dtls13) handshake(ctx context.Context) (err error) {
	defer clear(d.owner.psk)
	defer func() {
		clear(d.master)
		clear(d.clientHS)
		clear(d.serverHS)
		d.master, d.clientHS, d.serverHS, d.transcript = nil, nil, nil, nil
		d.private = nil
		if err != nil {
			d.owner.writeMu.Lock()
			d.clearFlight()
			d.owner.writeMu.Unlock()
		} else {
			d.owner.writeMu.Lock()
			if len(d.flight) == 0 {
				if old := d.writeKeys[2]; old != nil {
					clear(old.key.secret)
					delete(d.writeKeys, 2)
				}
			}
			d.owner.writeMu.Unlock()
		}
	}()
	if len(d.owner.psk) != 32 || len(d.identity) == 0 || len(d.identity) > 256 || len(d.owner.suites) == 0 {
		return errors.New("invalid DTLS1.3 PSK binding")
	}
	stop := context.AfterFunc(ctx, func() { d.owner.conn.SetReadDeadline(time.Now()) })
	defer stop()
	if d.owner.client {
		body, e := d.clientHello(nil)
		if e != nil {
			return e
		}
		d.transcript = stMessage(1, body)
		d.queueMessage(0, 1, body)
		if e = d.transmit(); e != nil {
			return e
		}
	}
	retry := time.Second
	nextRetry := time.Now().Add(retry)
	for !d.owner.ready.Load() {
		if err = ctx.Err(); err != nil {
			return err
		}
		end := nextRetry
		if limit, ok := ctx.Deadline(); ok && limit.Before(end) {
			end = limit
		}
		d.owner.conn.SetReadDeadline(end)
		wire, e := d.nextRecord()
		if e != nil {
			if os.IsTimeout(e) && ctx.Err() == nil {
				if !time.Now().Before(nextRetry) {
					d.owner.writeMu.Lock()
					e = d.transmit()
					d.owner.writeMu.Unlock()
					if e != nil {
						return e
					}
					retry = min(retry*2, 60*time.Second)
					nextRetry = time.Now().Add(retry)
				}
				continue
			}
			return e
		}
		kind, body, id, duplicate, ok := d.open(wire)
		if !ok {
			if d.failures >= 1<<16 {
				return errors.New("DTLS1.3 authentication failure limit")
			}
			continue
		}
		if id.epoch == 0 && d.stage > 1 {
			continue
		}
		switch kind {
		case 21:
			return errors.New("DTLS1.3 peer rejected handshake")
		case 26:
			if e = d.ack(body); e != nil {
				return e
			}
		case 23:
			if id.epoch >= 3 {
				continue
			} // UDP may deliver application data before the peer's Finished.
			return errors.New("DTLS1.3 early data was not negotiated")
		case 22:
			if !duplicate {
				if e = d.handshakes(body, id.epoch); e != nil {
					return e
				}
			}
			if e = d.acknowledge(id); e != nil {
				return e
			}
		default:
			return errors.New("DTLS1.3 application data before Finished")
		}
	}
	d.owner.suite = d.suite.id
	d.owner.lastReceive.Store(time.Now().UnixNano())
	d.owner.conn.SetReadDeadline(time.Time{})
	d.owner.writeMu.Lock()
	d.armFlight()
	d.owner.writeMu.Unlock()
	return nil
}

func (d *dtls13) handshakes(b []byte, epoch uint64) error {
	for len(b) > 0 {
		if len(b) < 12 {
			return errors.New("short DTLS1.3 handshake")
		}
		kind, seq := b[0], binary.BigEndian.Uint16(b[4:])
		size, offset, n := int(readUint24(b[1:])), int(readUint24(b[6:])), int(readUint24(b[9:]))
		if size > 16384 || n > len(b)-12 || offset > size || n > size-offset || kind == 1 && epoch != 0 || kind == 2 && epoch != 0 || kind != 1 && kind != 2 && epoch < 2 {
			return errors.New("invalid DTLS1.3 handshake fragment")
		}
		if seq < d.recvNext {
			d.owner.writeMu.Lock()
			var err error
			if time.Since(d.lastFlight) > 200*time.Millisecond && len(d.flight) > 0 {
				err = d.transmit()
			}
			d.owner.writeMu.Unlock()
			if err != nil {
				return err
			}
			b = b[12+n:]
			continue
		}
		if seq-d.recvNext > 8 || len(d.fragments) >= 8 && d.fragments[seq] == nil {
			return errors.New("DTLS1.3 handshake queue limit")
		}
		f := d.fragments[seq]
		if f == nil {
			f = &ocDTLSFragment{kind: kind, data: make([]byte, size), seen: make([]bool, size)}
			d.fragments[seq] = f
			d.fragmentEpoch[seq] = epoch
		}
		if f.kind != kind || len(f.data) != size || d.fragmentEpoch[seq] != epoch {
			return errors.New("conflicting DTLS1.3 handshake fragments")
		}
		for i, v := range b[12 : 12+n] {
			at := offset + i
			if f.seen[at] && f.data[at] != v {
				return errors.New("conflicting DTLS1.3 fragment overlap")
			}
			if !f.seen[at] {
				f.n++
			}
			f.seen[at] = true
			f.data[at] = v
		}
		b = b[12+n:]
		for f := d.fragments[d.recvNext]; f != nil && f.n == len(f.data); f = d.fragments[d.recvNext] {
			ep := d.fragmentEpoch[d.recvNext]
			delete(d.fragments, d.recvNext)
			delete(d.fragmentEpoch, d.recvNext)
			d.recvNext++
			if err := d.message(f.kind, f.data, ep); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *dtls13) trafficKeys(peer []byte) error {
	pub, err := d.private.Curve().NewPublicKey(peer)
	if err != nil {
		return err
	}
	shared, err := d.private.ECDH(pub)
	if err != nil {
		return err
	}
	defer clear(shared)
	early := d.suite.extract(nil, d.owner.psk)
	derived := dtls13Derive(d.suite, early, "derived", nil)
	hs := d.suite.extract(derived, shared)
	defer clear(early)
	defer clear(derived)
	defer clear(hs)
	d.clientHS = dtls13Derive(d.suite, hs, "c hs traffic", d.transcript)
	d.serverHS = dtls13Derive(d.suite, hs, "s hs traffic", d.transcript)
	derived = dtls13Derive(d.suite, hs, "derived", nil)
	d.master = d.suite.extract(derived, make([]byte, d.suite.hash.Size()))
	clear(derived)
	read, write := d.clientHS, d.serverHS
	if d.owner.client {
		read, write = write, read
	}
	d.readKeys[2], err = newDTLS13Epoch(d.suite, read, 2)
	if err != nil {
		return err
	}
	d.writeKeys[2], err = newDTLS13Epoch(d.suite, write, 2)
	d.writeEpoch, d.readEpoch = 2, 2
	return err
}

func (d *dtls13) applicationKeys() error {
	client := dtls13Derive(d.suite, d.master, "c ap traffic", d.transcript)
	server := dtls13Derive(d.suite, d.master, "s ap traffic", d.transcript)
	defer clear(client)
	defer clear(server)
	read, write := client, server
	if d.owner.client {
		read, write = write, read
	}
	var err error
	d.readKeys[3], err = newDTLS13Epoch(d.suite, read, 3)
	if err != nil {
		return err
	}
	d.writeKeys[3], err = newDTLS13Epoch(d.suite, write, 3)
	d.readEpoch = 3
	return err
}

func (d *dtls13) serverClientHello(body []byte) error {
	h, err := parseDTLS13Hello(body)
	if err != nil {
		return err
	}
	selected := -1
	for _, id := range d.owner.suites {
		if !slices.Contains(h.suites, id) {
			continue
		}
		s, _ := stSuite(id)
		for i, identity := range h.identities {
			if bytes.Equal(identity.identity, d.identity) && len(identity.binder) == s.hash.Size() {
				d.suite = s
				selected = i
				break
			}
		}
		if selected >= 0 {
			break
		}
	}
	if selected < 0 {
		return errors.New("DTLS1.3 has no matching external PSK and cipher")
	}
	msg := stMessage(1, body)
	input := append(bytes.Clone(d.transcript), msg[:4+h.truncated]...)
	if !hmac.Equal(h.identities[selected].binder, dtls13Binder(d.suite, d.owner.psk, input)) {
		return errors.New("DTLS1.3 PSK binder authentication failed")
	}
	d.transcript = append(d.transcript, msg...)
	curve, _ := stCurve(tls.CurveID(h.group))
	d.private, err = curve.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	rand.Read(d.random[:])
	hello := dtls13ServerHello(d.random[:], h.session, d.suite.id, d.private.PublicKey().Bytes(), h.group, selected, nil)
	d.transcript = append(d.transcript, stMessage(2, hello)...)
	if err = d.trafficKeys(h.share); err != nil {
		return err
	}
	d.owner.writeMu.Lock()
	defer d.owner.writeMu.Unlock()
	d.clearFlight()
	d.queueMessage(0, 2, hello)
	ee := []byte{0, 0}
	d.queueMessage(2, 8, ee)
	d.transcript = append(d.transcript, stMessage(8, ee)...)
	finished := dtls13Finished(d.suite, d.serverHS, d.transcript)
	d.queueMessage(2, 20, finished)
	d.transcript = append(d.transcript, stMessage(20, finished)...)
	if err = d.applicationKeys(); err != nil {
		return err
	}
	d.writeEpoch = 3
	d.stage = 2
	return d.transmit()
}

func (d *dtls13) clientServerHello(body []byte) error {
	p := stCursor{data: body}
	if p.number(2) != 0xfefd {
		return errors.New("invalid DTLS1.3 ServerHello version")
	}
	random := p.take(32)
	session := p.vector(1)
	suite := uint16(p.number(2))
	compression := p.number(1)
	extBytes := p.vector(2)
	if p.end() != nil || len(session) != 0 || compression != 0 || !slices.Contains(d.owner.suites, suite) {
		return errors.New("invalid DTLS1.3 ServerHello")
	}
	ext, err := stExtensions(extBytes)
	if err != nil {
		return err
	}
	if !bytes.Equal(ext[43], []byte{0xfe, 0xfc}) {
		return errors.New("DTLS1.3 version not selected")
	}
	s, _ := stSuite(suite)
	if bytes.Equal(random, stRetryRandom) {
		if d.retried || len(ext[44]) == 0 || ext[41] != nil {
			return errors.New("invalid DTLS1.3 HelloRetryRequest")
		}
		for kind := range ext {
			if kind != 43 && kind != 44 && kind != 51 {
				return errors.New("unoffered DTLS1.3 retry extension")
			}
		}
		if ext[51] != nil {
			return errors.New("DTLS1.3 retry requested an already offered key share")
		}
		q := stCursor{data: ext[44]}
		cookie := q.vector(2)
		if q.end() != nil || len(cookie) == 0 || len(cookie) > 256 {
			return errors.New("invalid DTLS1.3 retry cookie")
		}
		d.suite = s
		d.retried = true
		d.transcript = append(stMessage(254, dtls13Hash(s, d.transcript)), stMessage(2, body)...)
		hello, e := d.clientHello(cookie)
		if e != nil {
			return e
		}
		d.transcript = append(d.transcript, stMessage(1, hello)...)
		d.owner.writeMu.Lock()
		defer d.owner.writeMu.Unlock()
		d.clearFlight()
		d.queueMessage(0, 1, hello)
		return d.transmit()
	}
	if d.retried && s.id != d.suite.id {
		return errors.New("DTLS1.3 cipher changed after retry")
	}
	if len(ext) != 3 || len(ext[41]) != 2 {
		return errors.New("DTLS1.3 server did not select external PSK")
	}
	chosen := int(binary.BigEndian.Uint16(ext[41]))
	if chosen >= len(d.offered) || d.offered[chosen].hash != s.hash {
		return errors.New("DTLS1.3 server selected an incompatible PSK")
	}

	key := stCursor{data: ext[51]}
	group := key.number(2)
	share := key.vector(2)
	if key.end() != nil || group != 29 || len(share) != 32 {
		return errors.New("invalid DTLS1.3 server key share")
	}
	d.suite = s
	d.transcript = append(d.transcript, stMessage(2, body)...)
	d.owner.writeMu.Lock()
	defer d.owner.writeMu.Unlock()
	d.clearFlight()
	d.stage = 1
	return d.trafficKeys(share)
}

func (d *dtls13) message(kind byte, body []byte, epoch uint64) error {
	if d.owner.ready.Load() {
		if epoch < 3 {
			return errors.New("unexpected old-epoch DTLS1.3 handshake")
		}
		switch kind {
		case 4:
			if !d.owner.client {
				return errors.New("unexpected DTLS1.3 session ticket")
			}
			p := stCursor{data: body}
			p.take(8)
			p.vector(1)
			ticket := p.vector(2)
			ext := p.vector(2)
			if p.end() != nil || len(ticket) == 0 {
				return errors.New("invalid DTLS1.3 session ticket")
			}
			_, err := stExtensions(ext)
			return err
		case 24:
			if len(body) != 1 || body[0] > 1 || epoch != d.readEpoch {
				return errors.New("invalid DTLS1.3 KeyUpdate")
			}
			current := d.readKeys[epoch]
			secret := dtls13Expand(d.suite, current.key.secret, "traffic upd", nil, d.suite.hash.Size())
			next, err := newDTLS13Epoch(d.suite, secret, epoch+1)
			clear(secret)
			if err != nil {
				return err
			}
			d.readKeys[epoch+1] = next
			d.readEpoch++
			if body[0] == 1 {
				d.owner.writeMu.Lock()
				err = d.keyUpdateLocked(false)
				d.owner.writeMu.Unlock()
			}
			return err
		default:
			return errors.New("unexpected DTLS1.3 post-handshake message")
		}
	}
	if !d.owner.client {
		if kind == 1 && d.stage == 0 && epoch == 0 {
			return d.serverClientHello(body)
		}
		if kind != 20 || d.stage != 2 || epoch != 2 || !hmac.Equal(body, dtls13Finished(d.suite, d.clientHS, d.transcript)) {
			return errors.New("DTLS1.3 client Finished authentication failed")
		}
		d.owner.writeMu.Lock()
		d.clearFlight()
		d.owner.writeMu.Unlock()
		d.owner.ready.Store(true)
		return nil
	}
	switch {
	case kind == 2 && d.stage == 0 && epoch == 0:
		return d.clientServerHello(body)
	case kind == 8 && d.stage == 1 && epoch == 2:
		p := stCursor{data: body}
		ext := p.vector(2)
		if p.end() != nil {
			return errors.New("invalid DTLS1.3 EncryptedExtensions")
		}
		exts, err := stExtensions(ext)
		if err != nil {
			return err
		}
		for kind := range exts {
			if kind != 10 {
				return fmt.Errorf("unoffered DTLS1.3 extension %d", kind)
			}
		}
		d.transcript = append(d.transcript, stMessage(8, body)...)
		d.stage = 2
		return nil
	case kind == 20 && d.stage == 2 && epoch == 2:
		if !hmac.Equal(body, dtls13Finished(d.suite, d.serverHS, d.transcript)) {
			return errors.New("DTLS1.3 server Finished authentication failed")
		}
		d.transcript = append(d.transcript, stMessage(20, body)...)
		if err := d.applicationKeys(); err != nil {
			return err
		}
		finished := dtls13Finished(d.suite, d.clientHS, d.transcript)
		d.owner.writeMu.Lock()
		defer d.owner.writeMu.Unlock()
		d.clearFlight()
		d.queueMessage(2, 20, finished)
		if err := d.transmit(); err != nil {
			return err
		}
		d.writeEpoch = 3
		d.owner.ready.Store(true)
		return nil
	}
	return errors.New("unexpected DTLS1.3 PSK handshake")
}

func (d *dtls13) write(kind byte, payload []byte) error {
	data := make([]byte, len(payload)+1)
	data[0] = kind
	copy(data[1:], payload)
	_, err := d.writeRecord(d.writeEpoch, 23, data)
	if err == nil && kind == 0 {
		d.owner.sent.Add(1)
	}
	if err != nil {
		d.owner.ready.Store(false)
		d.clearFlight()
		d.owner.conn.Close()
	}
	return err
}

func (d *dtls13) read() (byte, []byte, error) {
	for {
		if d.failures >= 1<<16 {
			return 0, nil, errors.New("DTLS1.3 authentication failure limit")
		}
		wire, err := d.nextRecord()
		if err != nil {
			return 0, nil, err
		}
		kind, body, id, duplicate, ok := d.open(wire)
		if !ok {
			continue
		}
		switch kind {
		case 21:
			return 0, nil, io.EOF
		case 22:
			if !duplicate {
				if err = d.handshakes(body, id.epoch); err != nil {
					return 0, nil, err
				}
			}
			if err = d.acknowledge(id); err != nil {
				return 0, nil, err
			}
		case 26:
			if !duplicate {
				if err = d.ack(body); err != nil {
					return 0, nil, err
				}
			}
		case 23:
			if duplicate || id.epoch < 3 || len(body) == 0 {
				continue
			}
			d.owner.lastReceive.Store(time.Now().UnixNano())
			if body[0] == 0 {
				d.owner.received.Add(1)
			}
			return body[0], body[1:], nil
		}
	}
}
