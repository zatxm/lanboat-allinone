package native

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

func ocExporter(conn net.Conn) ([]byte, error) {
	return tlsExport(conn, "EXPORTER-openconnect-psk", nil, 32)
}

type ocDTLSBinding struct {
	tunnel  *ocTunnel
	peer    *ocDTLSPeer
	pending *ocDTLSPeer
	resume  *ocDTLSResume
}

type ocDTLSListener struct {
	version13 bool
	r         *Runtime
	packet    net.PacketConn
	suites    []uint16
	secret    [32]byte
	mu        sync.Mutex
	bindings  map[string]*ocDTLSBinding
	peers     map[string]*ocDTLSPeer
	workers   sync.WaitGroup
}

func newOCDTLSListener(r *Runtime, packet net.PacketConn) *ocDTLSListener {
	l := &ocDTLSListener{r: r, packet: packet, bindings: map[string]*ocDTLSBinding{}, peers: map[string]*ocDTLSPeer{}}
	rand.Read(l.secret[:])
	return l
}

func (l *ocDTLSListener) register(t *ocTunnel) (string, error) {
	psk, err := ocExporter(t.conn)
	if err != nil {
		return "", err
	}
	clear(psk)
	return l.registerBinding(t, nil)
}

func (l *ocDTLSListener) registerBinding(t *ocTunnel, resume *ocDTLSResume) (string, error) {
	var id [32]byte
	rand.Read(id[:])
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.bindings) >= 128 {
		return "", errors.New("OpenConnect DTLS session limit")
	}
	l.bindings[string(id[:])] = &ocDTLSBinding{tunnel: t, resume: resume}
	t.onClose = func() {
		l.mu.Lock()
		if b := l.bindings[string(id[:])]; b != nil {
			if b.resume != nil {
				clear(b.resume.master[:])
			}
			if b.peer != nil {
				b.peer.Close()
			}
			if b.pending != nil {
				b.pending.Close()
			}
			delete(l.bindings, string(id[:]))
		}
		l.mu.Unlock()
	}
	return hex.EncodeToString(id[:]), nil
}

func (l *ocDTLSListener) cookie(addr net.Addr, id, random []byte) []byte {
	m := hmac.New(sha256.New, l.secret[:])
	m.Write([]byte(addr.String()))
	m.Write(id)
	m.Write(random)
	return m.Sum(nil)[:16]
}

func (l *ocDTLSListener) run() {
	defer l.workers.Wait()
	defer func() {
		l.mu.Lock()
		for _, p := range l.peers {
			p.Close()
		}
		l.mu.Unlock()
	}()
	b := make([]byte, 18432)
	for {
		n, from, err := l.packet.ReadFrom(b)
		if err != nil {
			return
		}
		wire := b[:n]
		key := from.String()
		l.mu.Lock()
		peer := l.peers[key]
		if peer != nil && peer.closed() {
			delete(l.peers, key)
			peer = nil
		}
		l.mu.Unlock()
		if peer == nil {
			if len(wire) < 27 || wire[0] != 22 || !(wire[1] == 0xfe && (wire[2] == 0xfd || wire[2] == 0xff) || wire[1] == 1 && wire[2] == 0) || binary.BigEndian.Uint16(wire[3:5]) != 0 || int(binary.BigEndian.Uint16(wire[11:])) != len(wire)-13 || wire[13] != 1 || readUint24(wire[19:22]) != 0 || readUint24(wire[14:17]) != uint32(len(wire)-25) || readUint24(wire[22:25]) != uint32(len(wire)-25) {
				continue
			}
			var id, gotCookie, random []byte
			var v13 *dtls13
			if l.version13 {
				id, v13 = l.accept13(wire, from)
				if v13 == nil {
					continue
				}
			} else {
				id, gotCookie, random, _, _, err = ocDTLSParseHello(wire[25:], binary.BigEndian.Uint16(wire[25:27]))
				if err != nil {
					continue
				}
			}
			l.mu.Lock()
			binding := l.bindings[string(id)]
			if binding == nil || len(l.peers) >= 128 || binding.pending != nil && !binding.pending.closed() {
				l.mu.Unlock()
				continue
			}
			if binding.resume != nil && binary.BigEndian.Uint16(wire[25:27]) != binding.resume.version || binding.resume == nil && binary.BigEndian.Uint16(wire[25:27]) != 0xfefd {
				l.mu.Unlock()
				continue
			}
			cookie := l.cookie(from, id, random)
			if !l.version13 && binding.resume == nil && !hmac.Equal(cookie, gotCookie) {
				l.mu.Unlock()
				body := append([]byte{0xfe, 0xfd, byte(len(cookie))}, cookie...)
				msg := ocDTLSHandshakeMessage(3, 0, body)
				header := ocDTLSRecordHeader(22, 0, binary.BigEndian.Uint64(wire[3:11])&((1<<48)-1), len(msg))
				_, _ = l.packet.WriteTo(append(header, msg...), from)
				continue
			}
			seq := binary.BigEndian.Uint16(wire[17:19])
			if seq > 1 {
				l.mu.Unlock()
				continue
			}
			var psk []byte
			var resumed *ocDTLSResume
			if binding.resume != nil {
				copy := *binding.resume
				resumed = &copy
			} else {
				psk, err = ocExporter(binding.tunnel.conn)
			}
			if err != nil {
				l.mu.Unlock()
				continue
			}
			peer = &ocDTLSPeer{l: l, remote: from, packets: make(chan []byte, 128), done: make(chan struct{}), wake: make(chan struct{}, 1)}
			l.peers[key], binding.pending = peer, peer
			d := &ocDTLS{v13: v13, conn: peer, psk: psk, appID: bytes.Clone(id), recvNext: seq, sendNext: 1, writeSeq: 1, suites: l.suites}
			if resumed != nil {
				d.resume = resumed
				d.sendNext, d.writeSeq = 0, 0
			}
			l.workers.Add(1)
			go func(binding *ocDTLSBinding, peer *ocDTLSPeer, d *ocDTLS) {
				defer l.workers.Done()
				defer peer.Close()
				defer func() {
					l.mu.Lock()
					if l.peers[key] == peer {
						delete(l.peers, key)
					}
					if binding.pending == peer {
						binding.pending = nil
					}
					l.mu.Unlock()
				}()
				ctx, cancel := context.WithTimeout(l.r.ctx, 8*time.Second)
				stop := context.AfterFunc(ctx, func() { peer.Close() })
				err := d.handshake(ctx)
				stop()
				cancel()
				if err == nil {
					l.mu.Lock()
					binding.peer, binding.pending = peer, nil
					l.mu.Unlock()
					binding.tunnel.receiveDTLS(d)
				} else {
					l.r.logger.Debug("OpenConnect DTLS handshake unavailable", zap.Error(err))
				}
			}(binding, peer, d)
			l.mu.Unlock()
		}
		peer.queue(wire)
	}
}

type ocDTLSPeer struct {
	l           *ocDTLSListener
	remote      net.Addr
	packets     chan []byte
	done        chan struct{}
	wake        chan struct{}
	once        sync.Once
	mu          sync.Mutex
	readAt      time.Time
	queuedBytes int
}

func (p *ocDTLSPeer) closed() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}
func (p *ocDTLSPeer) Close() error {
	p.once.Do(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		close(p.done)
		for {
			select {
			case b := <-p.packets:
				p.queuedBytes -= len(b)
			default:
				return
			}
		}
	})
	return nil
}

func (p *ocDTLSPeer) queue(b []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed() || len(p.packets) == cap(p.packets) || p.queuedBytes+len(b) > 256<<10 {
		return false
	}
	p.packets <- bytes.Clone(b)
	p.queuedBytes += len(b)
	return true
}
func (p *ocDTLSPeer) LocalAddr() net.Addr              { return p.l.packet.LocalAddr() }
func (p *ocDTLSPeer) RemoteAddr() net.Addr             { return p.remote }
func (p *ocDTLSPeer) SetWriteDeadline(time.Time) error { return nil }
func (p *ocDTLSPeer) SetDeadline(t time.Time) error    { return p.SetReadDeadline(t) }
func (p *ocDTLSPeer) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.readAt = t
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
	return nil
}
func (p *ocDTLSPeer) Write(b []byte) (int, error) {
	if p.closed() {
		return 0, net.ErrClosed
	}
	return p.l.packet.WriteTo(b, p.remote)
}
func (p *ocDTLSPeer) Read(b []byte) (int, error) {
	for {
		p.mu.Lock()
		deadline := p.readAt
		p.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case data := <-p.packets:
			p.mu.Lock()
			p.queuedBytes -= len(data)
			p.mu.Unlock()
			if timer != nil {
				timer.Stop()
			}
			if len(data) > len(b) {
				return 0, io.ErrShortBuffer
			}
			return copy(b, data), nil
		case <-p.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, net.ErrClosed
		case <-p.wake:
			if timer != nil {
				timer.Stop()
			}
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (t *ocTunnel) receiveDTLS(d *ocDTLS) {
	t.dtlsMu.Lock()
	select {
	case <-t.done:
		t.dtlsMu.Unlock()
		d.conn.Close()
		return
	default:
	}
	old := t.dtls
	t.dtlsWorkers.Add(1)
	t.dtls = d
	t.dtlsPath.Store(true)
	t.dtlsMu.Unlock()
	defer t.dtlsWorkers.Done()
	if old != nil {
		old.conn.Close()
	}
	defer d.conn.Close()
	defer func() {
		d.ready.Store(false)
		if d.secret != nil {
			clear(d.secret[:])
		}
		if d.v13 != nil {
			d.writeMu.Lock()
			d.v13.clearFlight()
			d.writeMu.Unlock()
		}
	}()
	t.r.logger.Debug("OpenConnect DTLS channel ready", zap.Uint16("cipher_suite", d.suite))
	defer func() {
		t.r.logger.Debug("OpenConnect DTLS traffic", zap.Uint64("sent_ip_packets", d.sent.Load()), zap.Uint64("received_ip_packets", d.received.Load()))
	}()
	var renew time.Time
	if t.dtlsRekeyAfter > 0 {
		renew = time.Now().Add(t.dtlsRekeyAfter * 9 / 10)
	}
	generation := d.generation.Load()
	for {
		if latest := d.generation.Load(); latest != generation {
			generation = latest
			t.r.logger.Debug("OpenConnect DTLS rekeyed", zap.Uint64("generation", latest))
			if !renew.IsZero() {
				renew = time.Now().Add(t.dtlsRekeyAfter * 9 / 10)
			}
		}
		deadline := time.Unix(0, d.lastReceive.Load()).Add(30 * time.Second)
		if !renew.IsZero() && renew.Before(deadline) {
			deadline = renew
		}
		d.readDeadline = deadline
		d.conn.SetReadDeadline(deadline)
		kind, packet, err := d.read()
		if err != nil {
			if os.IsTimeout(err) && generation != d.generation.Load() {
				continue
			}
			if os.IsTimeout(err) && t.dtlsRekeyMethod == "ssl" && !renew.IsZero() && !time.Now().Before(renew) {
				ctx, cancel := context.WithTimeout(t.ctx, 5*time.Second)
				err = d.renegotiate(ctx, nil)
				cancel()
				if err == nil {
					renew = time.Now().Add(t.dtlsRekeyAfter * 9 / 10)
					continue
				}
			}
			t.r.logger.Debug("OpenConnect DTLS channel closed", zap.Error(err))
			return
		}
		if !t.handlePacket(kind, packet, d) {
			return
		}
	}
}

func (c *ocClient) startDTLS(t *ocTunnel, headers http.Header) {
	if c.o.DisableDTLS || !c.o.dtlsAccepted(headers) {
		if !c.o.DisableDTLS {
			c.r.logger.Debug("OpenConnect DTLS not negotiated", zap.String("cipher", headers.Get("X-DTLS-CipherSuite")))
		}
		return
	}
	idHeader := "X-DTLS-App-ID"
	if c.o.dtlsResume() {
		idHeader = "X-DTLS-Session-ID"
	}
	id, err := hex.DecodeString(headers.Get(idHeader))
	port, e := strconv.ParseUint(headers.Get("X-DTLS-Port"), 10, 16)
	if err != nil || e != nil || port == 0 || len(id) < 16 || len(id) > 32 {
		c.r.logger.Debug("OpenConnect DTLS negotiation parameters invalid", zap.Int("id_bytes", len(id)), zap.Uint64("port", port))
		return
	}
	if n, err := strconv.Atoi(headers.Get("X-DTLS-MTU")); err == nil && n >= 576 {
		t.dtlsMTU = min(t.dtlsMTU, n)
	}
	suites, _ := c.o.dtlsCipherIDs()
	var resumed *ocDTLSResume
	if c.o.dtlsResume() {
		if len(id) != 32 {
			return
		}
		resumed = &ocDTLSResume{version: c.o.resumeVersion(), suite: c.o.dtlsSelected(headers), master: c.connectMaster}
	}
	t.dtlsWorkers.Add(1)
	go func() {
		defer t.dtlsWorkers.Done()
		defer func() {
			if resumed != nil {
				clear(resumed.master[:])
			}
		}()
		for {
			ctx, cancel := context.WithTimeout(t.ctx, 4*time.Second)
			o := c.o
			o.ServerPort = uint16(port)
			var psk []byte
			var err error
			if resumed == nil {
				psk, err = ocExporter(t.conn)
			}
			if err != nil {
				cancel()
				return
			}
			raw, err := c.endpointTransport(ctx, o, "udp")
			retry := 30 * time.Second
			if err == nil {
				d := &ocDTLS{conn: raw, client: true, psk: psk, appID: id, suites: suites}
				if resumed != nil {
					copy := *resumed
					d.resume = &copy
				}
				if c.o.DTLSVersion == "1.3" {
					d.v13 = &dtls13{identity: []byte(hex.EncodeToString(id))}
				}
				stop := context.AfterFunc(ctx, func() { raw.Close() })
				err = d.handshake(ctx)
				stop()
				cancel()
				if err == nil {
					t.receiveDTLS(d)
					retry = time.Second
				} else {
					clear(d.psk)
					raw.Close()
					c.r.logger.Debug("OpenConnect DTLS handshake unavailable", zap.Error(err))
				}
			} else {
				cancel()
			}
			clear(psk)
			timer := time.NewTimer(retry)
			select {
			case <-t.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}

func (l *ocDTLSListener) negotiate(t *ocTunnel, o OpenConnectOptions, request, response http.Header, mtu int) {
	offered := strings.Split(request.Get(o.dtlsCipherHeader()), ":")
	var id string
	var err error
	cipher := o.dtlsNegotiation()
	cipherHeader := o.dtlsCipherHeader()
	var suiteID uint16
	if o.dtlsResume() {
		cipher = ""
		ids, _ := o.dtlsCipherIDs()
		for _, suite := range ids {
			if slices.Contains(offered, ocDTLSResumeName(suite)) {
				cipher, suiteID = ocDTLSResumeName(suite), suite
				if suite == 0xccab {
					cipherHeader = "X-DTLS-CipherSuite"
				}
				break
			}
			oldName := ocDTLSOldResumeName(suite)
			if o.DTLSVersion != "0.9" && oldName != "" && slices.Contains(strings.Split(request.Get("X-DTLS-CipherSuite"), ":"), oldName) {
				cipher, cipherHeader, suiteID = oldName, "X-DTLS-CipherSuite", suite
				break
			}
		}
		if cipher == "" {
			return
		}
		master, e := hex.DecodeString(request.Get("X-DTLS-Master-Secret"))
		if e != nil || len(master) != 48 {
			clear(master)
			return
		}
		resume := &ocDTLSResume{version: o.resumeVersion()}
		copy(resume.master[:], master)
		clear(master)
		resume.suite = suiteID
		id, err = l.registerBinding(t, resume)
		if err != nil {
			clear(resume.master[:])
			return
		}
		response["X-DTLS-Session-ID"] = []string{id}
	} else {
		if !slices.Contains(offered, cipher) {
			return
		}
		id, err = l.register(t)
		if err != nil {
			return
		}
		response["X-DTLS-App-ID"] = []string{id}
	}
	_, port, _ := net.SplitHostPort(l.packet.LocalAddr().String())
	response["X-DTLS-Port"] = []string{port}
	response[cipherHeader] = []string{cipher}
	response["X-DTLS-DPD"] = []string{"10"}
	response["X-DTLS-Keepalive"] = []string{"10"}
	response["X-DTLS-MTU"] = []string{strconv.Itoa(min(mtu, 1280))}
	if o.DTLSRekeyTime == "" {
		response["X-DTLS-Rekey-Method"] = []string{"none"}
	}
}
