package native

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"strings"
	"sync"
	"time"
)

type SudokuOptions struct {
	Key              string              `json:"key"`
	PrivateKey       string              `json:"private_key,omitempty"`
	AEAD             string              `json:"aead,omitempty"`
	ASCII            string              `json:"ascii,omitempty"`
	CustomTable      string              `json:"custom_table,omitempty"`
	CustomTables     []string            `json:"custom_tables,omitempty"`
	PaddingMin       int                 `json:"padding_min,omitempty"`
	PaddingMax       int                 `json:"padding_max,omitempty"`
	PureDownlink     *bool               `json:"enable_pure_downlink,omitempty"`
	HTTPMask         *SudokuHTTPMask     `json:"httpmask,omitempty"`
	Reverse          *SudokuReverse      `json:"reverse,omitempty"`
	Users            []SudokuUserOptions `json:"users,omitempty"`
	UsagePath        string              `json:"usage_path,omitempty"`
	users            *sudokuUsers
	table            *sudokuTable
	uplink, downlink *sudokuLayout
	hint             uint32
	tables           []*SudokuOptions
	acceptTables     []*SudokuOptions
	sharedKey        string
	clientHash       [8]byte
	packedUplink     bool
}

func (o *SudokuOptions) prepare() error {
	return o.prepareForRole(false)
}

func (o *SudokuOptions) prepareClient() error {
	return o.prepareForRole(true)
}

func (o *SudokuOptions) wireKey() string {
	if o.sharedKey != "" {
		return o.sharedKey
	}
	return o.Key
}

func (o *SudokuOptions) prepareForRole(client bool) error {
	if o == nil {
		return errors.New("Sudoku options are required")
	}
	if err := o.Reverse.validate(client); err != nil {
		return err
	}
	if err := o.validateUsers(client); err != nil {
		return err
	}
	o.sharedKey = o.Key
	hash := sha256.Sum256([]byte(o.Key))
	if o.PrivateKey != "" {
		if !client || o.Key != "" {
			return errors.New("Sudoku private_key is outbound-only and cannot be combined with key")
		}
		s, raw, err := sudokuParsePrivate(o.PrivateKey)
		defer clear(raw)
		if err != nil {
			return err
		}
		if s == (sudokuScalar{}) {
			return errors.New("zero Sudoku private scalar is not a connection credential")
		}
		public := sudokuPublic(s)
		o.sharedKey = fmt.Sprintf("%x", public)
		hash = sha256.Sum256(raw)
	}
	copy(o.clientHash[:], hash[:8])
	if len(o.sharedKey) < 16 || len(o.sharedKey) > 4096 {
		return errors.New("Sudoku requires a shared key of 16-4096 bytes")
	}
	if o.AEAD == "" {
		o.AEAD = "chacha20-poly1305"
	}
	if o.AEAD != "none" && o.AEAD != "chacha20-poly1305" && o.AEAD != "aes-128-gcm" {
		return errors.New("Sudoku aead must be none, chacha20-poly1305 or aes-128-gcm")
	}
	if err := o.HTTPMask.prepare(); err != nil {
		return err
	}
	if o.PaddingMin < 0 || o.PaddingMax > 100 || o.PaddingMin > o.PaddingMax {
		return errors.New("Sudoku padding must satisfy 0<=min<=max<=100")
	}
	up, down := false, false
	switch o.ASCII {
	case "", "prefer_entropy":
	case "prefer_ascii":
		up, down = true, true
	case "up_ascii_down_entropy":
		up = true
	case "up_entropy_down_ascii":
		down = true
	default:
		return errors.New("invalid Sudoku ascii mode")
	}
	patterns := o.CustomTables
	if len(patterns) == 0 {
		patterns = []string{o.CustomTable}
	} else if o.CustomTable != "" {
		return errors.New("Sudoku custom_table and custom_tables cannot be combined")
	}
	if len(patterns) > 16 {
		return errors.New("Sudoku supports at most16 custom tables")
	}
	o.table = newSudokuTable(o.wireKey())
	o.tables = make([]*SudokuOptions, 0, len(patterns))
	seen := make(map[uint32]*SudokuOptions, len(patterns))
	for _, pattern := range patterns {
		variant := *o
		variant.tables, variant.acceptTables, variant.CustomTables = nil, nil, nil
		variant.CustomTable = pattern
		if err := variant.prepareLayout(up, down); err != nil {
			return err
		}
		if previous := seen[variant.hint]; previous != nil {
			if previous.uplink.encode != variant.uplink.encode || previous.downlink.encode != variant.downlink.encode {
				return errors.New("Sudoku table hint collision")
			}
			continue
		}
		seen[variant.hint] = &variant
		o.tables = append(o.tables, &variant)
	}
	o.uplink, o.downlink, o.hint = o.tables[0].uplink, o.tables[0].downlink, o.tables[0].hint
	o.acceptTables = o.tables
	if !up && o.tables[0].CustomTable != "" {
		fallback := *o.tables[0]
		fallback.CustomTable = ""
		if err := fallback.prepareLayout(up, down); err != nil {
			return err
		}
		if seen[fallback.hint] == nil {
			o.acceptTables = append([]*SudokuOptions{&fallback}, o.tables...)
		}
	}
	return nil
}

func (o *SudokuOptions) prepareLayout(up, down bool) error {
	var err error
	o.uplink, err = newSudokuLayout(up, o.CustomTable)
	if err != nil {
		return err
	}
	o.downlink, err = newSudokuLayout(down, o.CustomTable)
	if err != nil {
		return err
	}
	mode := o.ASCII
	if mode == "" {
		mode = "prefer_entropy"
	}
	pattern := strings.ToLower(strings.ReplaceAll(o.CustomTable, " ", ""))
	upPattern, downPattern := pattern, pattern
	if up {
		upPattern = ""
	}
	if down {
		downPattern = ""
	}
	fingerprint := sha256.Sum256([]byte(strings.Join([]string{"sudoku-table-hint", o.wireKey(), mode, upPattern, downPattern}, "\x00")))
	o.hint = binary.BigEndian.Uint32(fingerprint[:4])
	return nil
}

func (o *SudokuOptions) codec(raw net.Conn, client bool) *sudokuRecord {
	packed := o.PureDownlink != nil && !*o.PureDownlink
	c := &sudokuCodec{Conn: raw, table: o.table, reader: bufio.NewReaderSize(raw, 4096), readLayout: o.uplink, writeLayout: o.downlink, readPacked: o.packedUplink, writePacked: packed, padding: o.PaddingMin + mathrand.IntN(o.PaddingMax-o.PaddingMin+1)}
	if client {
		c.readLayout, c.writeLayout = o.downlink, o.uplink
		c.readPacked, c.writePacked = packed, o.packedUplink
	}
	c.writePadding = c.writeLayout.padding
	if c.writePacked {
		c.writePadding = make([]byte, 0, len(c.writeLayout.padding)-1)
		for _, b := range c.writeLayout.padding {
			if b != c.writeLayout.marker {
				c.writePadding = append(c.writePadding, b)
			}
		}
	}
	c2s, s2c := sudokuBases(o.wireKey(), nil, nil)
	if client {
		r := newSudokuRecord(c, o.AEAD, c2s, s2c)
		r.options = o
		return r
	}
	r := newSudokuRecord(c, o.AEAD, s2c, c2s)
	r.options = o
	return r
}

func sudokuMessage(w io.Writer, kind byte, body []byte) error {
	if len(body) > 65535 {
		return errors.New("oversized Sudoku control message")
	}
	msg := make([]byte, 6+len(body))
	copy(msg, "kip")
	msg[3] = kind
	binary.BigEndian.PutUint16(msg[4:6], uint16(len(body)))
	copy(msg[6:], body)
	return writeAll(w, msg)
}

func sudokuReadMessage(r io.Reader) (byte, []byte, error) {
	var header [6]byte
	if _, e := io.ReadFull(r, header[:]); e != nil {
		return 0, nil, e
	}
	if string(header[:3]) != "kip" {
		return 0, nil, errors.New("invalid Sudoku control header")
	}
	// Reverse publications carry bounded JSON;other controls fit a SOCKS address.
	n := int(binary.BigEndian.Uint16(header[4:]))
	if n > 259 && (header[3] != 0x13 || n > sudokuReverseMaxRegistration) {
		return 0, nil, errors.New("oversized Sudoku session control")
	}
	b := make([]byte, n)
	_, e := io.ReadFull(r, b)
	return header[3], b, e
}

func sudokuSessionKeys(key string, private *ecdh.PrivateKey, peer, nonce []byte) ([]byte, []byte, error) {
	pub, e := ecdh.X25519().NewPublicKey(peer)
	if e != nil {
		return nil, nil, e
	}
	shared, e := private.ECDH(pub)
	if e != nil {
		return nil, nil, e
	}
	a, b := sudokuBases(key, shared, nonce)
	return a, b, nil
}

func sudokuHandshake(raw net.Conn, o *SudokuOptions, features uint32) (*sudokuRecord, uint32, error) {
	if ready, ok := raw.(*sudokuHTTPReady); ok {
		return ready.record, ready.features, nil
	}
	if len(o.tables) > 0 {
		o = o.tables[mathrand.IntN(len(o.tables))]
	}
	c := o.codec(raw, true)
	private, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return nil, 0, e
	}
	// Even the standard alphabet needs a hint when the peer's first table
	// uses the same ASCII uplink but a different entropy downlink.
	hello := make([]byte, 72)
	binary.BigEndian.PutUint64(hello[:8], uint64(time.Now().Unix()))
	copy(hello[8:16], o.clientHash[:])
	rand.Read(hello[16:32])
	copy(hello[32:64], private.PublicKey().Bytes())
	binary.BigEndian.PutUint32(hello[64:], features)
	binary.BigEndian.PutUint32(hello[68:], o.hint)
	if e = sudokuMessage(c, 1, hello); e != nil {
		return nil, 0, e
	}
	kind, reply, e := sudokuReadMessage(c)
	if e != nil {
		return nil, 0, e
	}
	if kind != 2 || len(reply) != 52 || subtle.ConstantTimeCompare(hello[16:32], reply[:16]) != 1 {
		return nil, 0, errors.New("invalid Sudoku server hello")
	}
	send, receive, e := sudokuSessionKeys(o.wireKey(), private, reply[16:48], hello[16:32])
	if e != nil {
		return nil, 0, e
	}
	c.rekey(send, receive)
	return c, binary.BigEndian.Uint32(reply[48:]), nil
}

func sudokuClient(raw net.Conn, o *SudokuOptions, address string, udp bool) (net.Conn, error) {
	c, selected, e := sudokuHandshake(raw, o, 5)
	if e != nil {
		return nil, e
	}
	feature := uint32(1)
	command := byte(0x10)
	var target []byte
	if udp {
		feature, command = 4, 0x12
	} else {
		target, e = encodeAddress(address)
		if e != nil {
			return nil, e
		}
	}
	if selected&feature == 0 {
		return nil, errors.New("Sudoku server did not negotiate requested command")
	}
	if e = sudokuMessage(c, command, target); e != nil {
		return nil, e
	}
	if udp {
		return &sudokuPackets{Conn: c, address: address}, nil
	}
	return c, nil
}

func (r *Runtime) sudokuServerHello(o *SudokuOptions, c *sudokuRecord) (uint32, error) {
	kind, hello, e := sudokuReadMessage(c)
	if e != nil {
		return 0, e
	}
	if kind != 1 || len(hello) != 68 && len(hello) != 72 {
		return 0, errors.New("invalid Sudoku client hello")
	}
	if len(hello) == 72 && binary.BigEndian.Uint32(hello[68:]) != c.options.hint {
		return 0, errors.New("unknown Sudoku table hint")
	}
	now := time.Now().Unix()
	stamp := int64(binary.BigEndian.Uint64(hello[:8]))
	if stamp < now-60 || stamp > now+60 {
		return 0, errors.New("expired Sudoku client hello")
	}
	if e = r.replay.claimFor("sudoku:"+o.wireKey()+string(hello[8:32]), 2*time.Minute); e != nil {
		return 0, e
	}
	if o.users != nil {
		if c.account == nil {
			return 0, errors.New("Sudoku user accounting is unavailable")
		}
		if e = o.users.authorize(c.account, hello[8:16]); e != nil {
			return 0, e
		}
	}
	private, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return 0, e
	}
	c2s, s2c, e := sudokuSessionKeys(o.wireKey(), private, hello[32:64], hello[16:32])
	if e != nil {
		return 0, e
	}
	allowed := uint32(7)
	if o.Reverse != nil && o.Reverse.Listen != "" {
		allowed |= 8
	}
	features := binary.BigEndian.Uint32(hello[64:68]) & allowed
	reply := make([]byte, 52)
	copy(reply, hello[16:32])
	copy(reply[16:], private.PublicKey().Bytes())
	binary.BigEndian.PutUint32(reply[48:], features)
	if e = sudokuMessage(c, 2, reply); e != nil {
		return 0, e
	}
	c.rekey(s2c, c2s)
	return features, nil
}

func (r *Runtime) serveSudoku(in Inbound, raw net.Conn, q request) error {
	account := in.sudokuAccount
	if account == nil && in.Sudoku.users != nil {
		account = newSudokuAccount()
		raw = account.wrap(raw)
		defer raw.Close()
	}
	raw, c, features, e := r.acceptSudokuHTTPMask(in.Sudoku, raw, account)
	if e != nil {
		if account != nil {
			account.Close()
		}
		return e
	}
	if raw == nil {
		return nil
	}
	defer raw.Close()
	if account != nil {
		defer account.finish()
	}
	if c == nil {
		c, e = in.Sudoku.acceptCodec(raw)
		if e != nil {
			return e
		}
		c.account = account
		features, e = r.sudokuServerHello(in.Sudoku, c)
		if e != nil {
			return e
		}
	}
	var stream net.Conn = c
	if account != nil {
		q.metadata.AuthUser = account.user.name
		if account.user.rate[0].bytesPerSecond != 0 || account.user.rate[1].bytesPerSecond != 0 {
			stream = newSudokuPayload(r.ctx, c, account)
		}
	}
	kind, body, e := sudokuReadMessage(stream)
	if e != nil {
		return e
	}
	switch kind {
	case 0x13:
		if features&8 == 0 || !c.options.packedUplink {
			return errors.New("Sudoku reverse requires negotiated packed uplink")
		}
		return r.serveSudokuReverse(in.Tag, stream, body)
	case 0x11:
		if len(body) != 0 || features&2 == 0 {
			return errors.New("Sudoku multiplexing not negotiated")
		}
		return r.serveSudokuMux(stream, q)
	case 0x10:
		if features&1 == 0 {
			return errors.New("Sudoku TCP not negotiated")
		}
		reader := bytes.NewReader(body)
		q.address, e = readAddress(reader)
		if e != nil || reader.Len() != 0 {
			return errors.New("invalid Sudoku TCP destination")
		}
		if _, e = encodeAddress(q.address); e != nil {
			return e
		}
		remote, e := r.routeDial(r.ctx, q)
		if e != nil {
			return e
		}
		r.relay(stream, remote)
		return nil
	case 0x12:
		if len(body) != 0 || features&4 == 0 {
			return errors.New("Sudoku UDP not negotiated")
		}
		_ = stream.SetDeadline(time.Time{})
		packets := &sudokuPackets{Conn: stream}
		flows := newUDPFlows(r)
		defer flows.Close()
		buf := packetBuffers.Get().([]byte)
		defer packetBuffers.Put(buf)
		for {
			_ = stream.SetReadDeadline(time.Now().Add(r.udpTimeoutFor(in.Tag, udpTimeout)))
			n, addr, e := packets.readPacket(buf)
			if e != nil {
				return e
			}
			q.address = addr
			if e = flows.send(addr, q, buf[:n], func(b []byte, a string) error {
				_ = stream.SetWriteDeadline(time.Now().Add(handshakeTimeout))
				_, err := packets.writePacket(b, a)
				return err
			}); e != nil {
				return e
			}
		}
	default:
		return fmt.Errorf("unnegotiated Sudoku command 0x%x", kind)
	}
}

type sudokuPackets struct {
	net.Conn
	address  string
	rmu, wmu sync.Mutex
}

func (c *sudokuPackets) Read(p []byte) (int, error)  { n, _, e := c.readPacket(p); return n, e }
func (c *sudokuPackets) Write(p []byte) (int, error) { return c.writePacket(p, c.address) }
func (c *sudokuPackets) readPacket(p []byte) (int, string, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	var header [4]byte
	if _, e := io.ReadFull(c.Conn, header[:]); e != nil {
		return 0, "", e
	}
	naddr, n := int(binary.BigEndian.Uint16(header[:2])), int(binary.BigEndian.Uint16(header[2:]))
	if naddr < 5 || naddr > 259 || n > 65507 {
		c.Close()
		return 0, "", errors.New("invalid Sudoku UDP frame length")
	}
	var address [259]byte
	if _, e := io.ReadFull(c.Conn, address[:naddr]); e != nil {
		return 0, "", e
	}
	r := bytes.NewReader(address[:naddr])
	target, e := readAddress(r)
	if e != nil || r.Len() != 0 {
		c.Close()
		return 0, "", errors.New("invalid Sudoku UDP destination")
	}
	if _, e = encodeAddress(target); e != nil {
		c.Close()
		return 0, "", e
	}
	if n > len(p) {
		_, e = io.CopyN(io.Discard, c.Conn, int64(n))
		if e == nil {
			e = io.ErrShortBuffer
		}
		return 0, "", e
	}
	n, e = io.ReadFull(c.Conn, p[:n])
	return n, target, e
}
func (c *sudokuPackets) writePacket(p []byte, address string) (int, error) {
	if len(p) > 65507 {
		return 0, errors.New("Sudoku UDP payload exceeds 65507 bytes")
	}
	encoded, e := encodeAddress(address)
	if e != nil {
		return 0, e
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	frame := make([]byte, 4+len(encoded)+len(p))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(encoded)))
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(p)))
	copy(frame[4:], encoded)
	copy(frame[4+len(encoded):], p)
	if e = writeAll(c.Conn, frame); e != nil {
		c.Close()
		return 0, e
	}
	return len(p), nil
}
