package native

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

func SSRProtocols() []string {
	return []string{"origin", "verify_sha1", "verify_deflate", "auth_sha1", "auth_sha1_v2", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "auth_chain_b", "auth_chain_c", "auth_chain_d", "auth_chain_e", "auth_chain_f"}
}
func ssrProtocol(value string) string {
	if value == "" {
		return "origin"
	}
	return value
}
func validateSSR(method, password, protocol, param, obfs string) error {
	key, err := newSSKey(method, password)
	if err != nil {
		return err
	}
	if _, _, ok := ssStreamParameters(method); !ok {
		return errors.New("SSR requires a stream cipher")
	}
	if !slices.Contains(SSRProtocols(), ssrProtocol(protocol)) {
		return errors.New("unknown SSR protocol")
	}
	if obfs != "" && obfs != "none" && !slices.Contains(SSRObfuscations(), obfs) {
		return errors.New("unknown SSR obfuscation")
	}
	_, _, _, err = ssrUser(key, ssrProtocol(protocol), param)
	return err
}
func ssrTime(timestamp uint32) error {
	delta := time.Now().Unix() - int64(timestamp)
	if delta < -600 || delta > 600 {
		return errors.New("authentication timestamp is outside the 10 minute window")
	}
	return nil
}
func readSSRAddress(conn net.Conn) (string, error) {
	ota, ok := conn.(*ssrOTAConn)
	if !ok {
		return readAddress(conn)
	}
	var head [1]byte
	if _, err := io.ReadFull(ota.ssStreamConn, head[:]); err != nil {
		return "", err
	}
	if head[0]&16 == 0 {
		return "", errors.New("SSR OTA flag is missing")
	}
	var raw bytes.Buffer
	raw.Write(head[:])
	head[0] &= 15
	reader := io.TeeReader(io.MultiReader(bytes.NewReader(head[:]), ota.ssStreamConn), &raw)
	address, err := readAddress(reader)
	if err != nil {
		return "", err
	}
	encoded := raw.Bytes()[1:]
	encoded[0] |= 16
	var tag [10]byte
	if _, err := io.ReadFull(ota.ssStreamConn, tag[:]); err != nil {
		return "", err
	}
	key := append(append([]byte{}, ota.readIV...), ota.key.master...)
	if !hmac.Equal(tag[:], ssrMAC(sha1.New, key, encoded, 10)) {
		return "", errors.New("SSR OTA header rejected")
	}
	return address, nil
}
func ssrUser(key *ssKey, protocol, param string) ([]byte, []byte, func() hash.Hash, error) {
	userKey, uid := key.master, ssrRandom(4)
	var h func() hash.Hash = sha1.New
	if protocol == "auth_aes128_md5" || strings.HasPrefix(protocol, "auth_chain_") {
		h = md5.New
	}
	if name, password, ok := strings.Cut(param, ":"); ok {
		n, err := strconv.ParseUint(name, 10, 32)
		if err != nil {
			return nil, nil, nil, errors.New("invalid SSR user ID")
		}
		uid = binary.LittleEndian.AppendUint32(nil, uint32(n))
		if strings.HasPrefix(protocol, "auth_chain_") {
			userKey = []byte(strings.Split(password, "#")[0])
		} else {
			digest := h()
			digest.Write([]byte(password))
			userKey = digest.Sum(nil)
		}
	}
	return userKey, uid, h, nil
}
func ssrClient(raw net.Conn, o Outbound, key *ssKey) (net.Conn, error) {
	wrapped, err := dialSSRObfs(raw, o, key)
	if err != nil {
		return nil, err
	}
	stream := &ssStreamConn{Conn: wrapped, key: key}
	_, size, _ := ssStreamParameters(key.method)
	stream.writeIV = ssrRandom(size)
	protocol := ssrProtocol(o.Protocol)
	if protocol == "origin" {
		return stream, nil
	}
	if protocol == "verify_sha1" {
		return &ssrOTAConn{ssStreamConn: stream}, nil
	}
	if strings.HasPrefix(protocol, "auth_chain_") {
		return newSSRChain(stream, o)
	}
	userKey, uid, h, err := ssrUser(key, protocol, o.ProtocolParam)
	if err != nil {
		return nil, err
	}
	return &ssrAuthConn{Conn: stream, protocol: protocol, key: key.master, iv: stream.writeIV, userKey: userKey, uid: uid, hash: h, sendID: 1, recvID: 1}, nil
}

func ssrAccept(raw net.Conn, in Inbound, key *ssKey, replay *replayWindow) (net.Conn, error) {
	wrapped, err := acceptSSRObfs(raw, in, key, replay)
	if err != nil {
		return nil, err
	}
	stream := &ssStreamConn{Conn: wrapped, key: key}
	if err := stream.initRead(); err != nil {
		return nil, err
	}
	protocol := ssrProtocol(in.Protocol)
	if protocol == "origin" {
		return stream, nil
	}
	if protocol == "verify_sha1" {
		return &ssrOTAConn{ssStreamConn: stream, server: true}, nil
	}
	if strings.HasPrefix(protocol, "auth_chain_") {
		return acceptSSRChain(stream, in, replay)
	}
	userKey, uid, h, err := ssrUser(key, protocol, in.ProtocolParam)
	if err != nil {
		return nil, err
	}
	c := &ssrAuthConn{Conn: stream, protocol: protocol, key: key.master, iv: stream.readIV, userKey: userKey, uid: uid, hash: h, sendID: 1, recvID: 1, server: true}
	if protocol == "verify_deflate" {
		return c, nil
	}
	var frame []byte
	if strings.HasPrefix(protocol, "auth_aes128_") {
		prefix := make([]byte, 31)
		if _, err := io.ReadFull(stream, prefix); err != nil {
			return nil, err
		}
		macKey := append(append([]byte{}, stream.readIV...), key.master...)
		if !hmac.Equal(prefix[1:7], ssrMAC(h, macKey, prefix[:1], 6)) || !hmac.Equal(prefix[27:31], ssrMAC(h, macKey, prefix[7:27], 4)) {
			return nil, errors.New("SSR authentication header rejected")
		}
		if in.ProtocolParam != "" && !bytes.Equal(uid, prefix[7:11]) {
			return nil, errors.New("SSR user rejected")
		}
		block, _ := aes.NewCipher(ssrPasswordKey(base64.StdEncoding.EncodeToString(userKey)+protocol, 16))
		identity := make([]byte, 16)
		cipher.NewCBCDecrypter(block, make([]byte, 16)).CryptBlocks(identity, prefix[11:27])
		size, padding := int(binary.LittleEndian.Uint16(identity[12:14])), int(binary.LittleEndian.Uint16(identity[14:16]))
		if size < 35 || size >= 8192 || padding > size-35 {
			return nil, fmt.Errorf("invalid SSR authentication length: %d", size)
		}
		if err := ssrTime(binary.LittleEndian.Uint32(identity)); err != nil {
			return nil, err
		}
		frame = make([]byte, size)
		copy(frame, prefix)
		if _, err := io.ReadFull(stream, frame[31:]); err != nil {
			return nil, err
		}
		if !hmac.Equal(frame[size-4:], ssrMAC(h, userKey, frame[:size-4], 4)) {
			return nil, errors.New("SSR authentication rejected")
		}
		c.pending = frame[31+padding : size-4]
	} else {
		prefix := make([]byte, 6)
		if _, err := io.ReadFull(stream, prefix); err != nil {
			return nil, err
		}
		size := int(binary.BigEndian.Uint16(prefix[4:6]))
		if protocol == "auth_sha1_v4" {
			size = int(binary.BigEndian.Uint16(prefix[:2]))
		}
		if size < 29 || size >= 8192 {
			return nil, fmt.Errorf("invalid SSR authentication length: %d", size)
		}
		frame = make([]byte, size)
		copy(frame, prefix)
		if _, err := io.ReadFull(stream, frame[6:]); err != nil {
			return nil, err
		}
		macKey := append(append([]byte{}, stream.readIV...), key.master...)
		if !hmac.Equal(frame[size-10:], ssrMAC(sha1.New, macKey, frame[:size-10], 10)) {
			return nil, errors.New("SSR authentication rejected")
		}
		checksum := crc32.ChecksumIEEE(key.master)
		position := 6
		if protocol == "auth_sha1_v4" {
			checksum = crc32.ChecksumIEEE(append(append(append([]byte{}, frame[:2]...), protocol...), key.master...))
			if binary.LittleEndian.Uint32(frame[2:6]) != checksum {
				return nil, errors.New("SSR authentication checksum rejected")
			}
		} else {
			if protocol == "auth_sha1_v2" {
				checksum = crc32.ChecksumIEEE(append([]byte(protocol), key.master...))
			}
			if binary.LittleEndian.Uint32(frame[:4]) != checksum {
				return nil, errors.New("SSR authentication checksum rejected")
			}
		}
		padding := int(frame[position])
		if protocol != "auth_sha1" && padding == 255 {
			padding = int(binary.BigEndian.Uint16(frame[position+1:]))
		}
		position += padding
		if padding < 1 || position+12 > size-10 {
			return nil, errors.New("invalid SSR authentication padding")
		}
		if protocol != "auth_sha1_v2" {
			if err := ssrTime(binary.LittleEndian.Uint32(frame[position:])); err != nil {
				return nil, err
			}
		}
		c.pending = frame[position+12 : size-10]
	}
	sum := sha256.Sum256(frame)
	if err := replay.add(key, sum[:]); err != nil {
		return nil, err
	}
	return c, nil
}

func acceptSSRChain(stream *ssStreamConn, in Inbound, replay *replayWindow) (net.Conn, error) {
	protocol := ssrProtocol(in.Protocol)
	userKey, uid, _, err := ssrUser(stream.key, protocol, in.ProtocolParam)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 36)
	if _, err := io.ReadFull(stream, header); err != nil {
		return nil, err
	}
	macKey := append(append([]byte{}, stream.readIV...), stream.key.master...)
	clientHash := ssrMAC(md5.New, macKey, header[:4], 16)
	if !hmac.Equal(header[4:12], clientHash[:8]) {
		return nil, errors.New("SSR chain client authentication rejected")
	}
	serverHash := ssrMAC(md5.New, userKey, header[12:32], 16)
	if !hmac.Equal(header[32:36], serverHash[:4]) {
		return nil, errors.New("SSR chain user authentication rejected")
	}
	if in.ProtocolParam != "" && binary.LittleEndian.Uint32(header[12:16])^binary.LittleEndian.Uint32(clientHash[8:12]) != binary.LittleEndian.Uint32(uid) {
		return nil, errors.New("SSR chain user rejected")
	}
	block, _ := aes.NewCipher(ssrPasswordKey(base64.StdEncoding.EncodeToString(userKey)+protocol, 16))
	identity := make([]byte, 16)
	cipher.NewCBCDecrypter(block, make([]byte, 16)).CryptBlocks(identity, header[16:32])
	if err := ssrTime(binary.LittleEndian.Uint32(identity)); err != nil {
		return nil, err
	}
	overhead := int(binary.LittleEndian.Uint16(identity[12:14]))
	if overhead < 4 || overhead > 64 {
		return nil, errors.New("invalid SSR chain overhead")
	}
	sum := sha256.Sum256(header)
	if err := replay.add(stream.key, sum[:]); err != nil {
		return nil, err
	}
	key := ssrPasswordKey(base64.StdEncoding.EncodeToString(userKey)+base64.StdEncoding.EncodeToString(clientHash), 16)
	enc, _ := rc4.NewCipher(key)
	dec, _ := rc4.NewCipher(key)
	c := &chainConn{Conn: stream, mode: protocol, userKey: userKey, key: stream.key.master, clientHash: serverHash, serverHash: clientHash, enc: enc, dec: dec, sendID: 1, recvID: 1, overhead: overhead, server: true}
	c.initSizes(in.ProtocolParam)
	return c, nil
}

func (c *ssrAuthConn) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return nil
}
func (c *chainConn) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return nil
}

// OTA authenticates only the client-to-server direction in the legacy protocol.
type ssrOTAConn struct {
	*ssStreamConn
	server   bool
	sent     bool
	count    uint64
	pending  []byte
	rmu, wmu sync.Mutex
}

func (c *ssrOTAConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.server {
		return c.ssStreamConn.Write(b)
	}
	if !c.sent {
		c.sent = true
		header := append([]byte{}, b...)
		header[0] |= 16
		key := append(append([]byte{}, c.writeIV...), c.key.master...)
		header = append(header, ssrMAC(sha1.New, key, header, 10)...)
		if err := writeAll(c.ssStreamConn, header); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	written := 0
	for len(b) > 0 {
		n := min(len(b), 65535)
		if c.count > 0xffffffff {
			return written, errors.New("SSR OTA counter exhausted")
		}
		key := binary.BigEndian.AppendUint32(append([]byte{}, c.writeIV...), uint32(c.count))
		c.count++
		frame := binary.BigEndian.AppendUint16(nil, uint16(n))
		frame = append(frame, ssrMAC(sha1.New, key, b[:n], 10)...)
		frame = append(frame, b[:n]...)
		if err := writeAll(c.ssStreamConn, frame); err != nil {
			return written, err
		}
		written += n
		b = b[n:]
	}
	return written, nil
}
func (c *ssrOTAConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if !c.server {
		return c.ssStreamConn.Read(b)
	}
	if len(c.pending) == 0 {
		var header [12]byte
		if _, err := io.ReadFull(c.ssStreamConn, header[:]); err != nil {
			return 0, err
		}
		n := int(binary.BigEndian.Uint16(header[:2]))
		data := make([]byte, n)
		if _, err := io.ReadFull(c.ssStreamConn, data); err != nil {
			return 0, err
		}
		if c.count > 0xffffffff {
			return 0, errors.New("SSR OTA counter exhausted")
		}
		key := binary.BigEndian.AppendUint32(append([]byte{}, c.readIV...), uint32(c.count))
		c.count++
		if !hmac.Equal(header[2:], ssrMAC(sha1.New, key, data, 10)) {
			return 0, errors.New("SSR OTA chunk rejected")
		}
		c.pending = data
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
