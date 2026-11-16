package native

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

const sshVersion = "SSH-2.0-Lanboat_1.0.0"
const sshMaxPacket = 256 * 1024

func sshString(b []byte, v []byte) []byte {
	return append(binary.BigEndian.AppendUint32(b, uint32(len(v))), v...)
}
func sshText(b []byte, v string) []byte { return sshString(b, []byte(v)) }
func sshInt(b []byte, v uint32) []byte  { return binary.BigEndian.AppendUint32(b, v) }

type sshReader struct {
	b   []byte
	err error
}

func (r *sshReader) take(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
func (r *sshReader) u32() uint32 {
	b := r.take(4)
	if len(b) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (r *sshReader) str() []byte {
	n := r.u32()
	if n > sshMaxPacket {
		r.err = errors.New("SSH string too long")
		return nil
	}
	return r.take(int(n))
}
func sshMPInt(b []byte) []byte {
	b = bytes.TrimLeft(b, "\x00")
	if len(b) > 0 && b[0]&128 != 0 {
		b = append([]byte{0}, b...)
	}
	return sshString(nil, b)
}

type sshCipher struct {
	stream cipher.Stream
	key    []byte
}
type sshWire struct {
	net.Conn
	reader                  *bufio.Reader
	readSeq, writeSeq       uint32
	readCipher, writeCipher sshCipher
	writeMu                 sync.Mutex
	sessionID               []byte
	written                 atomic.Uint64
	read                    uint64
	server                  bool
	host                    crypto.Signer
	pins                    []string
	insecure                bool
	peerVersion             string
	deferred                [][]byte
}

func (w *sshWire) readPacket() ([]byte, error) {
	blockSize := 8
	if w.readCipher.stream != nil {
		blockSize = 16
	}
	first := make([]byte, blockSize)
	if _, e := io.ReadFull(w.reader, first); e != nil {
		return nil, e
	}
	if w.readCipher.stream != nil {
		w.readCipher.stream.XORKeyStream(first, first)
	}
	n := int(binary.BigEndian.Uint32(first))
	if n < 12 || n > sshMaxPacket || (n+4)%blockSize != 0 {
		return nil, errors.New("invalid SSH packet size")
	}
	b := make([]byte, n+4)
	copy(b, first)
	if _, e := io.ReadFull(w.reader, b[blockSize:]); e != nil {
		return nil, e
	}
	if w.readCipher.stream != nil {
		w.readCipher.stream.XORKeyStream(b[blockSize:], b[blockSize:])
		tag := make([]byte, 32)
		if _, e := io.ReadFull(w.reader, tag); e != nil {
			return nil, e
		}
		mac := hmac.New(sha256.New, w.readCipher.key)
		mac.Write(sshInt(nil, w.readSeq))
		mac.Write(b)
		if !hmac.Equal(tag, mac.Sum(nil)) {
			return nil, errors.New("SSH packet authentication failed")
		}
	}
	w.readSeq++
	w.read += uint64(len(b))
	padding := int(b[4])
	if padding < 4 || padding+1 > n {
		return nil, errors.New("invalid SSH padding")
	}
	payload := b[5 : len(b)-padding]
	if len(payload) == 0 {
		return nil, errors.New("empty SSH payload")
	}
	return payload, nil
}
func (w *sshWire) writePacket(payload []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	return w.writePacketLocked(payload)
}
func (w *sshWire) writePacketLocked(payload []byte) error {
	if len(payload) > sshMaxPacket-32 {
		return errors.New("SSH payload too long")
	}
	padding := 16 - (len(payload)+5)%16
	if padding < 4 {
		padding += 16
	}
	b := make([]byte, 5+len(payload)+padding)
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))
	b[4] = byte(padding)
	copy(b[5:], payload)
	if _, e := rand.Read(b[5+len(payload):]); e != nil {
		return e
	}
	var tag []byte
	if w.writeCipher.stream != nil {
		mac := hmac.New(sha256.New, w.writeCipher.key)
		mac.Write(sshInt(nil, w.writeSeq))
		mac.Write(b)
		tag = mac.Sum(nil)
		w.writeCipher.stream.XORKeyStream(b, b)
	}
	if e := writeAll(w.Conn, append(b, tag...)); e != nil {
		return e
	}
	w.writeSeq++
	w.written.Add(uint64(len(b)))
	return nil
}
func (w *sshWire) next() ([]byte, error) {
	for {
		b, e := w.readPacket()
		if e != nil {
			return nil, e
		}
		switch b[0] {
		case 1:
			return nil, errors.New("SSH peer disconnected")
		case 2, 3, 4, 7:
			continue
		}
		return b, nil
	}
}
func sshKexInit(hostAlgs string) []byte {
	b := make([]byte, 17)
	b[0] = 20
	rand.Read(b[1:])
	for _, v := range []string{"curve25519-sha256,curve25519-sha256@libssh.org", hostAlgs, "aes128-ctr", "aes128-ctr", "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", ""} {
		b = sshText(b, v)
	}
	return append(b, 0, 0, 0, 0, 0)
}
func sshAlgorithms(b []byte) ([10]string, bool, error) {
	var out [10]string
	r := sshReader{b: b}
	if v := r.take(17); len(v) != 17 || v[0] != 20 {
		return out, false, errors.New("SSH KEXINIT required")
	}
	for i := range out {
		out[i] = string(r.str())
	}
	v := r.take(1)
	r.u32()
	if r.err != nil || len(r.b) != 0 {
		return out, false, errors.New("invalid SSH algorithm lists")
	}
	return out, v[0] != 0, nil
}
func sshChoose(client, server string) string {
	for _, v := range strings.Split(client, ",") {
		for _, s := range strings.Split(server, ",") {
			if v == s {
				return v
			}
		}
	}
	return ""
}
func sshPubKey(key crypto.PublicKey) ([]byte, error) {
	switch k := key.(type) {
	case ed25519.PublicKey:
		return sshString(sshText(nil, "ssh-ed25519"), k), nil
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, errors.New("SSH RSA key must be at least 2048 bits")
		}
		return append(append(sshText(nil, "ssh-rsa"), sshMPInt(big.NewInt(int64(k.E)).Bytes())...), sshMPInt(k.N.Bytes())...), nil
	case *ecdsa.PublicKey:
		curve, _, err := sshECDSA(k.Curve)
		if err != nil || k.X == nil || k.Y == nil || !k.Curve.IsOnCurve(k.X, k.Y) {
			return nil, errors.New("invalid SSH ECDSA public key")
		}
		return sshString(sshText(sshText(nil, "ecdsa-sha2-"+curve), curve), elliptic.Marshal(k.Curve, k.X, k.Y)), nil
	}
	return nil, errors.New("SSH requires Ed25519, RSA or ECDSA key")
}

func sshECDSA(curve elliptic.Curve) (string, crypto.Hash, error) {
	switch curve {
	case elliptic.P256():
		return "nistp256", crypto.SHA256, nil
	case elliptic.P384():
		return "nistp384", crypto.SHA384, nil
	case elliptic.P521():
		return "nistp521", crypto.SHA512, nil
	}
	return "", 0, errors.New("unsupported SSH ECDSA curve")
}
func sshCurve(name string) elliptic.Curve {
	switch name {
	case "nistp256":
		return elliptic.P256()
	case "nistp384":
		return elliptic.P384()
	case "nistp521":
		return elliptic.P521()
	}
	return nil
}
func sshParsePub(b []byte) (crypto.PublicKey, error) {
	r := sshReader{b: b}
	kind := string(r.str())
	switch kind {
	case "ssh-ed25519":
		v := r.str()
		if len(v) == 32 && r.err == nil && len(r.b) == 0 {
			return ed25519.PublicKey(v), nil
		}
	case "ssh-rsa":
		exponent, modulus := r.str(), r.str()
		n := new(big.Int).SetBytes(modulus)
		e := new(big.Int).SetBytes(exponent)
		if r.err == nil && len(r.b) == 0 && e.IsInt64() && e.Int64() >= 3 && e.Int64() < 1<<31 && n.BitLen() >= 2048 {
			return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
		}
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		name, point := string(r.str()), r.str()
		curve := sshCurve(name)
		if curve != nil && kind == "ecdsa-sha2-"+name && r.err == nil && len(r.b) == 0 {
			x, y := elliptic.Unmarshal(curve, point)
			if x != nil {
				return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
			}
		}
	}
	return nil, errors.New("invalid SSH public key")
}
func sshVerify(key []byte, algorithm string, message, signature []byte) error {
	pub, e := sshParsePub(key)
	if e != nil {
		return e
	}
	r := sshReader{b: signature}
	alg := string(r.str())
	sig := r.str()
	if r.err != nil || len(r.b) != 0 || alg != algorithm {
		return errors.New("invalid SSH signature algorithm")
	}
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if alg == "ssh-ed25519" && ed25519.Verify(k, message, sig) {
			return nil
		}
	case *rsa.PublicKey:
		switch alg {
		case "rsa-sha2-256":
			h := sha256.Sum256(message)
			return rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig)
		case "rsa-sha2-512":
			h := sha512.Sum512(message)
			return rsa.VerifyPKCS1v15(k, crypto.SHA512, h[:], sig)
		}
	case *ecdsa.PublicKey:
		curve, hash, _ := sshECDSA(k.Curve)
		r := sshReader{b: sig}
		ra, sa := r.str(), r.str()
		if alg != "ecdsa-sha2-"+curve || r.err != nil || len(r.b) != 0 || len(ra) == 0 || len(sa) == 0 || ra[0]&128 != 0 || sa[0]&128 != 0 {
			return errors.New("invalid SSH ECDSA signature")
		}
		h := hash.New()
		h.Write(message)
		if ecdsa.Verify(k, h.Sum(nil), new(big.Int).SetBytes(ra), new(big.Int).SetBytes(sa)) {
			return nil
		}
	}
	return errors.New("SSH signature verification failed")
}
func sshSign(key crypto.Signer, algorithm string, message []byte) ([]byte, error) {
	var digest []byte
	var hash crypto.Hash
	switch algorithm {
	case "ssh-ed25519":
		digest = message
	case "rsa-sha2-256":
		h := sha256.Sum256(message)
		digest = h[:]
		hash = crypto.SHA256
	case "rsa-sha2-512":
		h := sha512.Sum512(message)
		digest = h[:]
		hash = crypto.SHA512
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		pub, ok := key.Public().(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("SSH ECDSA signer required")
		}
		curve, h, err := sshECDSA(pub.Curve)
		if err != nil || algorithm != "ecdsa-sha2-"+curve {
			return nil, errors.New("SSH ECDSA curve mismatch")
		}
		hash = h
		d := h.New()
		d.Write(message)
		digest = d.Sum(nil)
	default:
		return nil, errors.New("unsupported SSH signature algorithm")
	}
	sig, e := key.Sign(rand.Reader, digest, hash)
	if strings.HasPrefix(algorithm, "ecdsa-sha2-") && e == nil {
		var v struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(sig, &v)
		if err != nil || len(rest) != 0 || v.R == nil || v.S == nil {
			return nil, errors.New("invalid SSH ECDSA signer output")
		}
		sig = append(sshMPInt(v.R.Bytes()), sshMPInt(v.S.Bytes())...)
	}
	return sshString(sshText(nil, algorithm), sig), e
}
func sshPrivate(inline []string, path string, passphrase ...string) (crypto.Signer, error) {
	raw := []byte(strings.Join(inline, "\n"))
	var e error
	if path != "" {
		raw, e = os.ReadFile(path)
		if e != nil {
			return nil, e
		}
	}
	p, _ := pem.Decode(raw)
	if p == nil {
		return nil, errors.New("SSH private key must be PEM or OpenSSH format")
	}
	var key any
	password := ""
	if len(passphrase) != 0 {
		password = passphrase[0]
	}
	if x509.IsEncryptedPEMBlock(p) {
		p.Bytes, e = x509.DecryptPEMBlock(p, []byte(password))
		if e != nil {
			return nil, errors.New("SSH private key decryption failed")
		}
	}
	switch p.Type {
	case "PRIVATE KEY":
		key, e = x509.ParsePKCS8PrivateKey(p.Bytes)
	case "ENCRYPTED PRIVATE KEY":
		var der []byte
		der, e = sshDecryptPKCS8(p.Bytes, password)
		if e == nil {
			key, e = x509.ParsePKCS8PrivateKey(der)
			clear(der)
		}
	case "RSA PRIVATE KEY":
		key, e = x509.ParsePKCS1PrivateKey(p.Bytes)
	case "EC PRIVATE KEY":
		key, e = x509.ParseECPrivateKey(p.Bytes)
	case "OPENSSH PRIVATE KEY":
		return sshOpenSSHPrivate(p.Bytes, passphrase...)
	default:
		return nil, errors.New("unsupported SSH private key format")
	}
	if e != nil {
		return nil, e
	}
	k, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("invalid SSH private key")
	}
	if _, e = sshPubKey(k.Public()); e != nil {
		return nil, e
	}
	return k, nil
}
func sshOpenSSHPrivate(raw []byte, passphrase ...string) (crypto.Signer, error) {
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(raw, []byte(magic)) {
		return nil, errors.New("invalid OpenSSH key")
	}
	r := sshReader{b: raw[len(magic):]}
	cipherName, kdf, options := string(r.str()), string(r.str()), r.str()
	if r.u32() != 1 {
		return nil, errors.New("OpenSSH key must contain one key")
	}
	public := r.str()
	private := r.str()
	if r.err != nil {
		return nil, errors.New("invalid OpenSSH key envelope")
	}
	if cipherName == "none" {
		if kdf != "none" || len(options) != 0 || len(r.b) != 0 || len(private)%8 != 0 {
			return nil, errors.New("invalid unencrypted OpenSSH key")
		}
	} else {
		password := ""
		if len(passphrase) != 0 {
			password = passphrase[0]
		}
		var err error
		private, err = sshDecryptPrivate(cipherName, kdf, options, private, r.b, password)
		if err != nil {
			return nil, err
		}
	}
	r = sshReader{b: private}
	a, b := r.u32(), r.u32()
	if r.err != nil || a != b {
		return nil, errors.New("OpenSSH key check failed")
	}
	kind := string(r.str())
	var signer crypto.Signer
	switch kind {
	case "ssh-ed25519":
		pub, key := r.str(), r.str()
		if len(pub) != 32 || len(key) != 64 || !bytes.Equal(pub, key[32:]) {
			return nil, errors.New("invalid Ed25519 private key")
		}
		signer = ed25519.NewKeyFromSeed(key[:32])
		if !bytes.Equal(signer.Public().(ed25519.PublicKey), pub) {
			return nil, errors.New("invalid Ed25519 key pair")
		}
	case "ssh-rsa":
		n := new(big.Int).SetBytes(r.str())
		e := new(big.Int).SetBytes(r.str())
		d := new(big.Int).SetBytes(r.str())
		r.str()
		p := new(big.Int).SetBytes(r.str())
		q := new(big.Int).SetBytes(r.str())
		if !e.IsInt64() || e.Int64() < 3 || e.Int64() >= 1<<31 || n.BitLen() < 2048 {
			return nil, errors.New("invalid RSA private key")
		}
		key := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())}, D: d, Primes: []*big.Int{p, q}}
		if err := key.Validate(); err != nil {
			return nil, err
		}
		key.Precompute()
		signer = key
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		name, point, scalar := string(r.str()), r.str(), r.str()
		curve := sshCurve(name)
		if r.err != nil || curve == nil || kind != "ecdsa-sha2-"+name {
			return nil, errors.New("invalid SSH ECDSA private key")
		}
		if len(scalar) == 0 || scalar[0]&128 != 0 {
			return nil, errors.New("invalid SSH ECDSA scalar encoding")
		}
		d := new(big.Int).SetBytes(scalar)
		if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
			return nil, errors.New("invalid SSH ECDSA scalar")
		}
		x, y := curve.ScalarBaseMult(d.Bytes())
		if !bytes.Equal(point, elliptic.Marshal(curve, x, y)) {
			return nil, errors.New("SSH ECDSA key pair mismatch")
		}
		signer = &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}
	default:
		return nil, errors.New("unsupported OpenSSH private key type")
	}
	r.str()
	if r.err != nil {
		return nil, r.err
	}
	for i, v := range r.b {
		if v != byte(i+1) {
			return nil, errors.New("invalid OpenSSH key padding")
		}
	}
	actual, e := sshPubKey(signer.Public())
	if e != nil || !bytes.Equal(actual, public) {
		return nil, errors.New("OpenSSH public/private key mismatch")
	}
	return signer, nil
}
func sshPinned(key []byte, pins []string) bool {
	h := sha256.Sum256(key)
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
	valid := 0
	for _, pin := range pins {
		v := strings.Fields(pin)
		if len(v) >= 2 {
			if blob, e := base64.StdEncoding.DecodeString(v[1]); e == nil {
				valid |= subtle.ConstantTimeCompare(key, blob)
			}
		} else {
			valid |= subtle.ConstantTimeCompare([]byte(fingerprint), []byte(pin))
		}
	}
	return valid == 1
}
func (w *sshWire) handshake(server bool, host crypto.Signer, pins []string, insecure bool) (err error) {
	if err = writeAll(w.Conn, []byte(sshVersion+"\r\n")); err != nil {
		return
	}
	var peer string
	for i := 0; i < 50; i++ {
		lineBytes, e := w.reader.ReadSlice('\n')
		line := string(lineBytes)
		if e != nil {
			return e
		}
		if len(line) > 255 {
			return errors.New("SSH identification too long")
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "SSH-") {
			peer = line
			break
		}
	}
	if !strings.HasPrefix(peer, "SSH-2.0-") {
		return errors.New("SSH version 2 required")
	}
	w.server, w.host, w.pins, w.insecure, w.peerVersion = server, host, pins, insecure, peer
	return w.exchange(nil)
}
func (w *sshWire) exchange(peerInit []byte) (err error) {
	server, host, pins, insecure, peer := w.server, w.host, w.pins, w.insecure, w.peerVersion
	localHost := "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256"
	if server {
		switch host.Public().(type) {
		case ed25519.PublicKey:
			localHost = "ssh-ed25519"
		case *rsa.PublicKey:
			localHost = "rsa-sha2-512,rsa-sha2-256"
		case *ecdsa.PublicKey:
			curve, _, err := sshECDSA(host.Public().(*ecdsa.PublicKey).Curve)
			if err != nil {
				return err
			}
			localHost = "ecdsa-sha2-" + curve
		}
	}
	ownInit := sshKexInit(localHost)
	if err = w.writePacket(ownInit); err != nil {
		return
	}
	if peerInit == nil {
		for {
			peerInit, err = w.next()
			if err != nil {
				return
			}
			if peerInit[0] == 20 {
				break
			}
			total := len(peerInit)
			for _, b := range w.deferred {
				total += len(b)
			}
			if total > 4<<20 {
				return errors.New("SSH pre-key-exchange queue limit exceeded")
			}
			w.deferred = append(w.deferred, peerInit)
		}
	}
	ours, _, _ := sshAlgorithms(ownInit)
	theirs, guess, err := sshAlgorithms(peerInit)
	if err != nil {
		return
	}
	client, serv := ours, theirs
	vc, vs, ic, is := sshVersion, peer, ownInit, peerInit
	if server {
		client, serv = theirs, ours
		vc, vs, ic, is = peer, sshVersion, peerInit, ownInit
	}
	var selected [8]string
	for i := range selected {
		selected[i] = sshChoose(client[i], serv[i])
		if selected[i] == "" {
			return fmt.Errorf("SSH has no common algorithm at index %d", i)
		}
	}
	if guess && (strings.Split(theirs[0], ",")[0] != selected[0] || strings.Split(theirs[1], ",")[0] != selected[1]) {
		if _, err = w.next(); err != nil {
			return
		}
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	ownPub := private.PublicKey().Bytes()
	var qc, qs, hostKey, sig, secret []byte
	if !server {
		if err = w.writePacket(sshString([]byte{30}, ownPub)); err != nil {
			return
		}
		b, e := w.next()
		if e != nil {
			return e
		}
		r := sshReader{b: b}
		v := r.take(1)
		hostKey = r.str()
		qs = r.str()
		sig = r.str()
		if r.err != nil || len(r.b) != 0 || v[0] != 31 || len(qs) != 32 {
			return errors.New("invalid SSH key exchange reply")
		}
		qc = ownPub
		pub, e := ecdh.X25519().NewPublicKey(qs)
		if e != nil {
			return e
		}
		secret, err = private.ECDH(pub)
	} else {
		b, e := w.next()
		if e != nil {
			return e
		}
		r := sshReader{b: b}
		v := r.take(1)
		qc = r.str()
		if r.err != nil || len(r.b) != 0 || v[0] != 30 || len(qc) != 32 {
			return errors.New("invalid SSH key exchange request")
		}
		qs = ownPub
		pub, e := ecdh.X25519().NewPublicKey(qc)
		if e != nil {
			return e
		}
		secret, err = private.ECDH(pub)
		if err != nil {
			return
		}
		hostKey, err = sshPubKey(host.Public())
	}
	if err != nil {
		return
	}
	k := sshMPInt(secret)
	exchange := sshText(nil, vc)
	exchange = sshText(exchange, vs)
	exchange = sshString(exchange, ic)
	exchange = sshString(exchange, is)
	exchange = sshString(exchange, hostKey)
	exchange = sshString(exchange, qc)
	exchange = sshString(exchange, qs)
	exchange = append(exchange, k...)
	h := sha256.Sum256(exchange)
	if len(w.sessionID) == 0 {
		w.sessionID = append([]byte{}, h[:]...)
	}
	if server {
		sig, err = sshSign(host, selected[1], h[:])
		if err != nil {
			return
		}
		reply := sshString(sshString(sshString([]byte{31}, hostKey), qs), sig)
		if err = w.writePacket(reply); err != nil {
			return
		}
	} else {
		if !insecure && !sshPinned(hostKey, pins) {
			return errors.New("SSH host key does not match configured host_key")
		}
		if err = sshVerify(hostKey, selected[1], h[:], sig); err != nil {
			return
		}
	}
	derive := func(letter byte, n int) []byte {
		seed := append(append(append([]byte{}, k...), h[:]...), letter)
		seed = append(seed, w.sessionID...)
		sum := sha256.Sum256(seed)
		return sum[:n]
	}
	direction := byte(0)
	if server {
		direction = 1
	}
	wc, _ := aes.NewCipher(derive('C'+direction, 16))
	rc, _ := aes.NewCipher(derive('D'-direction, 16))
	writeCipher := sshCipher{stream: cipher.NewCTR(wc, derive('A'+direction, 16)), key: derive('E'+direction, 32)}
	readCipher := sshCipher{stream: cipher.NewCTR(rc, derive('B'-direction, 16)), key: derive('F'-direction, 32)}
	if err = w.writePacket([]byte{21}); err != nil {
		return
	}
	w.writeCipher = writeCipher
	b, err := w.next()
	if err != nil {
		return
	}
	if len(b) != 1 || b[0] != 21 {
		return errors.New("SSH NEWKEYS required")
	}
	w.readCipher = readCipher
	w.read = 0
	w.written.Store(0)
	return nil
}
