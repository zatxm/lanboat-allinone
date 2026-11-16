package native

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"io"
	"math/bits"
	"net"
	"sort"
	"strings"
	"sync"
)

func ssStreamParameters(method string) (keySize, ivSize int, ok bool) {
	for _, bits := range []struct {
		prefix string
		size   int
	}{{"aes-128-", 16}, {"aes-192-", 24}, {"aes-256-", 32}} {
		if strings.HasPrefix(method, bits.prefix) {
			switch strings.TrimPrefix(method, bits.prefix) {
			case "cfb", "cfb1", "cfb8", "ctr":
				return bits.size, 16, true
			}
		}
	}
	switch method {
	case "none", "table", "rc4":
		return 16, 0, true
	case "rc4-md5":
		return 16, 16, true
	case "rc4-md5-6":
		return 16, 6, true
	case "chacha20", "salsa20":
		return 32, 8, true
	case "chacha20-ietf":
		return 32, 12, true
	case "des-cfb":
		return 8, 8, true
	case "bf-cfb":
		return 16, 8, true
	case "cast5-cfb", "idea-cfb", "rc2-cfb":
		return 16, 8, true
	case "seed-cfb", "camellia-128-cfb":
		return 16, 16, true
	case "camellia-192-cfb":
		return 24, 16, true
	case "camellia-256-cfb":
		return 32, 16, true
	}
	return 0, 0, false
}

func newSSStreamBlock(method string, key []byte) (cipher.Block, error) {
	switch method {
	case "des-cfb":
		return des.NewCipher(key)
	case "bf-cfb":
		return newBlowfish(key)
	case "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb":
		return newCamellia(key)
	case "cast5-cfb":
		return newCAST5(key)
	case "idea-cfb":
		return newIDEA(key)
	case "rc2-cfb":
		return newRC2(key, 128), nil
	case "seed-cfb":
		return newSEED(key)
	}
	if strings.HasPrefix(method, "aes-") {
		return aes.NewCipher(key)
	}
	return nil, nil
}

func (k *ssKey) stream(iv []byte, decrypt bool) (cipher.Stream, error) {
	method := k.method
	if method == "none" {
		return &identityStream{}, nil
	}
	if method == "table" {
		table := k.tableEnc
		if decrypt {
			table = k.tableDec
		}
		return &tableStream{table: *table}, nil
	}
	if method == "rc4" || method == "rc4-md5" || method == "rc4-md5-6" {
		key := k.master
		if method != "rc4" {
			sum := md5.Sum(append(append([]byte{}, key...), iv...))
			key = sum[:]
		}
		return rc4.NewCipher(key)
	}
	if method == "chacha20" || method == "chacha20-ietf" {
		stream := &chachaStream{legacy: len(iv) == 8}
		copy(stream.key[:], k.master)
		copy(stream.nonce[:], iv)
		return stream, nil
	}
	if method == "salsa20" {
		stream := &salsaStream{}
		copy(stream.key[:], k.master)
		copy(stream.nonce[:], iv)
		return stream, nil
	}
	block := k.streamBlock
	if strings.HasSuffix(method, "-ctr") {
		return cipher.NewCTR(block, iv), nil
	}
	if strings.HasSuffix(method, "-cfb1") || strings.HasSuffix(method, "-cfb8") {
		return &feedbackStream{block: block, register: append([]byte{}, iv...), oneBit: strings.HasSuffix(method, "-cfb1"), decrypt: decrypt}, nil
	}
	if decrypt {
		return cipher.NewCFBDecrypter(block, iv), nil
	}
	return cipher.NewCFBEncrypter(block, iv), nil
}

type identityStream struct{}

func (*identityStream) XORKeyStream(dst, src []byte) { copy(dst, src) }

type tableStream struct{ table [256]byte }

func (c *tableStream) XORKeyStream(dst, src []byte) {
	for i, b := range src {
		dst[i] = c.table[b]
	}
}

func ssTable(password string) (enc, dec [256]byte) {
	for i := range enc {
		enc[i] = byte(i)
	}
	sum := md5.Sum([]byte(password))
	seed := binary.LittleEndian.Uint64(sum[:8])
	for pass := uint64(1); pass < 1024; pass++ {
		sort.SliceStable(enc[:], func(i, j int) bool { return seed%(uint64(enc[i])+pass) < seed%(uint64(enc[j])+pass) })
	}
	for i, value := range enc {
		dec[value] = byte(i)
	}
	return
}

type feedbackStream struct {
	block           cipher.Block
	register        []byte
	oneBit, decrypt bool
}

func (c *feedbackStream) XORKeyStream(dst, src []byte) {
	var encrypted [16]byte
	for i, input := range src {
		if !c.oneBit {
			c.block.Encrypt(encrypted[:], c.register)
			out := input ^ encrypted[0]
			dst[i] = out
			feedback := out
			if c.decrypt {
				feedback = input
			}
			copy(c.register, c.register[1:])
			c.register[len(c.register)-1] = feedback
			continue
		}
		var output byte
		for bit := 7; bit >= 0; bit-- {
			c.block.Encrypt(encrypted[:], c.register)
			inputBit := (input >> uint(bit)) & 1
			result := inputBit ^ (encrypted[0] >> 7)
			output |= result << uint(bit)
			feedback := result
			if c.decrypt {
				feedback = inputBit
			}
			for j := 0; j < len(c.register)-1; j++ {
				c.register[j] = c.register[j]<<1 | c.register[j+1]>>7
			}
			c.register[len(c.register)-1] = c.register[len(c.register)-1]<<1 | feedback
		}
		dst[i] = output
	}
}

type chachaStream struct {
	key     [32]byte
	nonce   [12]byte
	counter uint64
	block   [64]byte
	offset  int
	legacy  bool
}

type salsaStream struct {
	key     [32]byte
	nonce   [8]byte
	counter uint64
	block   [64]byte
	offset  int
}

func (c *salsaStream) XORKeyStream(dst, src []byte) {
	for i, input := range src {
		if c.offset == 0 {
			state := [16]uint32{0: 0x61707865, 5: 0x3320646e, 10: 0x79622d32, 15: 0x6b206574}
			for j := range 4 {
				state[1+j] = binary.LittleEndian.Uint32(c.key[j*4:])
				state[11+j] = binary.LittleEndian.Uint32(c.key[16+j*4:])
			}
			state[6] = binary.LittleEndian.Uint32(c.nonce[:4])
			state[7] = binary.LittleEndian.Uint32(c.nonce[4:])
			state[8] = uint32(c.counter)
			state[9] = uint32(c.counter >> 32)
			work := state
			quarter := func(a, b, d, e int) {
				work[b] ^= bits.RotateLeft32(work[a]+work[e], 7)
				work[d] ^= bits.RotateLeft32(work[b]+work[a], 9)
				work[e] ^= bits.RotateLeft32(work[d]+work[b], 13)
				work[a] ^= bits.RotateLeft32(work[e]+work[d], 18)
			}
			for range 10 {
				quarter(0, 4, 8, 12)
				quarter(5, 9, 13, 1)
				quarter(10, 14, 2, 6)
				quarter(15, 3, 7, 11)
				quarter(0, 1, 2, 3)
				quarter(5, 6, 7, 4)
				quarter(10, 11, 8, 9)
				quarter(15, 12, 13, 14)
			}
			for j := range state {
				binary.LittleEndian.PutUint32(c.block[j*4:], work[j]+state[j])
			}
			c.counter++
		}
		dst[i] = input ^ c.block[c.offset]
		c.offset = (c.offset + 1) & 63
	}
}

func (c *chachaStream) XORKeyStream(dst, src []byte) {
	for i, b := range src {
		if c.offset == 0 {
			if c.legacy {
				s := chachaState(&c.key)
				s[12] = uint32(c.counter)
				s[13] = uint32(c.counter >> 32)
				s[14] = binary.LittleEndian.Uint32(c.nonce[:4])
				s[15] = binary.LittleEndian.Uint32(c.nonce[4:8])
				work := s
				chachaRounds(&work, 10)
				for j := range s {
					binary.LittleEndian.PutUint32(c.block[j*4:], work[j]+s[j])
				}
			} else {
				if c.counter > uint64(^uint32(0)) {
					panic("ChaCha20 stream counter exhausted")
				}
				c.block = chachaBlock(&c.key, c.nonce[:], uint32(c.counter))
			}
			c.counter++
		}
		dst[i] = b ^ c.block[c.offset]
		c.offset = (c.offset + 1) & 63
	}
}

type ssStreamConn struct {
	net.Conn
	key               *ssKey
	readMu, writeMu   sync.Mutex
	reader, writer    cipher.Stream
	readIV, writeIV   []byte
	readErr, writeErr error
}

func (c *ssStreamConn) initRead() error {
	if c.reader != nil {
		return nil
	}
	_, size, _ := ssStreamParameters(c.key.method)
	c.readIV = make([]byte, size)
	if _, err := io.ReadFull(c.Conn, c.readIV); err != nil {
		return err
	}
	var err error
	c.reader, err = c.key.stream(c.readIV, true)
	return err
}
func (c *ssStreamConn) initWrite() error {
	if c.writer != nil {
		return nil
	}
	if c.writeIV == nil {
		_, size, _ := ssStreamParameters(c.key.method)
		c.writeIV = make([]byte, size)
		if _, err := rand.Read(c.writeIV); err != nil {
			return err
		}
	}
	var err error
	c.writer, err = c.key.stream(c.writeIV, false)
	if err == nil {
		err = writeAll(c.Conn, c.writeIV)
	}
	return err
}
func (c *ssStreamConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	if err := c.initRead(); err != nil {
		c.readErr = err
		return 0, err
	}
	n, err := c.Conn.Read(p)
	c.reader.XORKeyStream(p[:n], p[:n])
	return n, err
}
func (c *ssStreamConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if err := c.initWrite(); err != nil {
		c.writeErr = err
		return 0, err
	}
	buffer := buffers.Get().([]byte)
	defer buffers.Put(buffer)
	written := 0
	for len(p) > 0 {
		n := min(len(buffer), len(p))
		c.writer.XORKeyStream(buffer[:n], p[:n])
		if err := writeAll(c.Conn, buffer[:n]); err != nil {
			c.writeErr = err
			return written, err
		}
		p = p[n:]
		written += n
	}
	return written, nil
}
func (c *ssStreamConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func (k *ssKey) sealStreamPacket(payload []byte) ([]byte, error) {
	_, ivSize, _ := ssStreamParameters(k.method)
	packet := make([]byte, ivSize+len(payload))
	if _, err := rand.Read(packet[:ivSize]); err != nil {
		return nil, err
	}
	stream, err := k.stream(packet[:ivSize], false)
	if err != nil {
		return nil, err
	}
	stream.XORKeyStream(packet[ivSize:], payload)
	return packet, nil
}
func (k *ssKey) openStreamPacket(packet []byte) ([]byte, error) {
	_, ivSize, _ := ssStreamParameters(k.method)
	if len(packet) < ivSize {
		return nil, io.ErrUnexpectedEOF
	}
	stream, err := k.stream(packet[:ivSize], true)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(packet)-ivSize)
	stream.XORKeyStream(plain, packet[ivSize:])
	return plain, nil
}
