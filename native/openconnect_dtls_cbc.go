package native

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
)

type ocDTLSCBC struct {
	readKey, writeKey cipher.Block
	readMAC, writeMAC hash.Hash
	verify            ocCBCMAC
}

func ocDTLSIsCBC(suite uint16) bool {
	return suite == 0x008c || suite == 0x008d || suite == 0x00ae || suite == 0x00af
}

func (d *ocDTLS) packetMTU(mtu int) int {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if d.cbc != nil {
		// Reserve CBC's explicit IV, MAC and full padding block beyond AEAD's24B.
		return mtu - (2*d.cbc.writeKey.BlockSize() + d.cbc.writeMAC.Size() - 24)
	}
	return mtu
}

func (d *ocDTLS) cbcKeys(block []byte, keySize int, newMAC func() hash.Hash) {
	size := newMAC().Size()
	clientMAC, serverMAC := block[:size], block[size:size*2]
	newCipher := aes.NewCipher
	if d.resume != nil && d.resume.suite == 0x000a {
		newCipher = des.NewTripleDESCipher
	}
	clientKey, _ := newCipher(block[size*2 : size*2+keySize])
	serverKey, _ := newCipher(block[size*2+keySize : size*2+keySize*2])
	if !d.client {
		clientMAC, serverMAC = serverMAC, clientMAC
		clientKey, serverKey = serverKey, clientKey
	}
	d.cbc = &ocDTLSCBC{
		writeKey: clientKey, readKey: serverKey,
		writeMAC: hmac.New(newMAC, clientMAC), readMAC: hmac.New(newMAC, serverMAC),
		verify: newOCCBCMAC(serverMAC, size),
	}
}

func ocDTLSCBCSpec(suite uint16) (int, func() hash.Hash) {
	switch suite {
	case 0x008c:
		return 16, sha1.New
	case 0x008d:
		return 32, sha1.New
	case 0x00ae:
		return 16, sha256.New
	case 0x00af:
		return 32, sha512.New384
	}
	return 0, nil
}

func ocDTLSCBCMAC(mac hash.Hash, header, data []byte, dst []byte) []byte {
	var aad [13]byte
	copy(aad[:8], header[3:11])
	copy(aad[8:11], header[:3])
	binary.BigEndian.PutUint16(aad[11:], uint16(len(data)))
	mac.Reset()
	mac.Write(aad[:])
	mac.Write(data)
	return mac.Sum(dst)
}

func (d *ocDTLS) sealCBC(header, data []byte) ([]byte, error) {
	c := d.cbc
	size, blockSize := c.writeMAC.Size(), c.writeKey.BlockSize()
	pad := blockSize - (len(data)+size)%blockSize
	if d.etm {
		pad = blockSize - len(data)%blockSize
	}
	var tag [48]byte
	if !d.etm {
		ocDTLSCBCMAC(c.writeMAC, header, data, tag[:0])
	}
	b := append(header, make([]byte, blockSize)...)
	rand.Read(b[13 : 13+blockSize])
	b = append(b, data...)
	if !d.etm {
		b = append(b, tag[:size]...)
	}
	for range pad {
		b = append(b, byte(pad-1))
	}
	ocDTLSCBCEncrypt(c.writeKey, b[13:13+blockSize], b[13+blockSize:])
	if d.etm {
		ocDTLSCBCMAC(c.writeMAC, b, b[13:], tag[:0])
		b = append(b, tag[:size]...)
	}
	binary.BigEndian.PutUint16(b[11:], uint16(len(b)-13))
	d.writeBuffer = b[:0]
	return b, nil
}

func ocDTLSCBCEncrypt(key cipher.Block, iv, data []byte) {
	size := key.BlockSize()
	for i := 0; i < len(data); i += size {
		for j := range size {
			data[i+j] ^= iv[j]
		}
		key.Encrypt(data[i:i+size], data[i:i+size])
		iv = data[i : i+size]
	}
}

func ocDTLSCBCDecrypt(key cipher.Block, iv, data []byte) {
	var previous, next [16]byte
	copy(previous[:], iv)
	size := key.BlockSize()
	for i := 0; i < len(data); i += size {
		copy(next[:], data[i:i+size])
		key.Decrypt(data[i:i+size], data[i:i+size])
		for j := range size {
			data[i+j] ^= previous[j]
		}
		previous = next
	}
}

func (d *ocDTLS) openCBC(b []byte) ([]byte, bool) {
	c := d.cbc
	size, fragment := c.readMAC.Size(), b[13:]
	blockSize := c.readKey.BlockSize()
	if d.etm {
		if len(fragment) < blockSize*2+size || len(fragment) > blockSize+16384+256+size {
			return nil, false
		}
		n := len(fragment) - size
		var tag [48]byte
		ocDTLSCBCMAC(c.readMAC, b, fragment[:n], tag[:0])
		if !hmac.Equal(tag[:size], fragment[n:]) {
			return nil, false
		}
		fragment = fragment[:n]
	}
	if len(fragment) < blockSize*2 || len(fragment) > blockSize+16384+size+256 || (len(fragment)-blockSize)%blockSize != 0 {
		return nil, false
	}
	d.plain = append(d.plain[:0], fragment[blockSize:]...)
	plain := d.plain
	ocDTLSCBCDecrypt(c.readKey, fragment[:blockSize], plain)
	if d.etm {
		return ocCBCUnpad(plain, nil, nil)
	}
	var aad [13]byte
	copy(aad[:8], b[3:11])
	copy(aad[8:11], b[:3])
	return ocCBCUnpad(plain, &c.verify, aad[:])
}
