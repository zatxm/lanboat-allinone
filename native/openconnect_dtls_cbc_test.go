package native

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"testing"
)

func ocCBCPair(t testing.TB, suite uint16, etm bool) (*ocDTLS, *ocDTLS) {
	t.Helper()
	c := &ocDTLS{client: true, suite: suite, psk: bytes.Repeat([]byte{7}, 32), writeEpoch: 1, etm: etm, ccs: true}
	s := &ocDTLS{suite: suite, psk: bytes.Clone(c.psk), writeEpoch: 1, etm: etm, ccs: true}
	for _, d := range []*ocDTLS{c, s} {
		if err := d.keys(); err != nil {
			t.Fatal(err)
		}
	}
	return c, s
}

// Independent record encoding uses the standard CBC and HMAC APIs as oracle.
func ocCBCOracle(c *ocDTLS, plain []byte, padding int, corruptPadding, corruptMAC bool) []byte {
	header := ocDTLSRecordHeader(23, 1, c.writeSeq, 0)
	c.writeSeq++
	fragment := bytes.Repeat([]byte{0x81}, 16)
	fragment = append(fragment, plain...)
	mac := func(data []byte) []byte {
		x := c.cbc.writeMAC
		x.Reset()
		x.Write(header[3:11])
		x.Write(header[:3])
		x.Write(binary.BigEndian.AppendUint16(nil, uint16(len(data))))
		x.Write(data)
		return x.Sum(nil)
	}
	if !c.etm {
		tag := mac(plain)
		if corruptMAC {
			tag[0] ^= 1
		}
		fragment = append(fragment, tag...)
	}
	for range padding {
		fragment = append(fragment, byte(padding-1))
	}
	if corruptPadding {
		fragment[len(fragment)-2] ^= 1
	}
	cipher.NewCBCEncrypter(c.cbc.writeKey, fragment[:16]).CryptBlocks(fragment[16:], fragment[16:])
	if c.etm {
		tag := mac(fragment)
		if corruptMAC {
			tag[0] ^= 1
		}
		fragment = append(fragment, tag...)
	}
	binary.BigEndian.PutUint16(header[11:], uint16(len(fragment)))
	return append(header, fragment...)
}

func TestOpenConnectCBCPadding(t *testing.T) {
	for _, spec := range ocDTLSSuites {
		if !ocDTLSIsCBC(spec.id) {
			continue
		}
		for _, etm := range []bool{false, true} {
			mode := "MtE"
			if etm {
				mode = "EtM"
			}
			t.Run(spec.name+"/"+mode, func(t *testing.T) {
				c, s := ocCBCPair(t, spec.id, etm)
				for padding := 1; padding <= 256; padding++ {
					size := 16 - padding%16
					if !etm {
						size = (32 - (padding+c.cbc.writeMAC.Size())%16) % 16
					}
					plain := bytes.Repeat([]byte{9}, size)
					for _, corrupt := range [][2]bool{{true, false}, {false, true}, {false, false}} {
						if padding < 2 && corrupt[0] {
							continue
						}
						wire := ocCBCOracle(c, plain, padding, corrupt[0], corrupt[1])
						_, got, ok := s.open(wire)
						valid := !corrupt[0] && !corrupt[1]
						if ok != valid || valid && !bytes.Equal(got, plain) {
							t.Fatal("padding/MAC authentication", padding, corrupt, ok)
						}
						if !ok && bytes.Count(s.plain, []byte{0}) != len(s.plain) {
							t.Fatal("unauthenticated plaintext retained")
						}
						if valid {
							if _, _, replay := s.open(wire); replay {
								t.Fatal("CBC replay accepted")
							}
						}
					}
				}
				for size := range 81 {
					wire := ocDTLSRecordHeader(23, 1, c.writeSeq, size)
					wire = append(wire, bytes.Repeat([]byte{3}, size)...)
					if _, _, ok := s.open(wire); ok {
						t.Fatal("malformed CBC accepted", size)
					}
				}
			})
		}
	}
}

func TestOpenConnectCBCEtMNegotiation(t *testing.T) {
	for _, suites := range [][]uint16{{0x00a8}, {0x008c}, {0x00a8, 0x00af}} {
		c := &ocDTLS{client: true, suites: suites, appID: bytes.Repeat([]byte{1}, 32)}
		_, _, _, _, flags, err := ocDTLSClientHello(c.hello(nil))
		if err != nil || !flags.ems || flags.etm != (len(suites) > 1 || suites[0] == 0x008c) {
			t.Fatal("client EtM offer", suites, flags, err)
		}
		for _, suite := range suites {
			body := append([]byte{0xfe, 0xfd}, make([]byte, 32)...)
			body = binary.BigEndian.AppendUint16(append(body, 0), suite)
			body = ocDTLSAppendExtensions(append(body, 0), true, true)
			err := c.message(2, body, nil)
			if (err == nil) != ocDTLSIsCBC(suite) {
				t.Fatal("invalid EtM negotiation", suites, suite, err)
			}
			c.stage = 0
		}
	}
	for _, ext := range [][]byte{{0, 5, 0, 22, 0, 1, 0}, {0, 8, 0, 22, 0, 0, 0, 22, 0, 0}} {
		if _, err := ocDTLSExtensions(ext); err == nil {
			t.Fatal("bad EtM extension accepted")
		}
	}
}

func TestOpenConnectCBCIVAndStandardDecrypt(t *testing.T) {
	for _, spec := range ocDTLSSuites {
		if !ocDTLSIsCBC(spec.id) {
			continue
		}
		for _, etm := range []bool{false, true} {
			c, s := ocCBCPair(t, spec.id, etm)
			var previous [16]byte
			for _, size := range []int{0, 1, 15, 16, 17, 127, 1280, 16384} {
				plain := bytes.Repeat([]byte{1}, size)
				wire, err := c.record(23, plain)
				if err != nil {
					t.Fatal(err)
				}
				iv := [16]byte(wire[13:29])
				if iv == previous {
					t.Fatal("explicit CBC IV reused")
				}
				previous = iv
				end := len(wire)
				if etm {
					end -= s.cbc.readMAC.Size()
					var tag [48]byte
					ocDTLSCBCMAC(s.cbc.readMAC, wire, wire[13:end], tag[:0])
					if !hmac.Equal(tag[:s.cbc.readMAC.Size()], wire[end:]) {
						t.Fatal("EtM tag mismatch")
					}
				}
				decrypted := bytes.Clone(wire[29:end])
				cipher.NewCBCDecrypter(s.cbc.readKey, iv[:]).CryptBlocks(decrypted, decrypted)
				if !bytes.Equal(decrypted[:size], plain) {
					t.Fatal("standard CBC decryption mismatch")
				}
				if _, got, ok := s.open(wire); !ok || !bytes.Equal(got, plain) {
					t.Fatal("CBC round trip", spec.name, etm, size)
				}
			}
		}
	}
}

func TestOpenConnectCBCPacketMTU(t *testing.T) {
	for _, spec := range ocDTLSSuites {
		if !ocDTLSIsCBC(spec.id) {
			continue
		}
		for _, etm := range []bool{false, true} {
			c, _ := ocCBCPair(t, spec.id, etm)
			for size := c.packetMTU(1180) - 15; size <= c.packetMTU(1180); size++ {
				wire, err := c.record(23, make([]byte, 1+size))
				if err != nil || len(wire)+40+8 > 1280 {
					t.Fatal("CBC exceeded conservative IPv6 path MTU", spec.name, etm, size, len(wire), err)
				}
			}
		}
	}
}

func BenchmarkOpenConnectCBCOpen(b *testing.B) {
	for _, spec := range ocDTLSSuites {
		if !ocDTLSIsCBC(spec.id) {
			continue
		}
		for _, etm := range []bool{true, false} {
			mode := "MtE"
			if etm {
				mode = "EtM"
			}
			b.Run(spec.name+"/"+mode, func(b *testing.B) {
				c, s := ocCBCPair(b, spec.id, etm)
				wire, err := c.record(23, make([]byte, 1280))
				if err != nil {
					b.Fatal(err)
				}
				b.SetBytes(1280)
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					s.window = packetWindow{}
					if _, _, ok := s.open(wire); !ok {
						b.Fatal("CBC receive failed")
					}
				}
			})
		}
	}
}
