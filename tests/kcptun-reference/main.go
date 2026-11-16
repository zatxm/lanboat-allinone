package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/golang/snappy"
	"github.com/klauspost/reedsolomon"
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/pbkdf2"
)

func crypt(method, password string) kcp.BlockCrypt {
	key := pbkdf2.Key([]byte(password), []byte("kcp-go"), 4096, 32, sha1.New)
	construct := map[string]func([]byte) (kcp.BlockCrypt, error){"none": kcp.NewNoneBlockCrypt, "aes": kcp.NewAESBlockCrypt, "salsa20": kcp.NewSalsa20BlockCrypt, "blowfish": kcp.NewBlowfishBlockCrypt, "twofish": kcp.NewTwofishBlockCrypt, "cast5": kcp.NewCast5BlockCrypt, "3des": kcp.NewTripleDESBlockCrypt, "tea": kcp.NewTEABlockCrypt, "xtea": kcp.NewXTEABlockCrypt, "xor": kcp.NewSimpleXORBlockCrypt}
	var c kcp.BlockCrypt
	var err error
	switch method {
	case "aes-128":
		c, err = kcp.NewAESBlockCrypt(key[:16])
	case "aes-192":
		c, err = kcp.NewAESBlockCrypt(key[:24])
	case "aes-128-gcm":
		c, err = kcp.NewAESGCMCrypt(key[:16])
	case "aes-192-gcm":
		c, err = kcp.NewAESGCMCrypt(key[:24])
	case "aes-256-gcm":
		c, err = kcp.NewAESGCMCrypt(key)
	default:
		if method == "cast5" {
			key = key[:16]
		}
		if method == "3des" {
			key = key[:24]
		}
		if method == "tea" || method == "xtea" {
			key = key[:16]
		}
		c, err = construct[method](key)
	}
	if err != nil {
		panic(err)
	}
	return c
}

type compressed struct {
	net.Conn
	r  *snappy.Reader
	w  *snappy.Writer
	mu sync.Mutex
}

func (c *compressed) Read(b []byte) (int, error) { return c.r.Read(b) }
func (c *compressed) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, e := c.w.Write(b)
	if e == nil {
		e = c.w.Flush()
	}
	return n, e
}
func main() {
	mode := flag.String("mode", "server", "")
	listen := flag.String("listen", "127.0.0.1:0", "")
	target := flag.String("target", "", "")
	method := flag.String("crypt", "aes", "")
	password := flag.String("key", "private", "")
	version := flag.Int("version", 1, "")
	comp := flag.Bool("compress", false, "")
	data := flag.Int("data", 10, "")
	parity := flag.Int("parity", 3, "")
	flag.Parse()
	if *mode == "oracle" {
		in := json.NewDecoder(bufio.NewReader(os.Stdin))
		out := json.NewEncoder(os.Stdout)
		for {
			var q struct {
				Method, Password, Plain, Encrypted string
				Snappy, Unsnappy                   string
				Shards                             [][]byte
				Data, Parity                       int
			}
			if e := in.Decode(&q); e != nil {
				return
			}
			if q.Snappy != "" {
				b, e := hex.DecodeString(q.Snappy)
				if e != nil {
					panic(e)
				}
				var wire bytes.Buffer
				w := snappy.NewBufferedWriter(&wire)
				w.Write(b)
				w.Close()
				out.Encode(map[string]string{"wire": hex.EncodeToString(wire.Bytes())})
				continue
			}
			if q.Unsnappy != "" {
				b, _ := hex.DecodeString(q.Unsnappy)
				data, e := io.ReadAll(snappy.NewReader(bytes.NewReader(b)))
				if e != nil {
					out.Encode(map[string]string{"error": e.Error()})
				} else {
					out.Encode(map[string]string{"plain": hex.EncodeToString(data)})
				}
				continue
			}
			if q.Data != 0 {
				rs, e := reedsolomon.New(q.Data, q.Parity)
				if e != nil {
					panic(e)
				}
				if e = rs.Encode(q.Shards); e != nil {
					panic(e)
				}
				out.Encode(q.Shards)
				continue
			}
			c := crypt(q.Method, q.Password)
			if q.Plain != "" {
				b, _ := hex.DecodeString(q.Plain)
				d := make([]byte, len(b))
				if a, ok := c.(cipher.AEAD); ok {
					n := a.NonceSize()
					packet := make([]byte, len(b), len(b)+a.Overhead())
					copy(packet, b)
					d = a.Seal(packet[:n], packet[:n], packet[n:], nil)
				} else {
					c.Encrypt(d, b)
				}
				out.Encode(map[string]string{"encrypted": hex.EncodeToString(d)})
			} else {
				b, _ := hex.DecodeString(q.Encrypted)
				d := make([]byte, len(b))
				if a, ok := c.(cipher.AEAD); ok {
					n := a.NonceSize()
					data, e := a.Open(b[n:n], b[:n], b[n:], nil)
					if e != nil {
						panic(e)
					}
					d = append(append([]byte(nil), b[:n]...), data...)
				} else {
					c.Decrypt(d, b)
				}
				out.Encode(map[string]string{"plain": hex.EncodeToString(d)})
			}
		}
	}
	setup := func(conn *kcp.UDPSession, client bool) *smux.Session {
		conn.SetStreamMode(true)
		conn.SetNoDelay(1, 20, 2, 1)
		conn.SetWindowSize(1024, 1024)
		conn.SetMtu(1350)
		var raw net.Conn = conn
		if *comp {
			raw = &compressed{Conn: conn, r: snappy.NewReader(conn), w: snappy.NewBufferedWriter(conn)}
		}
		cfg := smux.DefaultConfig()
		cfg.Version = *version
		cfg.MaxReceiveBuffer = 4 << 20
		cfg.MaxStreamBuffer = 64 << 10
		var s *smux.Session
		var e error
		if client {
			s, e = smux.Client(raw, cfg)
		} else {
			s, e = smux.Server(raw, cfg)
		}
		if e != nil {
			panic(e)
		}
		return s
	}
	forward := func(a, b net.Conn) {
		defer a.Close()
		defer b.Close()
		done := make(chan struct{})
		go func() { io.Copy(a, b); a.Close(); close(done) }()
		io.Copy(b, a)
		b.Close()
		<-done
	}
	if *mode == "server" {
		l, e := kcp.ListenWithOptions(*listen, crypt(*method, *password), *data, *parity)
		if e != nil {
			panic(e)
		}
		fmt.Println(l.Addr())
		for {
			conn, e := l.AcceptKCP()
			if e != nil {
				return
			}
			go func() {
				s := setup(conn, false)
				defer s.Close()
				for {
					stream, e := s.AcceptStream()
					if e != nil {
						return
					}
					go func() {
						to, e := net.DialTimeout("tcp", *target, time.Second*5)
						if e != nil {
							stream.Close()
							return
						}
						forward(stream, to)
					}()
				}
			}()
		}
	}
	conn, e := kcp.DialWithOptions(*target, crypt(*method, *password), *data, *parity)
	if e != nil {
		panic(e)
	}
	s := setup(conn, true)
	l, e := net.Listen("tcp", *listen)
	if e != nil {
		panic(e)
	}
	fmt.Println(l.Addr())
	for {
		in, e := l.Accept()
		if e != nil {
			return
		}
		go func() {
			stream, e := s.OpenStream()
			if e != nil {
				in.Close()
				return
			}
			forward(in, stream)
		}()
	}
}
