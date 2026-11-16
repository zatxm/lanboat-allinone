package main

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/tsnet"
)

// An actual upstream tsnet DNS endpoint, separate from the product implementation.
func dnsReferenceReply(q []byte, tcp bool) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		return nil
	}
	question, err := p.Question()
	if err != nil {
		return nil
	}
	name := strings.ToLower(question.Name.String())
	h.Response = true
	h.RecursionAvailable = true
	if strings.HasPrefix(name, "missing.") {
		h.RCode = dnsmessage.RCodeNameError
	}
	if strings.HasPrefix(name, "trunc.") && !tcp {
		h.Truncated = true
	}
	b := dnsmessage.NewBuilder(nil, h)
	b.EnableCompression()
	if b.StartQuestions() != nil || b.Question(question) != nil {
		return nil
	}
	if h.RCode == 0 && !h.Truncated {
		b.StartAnswers()
		rh := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}
		switch question.Type {
		case dnsmessage.TypeA:
			b.AResource(rh, dnsmessage.AResource{A: [4]byte{192, 0, 2, 42}})
		case dnsmessage.TypeAAAA:
			b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42}})
		case dnsmessage.TypeTXT:
			b.TXTResource(rh, dnsmessage.TXTResource{TXT: []string{"tailnet-private"}})
		}
	}
	out, _ := b.Finish()
	return out
}
func startDNSReference(s *tsnet.Server, ips []netip.Addr) error {
	for _, ip := range ips {
		if err := startDNSPacketReference(s, ip); err != nil {
			return err
		}
	}
	tcp, err := s.Listen("tcp", ":5353")
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var size [2]byte
				if _, err := io.ReadFull(c, size[:]); err != nil {
					return
				}
				q := make([]byte, int(binary.BigEndian.Uint16(size[:])))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				b := dnsReferenceReply(q, true)
				c.Write(binary.BigEndian.AppendUint16(nil, uint16(len(b))))
				c.Write(b)
			}()
		}
	}()
	httpListener, err := s.Listen("tcp", ":5354")
	if err != nil {
		return err
	}
	go http.Serve(httpListener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, err := io.ReadAll(io.LimitReader(r.Body, 65536))
		if err != nil || len(q) > 65535 {
			http.Error(w, "invalid query", 400)
			return
		}
		b := dnsReferenceReply(q, true)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(b)
	}))
	return nil
}
func startDNSPacketReference(s *tsnet.Server, ip netip.Addr) error {
	udp, err := s.ListenPacket("udp", net.JoinHostPort(ip.String(), "5353"))
	if err != nil {
		return err
	}
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			if reply := dnsReferenceReply(b[:n], false); reply != nil {
				udp.WriteTo(reply, a)
			}
		}
	}()
	return nil
}
