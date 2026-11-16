package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/miekg/dns"
)

type record struct {
	Text       string `json:"text"`
	Type       uint16 `json:"type"`
	Class      uint16 `json:"class"`
	TTL        uint32 `json:"ttl"`
	Data       string `json:"data"`
	Compressed string `json:"compressed"`
}

func main() {
	var records []record
	check(json.NewDecoder(os.Stdin).Decode(&records))
	for i := range records {
		v := &records[i]
		rr, err := dns.NewRR(v.Text)
		if err != nil {
			panic(fmt.Sprintf("%s: %v", v.Text, err))
		}
		v.Type, v.Class, v.TTL = rr.Header().Rrtype, rr.Header().Class, rr.Header().Ttl
		wire := make([]byte, 65535)
		end, err := dns.PackRR(rr, wire, 0, nil, false)
		check(err)
		length := rr.Header().Rdlength
		v.Data = hex.EncodeToString(wire[end-int(length) : end])
		m := &dns.Msg{MsgHdr: dns.MsgHdr{Id: 17, Response: true}, Compress: true,
			Question: []dns.Question{{Name: rr.Header().Name, Qtype: v.Type, Qclass: v.Class}}, Answer: []dns.RR{rr}}
		wire, err = m.Pack()
		check(err)
		if binary.BigEndian.Uint16(wire[6:]) != 1 {
			panic("missing answer")
		}
		v.Compressed = hex.EncodeToString(wire)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	check(encoder.Encode(records))
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
