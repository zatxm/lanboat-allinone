package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"

	connectip "github.com/quic-go/connect-ip-go"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/dns/dnsmessage"
)

// Only adapt public API values; all wire encoding and decoding is upstream code.
type configurationNameserver struct {
	Priority      uint16            `json:"priority"`
	IPv4Addresses []netip.Addr      `json:"ipv4_addresses,omitempty"`
	IPv6Addresses []netip.Addr      `json:"ipv6_addresses,omitempty"`
	ServerName    string            `json:"server_name,omitempty"`
	Parameters    map[uint16][]byte `json:"parameters,omitempty"`
}
type configurationDNS struct {
	Nameservers     []configurationNameserver `json:"nameservers"`
	InternalDomains []string                  `json:"internal_domains,omitempty"`
	SearchDomains   []string                  `json:"search_domains,omitempty"`
}
type configurationMessage struct {
	Event  string              `json:"event,omitempty"`
	DNS    *[]configurationDNS `json:"dns,omitempty"`
	PREF64 *[]netip.Prefix     `json:"pref64,omitempty"`
}

func upstreamDNS(configs []configurationDNS) []connectip.DNSConfiguration {
	var out []connectip.DNSConfiguration
	for _, cfg := range configs {
		item := connectip.DNSConfiguration{InternalDomains: cfg.InternalDomains, SearchDomains: cfg.SearchDomains}
		for _, ns := range cfg.Nameservers {
			params := map[dnsmessage.SVCParamKey][]byte{}
			for key, value := range ns.Parameters {
				params[dnsmessage.SVCParamKey(key)] = value
			}
			item.Nameservers = append(item.Nameservers, connectip.DNSNameserver{ServicePriority: ns.Priority, IPv4Addresses: ns.IPv4Addresses, IPv6Addresses: ns.IPv6Addresses, AuthenticationDomainName: ns.ServerName, ServiceParameters: params})
		}
		out = append(out, item)
	}
	return out
}
func fixtureDNS(configs []connectip.DNSConfiguration) []configurationDNS {
	var out []configurationDNS
	for _, cfg := range configs {
		item := configurationDNS{InternalDomains: cfg.InternalDomains, SearchDomains: cfg.SearchDomains}
		for _, ns := range cfg.Nameservers {
			params := map[uint16][]byte{}
			for key, value := range ns.ServiceParameters {
				params[uint16(key)] = value
			}
			item.Nameservers = append(item.Nameservers, configurationNameserver{Priority: ns.ServicePriority, IPv4Addresses: ns.IPv4Addresses, IPv6Addresses: ns.IPv6Addresses, ServerName: ns.AuthenticationDomainName, Parameters: params})
		}
		out = append(out, item)
	}
	return out
}

func configurationPeer(c *connectip.Conn, server bool) error {
	call, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); c.Close(); workers.Wait() }()
	var output sync.Mutex
	emit := func(value configurationMessage) {
		output.Lock()
		defer output.Unlock()
		json.NewEncoder(os.Stdout).Encode(value)
	}
	workers.Go(func() {
		for {
			cfg, err := c.ReceiveDNSConfiguration(call)
			if err != nil {
				return
			}
			value := fixtureDNS(cfg)
			emit(configurationMessage{Event: "dns", DNS: &value})
		}
	})
	workers.Go(func() {
		for {
			prefixes, err := c.ReceivePREF64Configuration(call)
			if err != nil {
				return
			}
			emit(configurationMessage{Event: "pref64", PREF64: &prefixes})
		}
	})
	if server {
		if err := c.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("10.44.0.2/32"), netip.MustParsePrefix("fd44::2/128")}); err != nil {
			return err
		}
		if err := c.AdvertiseRoute([]connectip.IPRoute{{StartIP: netip.IPv4Unspecified(), EndIP: netip.MustParseAddr("255.255.255.255")}, {StartIP: netip.IPv6Unspecified(), EndIP: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")}}); err != nil {
			return err
		}
	}
	emit(configurationMessage{Event: "ready"})
	fmt.Fprintln(os.Stderr, "ready")
	decoder := json.NewDecoder(os.Stdin)
	for {
		var command configurationMessage
		if err := decoder.Decode(&command); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if command.DNS != nil {
			if err := c.SendDNSConfiguration(upstreamDNS(*command.DNS)); err != nil {
				return err
			}
		}
		if command.PREF64 != nil {
			if err := c.SendPREF64Configuration(*command.PREF64); err != nil {
				return err
			}
		}
	}
}

func configurationClient(address string) error {
	t := &connectip.Transport{TLSClientConfig: tlsClient()}
	req, err := connectip.NewRequest(ctx, uritemplate.MustNew("https://"+address+"/.well-known/masque/ip/*/*/"))
	if err != nil {
		return err
	}
	req.Header().Set("Proxy-Authorization", "Basic Y2xpZW50OnByaXZhdGU=")
	c, _, err := t.Dial(req)
	if err != nil {
		return err
	}
	return configurationPeer(c, false)
}
func configurationServer(address, cert, key string) error {
	identity, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return err
	}
	packet, err := net.ListenPacket("udp", address)
	if err != nil {
		return err
	}
	defer packet.Close()
	proxy := &connectip.Proxy{}
	var active atomic.Bool
	server := http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{identity}}, EnableDatagrams: true, QUICConfig: &quic.Config{EnableDatagrams: true}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "Basic Y2xpZW50OnByaXZhdGU=" {
			w.WriteHeader(407)
			return
		}
		if !active.CompareAndSwap(false, true) {
			w.WriteHeader(503)
			return
		}
		defer active.Store(false)
		req, err := connectip.ParseProxyRequest(r, uritemplate.MustNew("https://"+address+"/.well-known/masque/ip/*/*/"))
		if err != nil {
			w.WriteHeader(400)
			return
		}
		c, err := proxy.Proxy(w, req)
		if err != nil {
			return
		}
		if err = configurationPeer(c, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	})}
	fmt.Fprintln(os.Stderr, "ready")
	return server.Serve(packet)
}
