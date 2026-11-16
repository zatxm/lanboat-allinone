package main

import (
	"encoding/base64"
	"fmt"
	"github.com/enfein/mieru/v3/apis/trafficpattern"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/log"
	"github.com/enfein/mieru/v3/pkg/protocol"
	"github.com/enfein/mieru/v3/pkg/socks5"
	"google.golang.org/protobuf/proto"
	"net"
	"os"
	"strconv"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 4 {
		return fmt.Errorf("usage: reference server|client tcp|udp endpoint [local-socks] [low-entropy-mode]")
	}
	log.SetLevel("debug")
	server := os.Args[1] == "server"
	network, address := os.Args[2], os.Args[3]
	var local, remote net.Addr
	transport := common.StreamTransport
	if network == "udp" {
		transport = common.PacketTransport
		a, e := net.ResolveUDPAddr("udp", address)
		if e != nil {
			return e
		}
		if server {
			local = a
		} else {
			remote = a
		}
	} else {
		a, e := net.ResolveTCPAddr("tcp", address)
		if e != nil {
			return e
		}
		if server {
			local = a
		} else {
			remote = a
		}
	}
	m := protocol.NewMux(!server).SetEndpoints([]protocol.UnderlayProperties{protocol.NewUnderlayProperties(1400, transport, local, remote)})
	defer m.Close()
	if len(os.Args) > 5 {
		n, e := strconv.Atoi(os.Args[5])
		if e != nil {
			return e
		}
		pattern, e := trafficpattern.NewConfig(&pb.TrafficPattern{LowEntropy: &pb.LowEntropyPattern{Mode: pb.LowEntropyMode(n).Enum()}})
		if e != nil {
			return e
		}
		m.SetTrafficPattern(pattern)
	}
	if len(os.Args) > 6 && os.Args[6] != "" {
		raw, e := base64.StdEncoding.DecodeString(os.Args[6])
		if e != nil {
			return e
		}
		var p pb.TrafficPattern
		if e = proto.Unmarshal(raw, &p); e != nil {
			return e
		}
		cfg, e := trafficpattern.NewConfig(&p)
		if e != nil {
			return e
		}
		m.SetTrafficPattern(cfg)
	}
	if server {
		users := map[string]*pb.User{"client": {Name: proto.String("client"), Password: proto.String("private")}}
		m.SetServerUsers(users)
		if e := m.Start(); e != nil {
			return e
		}
		s, e := socks5.New(&socks5.Config{AuthOpts: socks5.Auth{ClientSideAuthentication: true}, Users: users, AllowLoopbackDestination: true})
		if e != nil {
			return e
		}
		fmt.Fprintln(os.Stderr, "ready")
		return s.Serve(m)
	}
	m.SetClientUserNamePassword("client", cipher.HashPassword([]byte("private"), []byte("client"))).SetClientMultiplexFactor(2)
	s, e := socks5.New(&socks5.Config{UseProxy: true, ProxyDialer: m, AuthOpts: socks5.Auth{ClientSideAuthentication: true}, AllowLoopbackDestination: true})
	if e != nil {
		return e
	}
	listener, e := net.Listen("tcp", os.Args[4])
	if e != nil {
		return e
	}
	fmt.Fprintln(os.Stderr, "ready")
	return s.Serve(listener)
}
