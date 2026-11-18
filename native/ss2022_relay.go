package native

import (
	"crypto/aes"
	"errors"
	"io"
	"net"
	"time"
)

type ShadowsocksDestination struct {
	Name       string `json:"name,omitempty"`
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
	Password   string `json:"password"`
}

func ss2022RelayTCP(key *ssKey, initial []byte) (*ssKey, []byte, error) {
	size := len(key.master)
	if len(initial) < size+16+27 {
		return nil, nil, errors.New("incomplete Shadowsocks2022 relay initial header")
	}
	block, _ := aes.NewCipher(ss2022Derive(key.master, initial[:size], true))
	var id [16]byte
	block.Decrypt(id[:], initial[size:size+16])
	next := key.users[id]
	if next == nil {
		return nil, nil, errors.New("unknown Shadowsocks2022 relay identity")
	}
	copy(initial[size:], initial[size+16:])
	return next, initial[:len(initial)-16], nil
}

func (r *Runtime) serveSS2022Relay(in Inbound, raw net.Conn, q request) error {
	var remote net.Conn
	err := func() error {
		owner := buffers.Get().(*[32 * 1024]byte)
		defer buffers.Put(owner)
		buffer := owner[:]
		// Preserve the one-read/one-write initial flight used by the final server.
		n, err := raw.Read(buffer)
		if err != nil {
			return err
		}
		key := r.keys["in:"+in.Tag]
		next, initial, err := ss2022RelayTCP(key, buffer[:n])
		if err != nil {
			return err
		}
		// Only the final server can authenticate the body before claiming its salt.
		q.address, q.metadata.AuthUser = next.relayAddress, next.userName
		remote, err = r.routeDial(r.ctx, q)
		if err != nil {
			return err
		}
		n, err = remote.Write(initial)
		r.up.Add(int64(n))
		if err == nil && n != len(initial) {
			err = io.ErrShortWrite
		}
		if err != nil {
			remote.Close()
		}
		return err
	}()
	if err != nil {
		return err
	}
	r.relay(raw, remote)
	return nil
}

func ss2022RelayPacket(key *ssKey, packet []byte) (*ssKey, []byte, error) {
	if len(packet) < 66 || len(packet) > 65507 {
		return nil, nil, errors.New("invalid Shadowsocks2022 relay datagram length")
	}
	key.udpBlock.Decrypt(packet[:16], packet[:16])
	key.udpBlock.Decrypt(packet[16:32], packet[16:32])
	for i := range 16 {
		packet[16+i] ^= packet[i]
	}
	next := key.users[[16]byte(packet[16:32])]
	if next == nil {
		return nil, nil, errors.New("unknown Shadowsocks2022 relay identity")
	}
	next.udpBlock.Encrypt(packet[16:32], packet[:16])
	return next, packet[16:], nil
}

func (r *Runtime) serveSS2022RelayPackets(in Inbound, packets net.PacketConn) {
	key := r.keys["in:"+in.Tag]
	flows := newUDPFlows(r)
	flows.timeout, _ = optionDuration(in.UDPTimeout, time.Minute)
	defer flows.Close()
	buffer := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(buffer)
	for {
		n, peer, err := packets.ReadFrom(buffer)
		if err != nil {
			return
		}
		next, packet, err := ss2022RelayPacket(key, buffer[:n])
		if err != nil {
			continue
		}
		q := request{origin: r.socketOrigin(peer, packets.LocalAddr()), network: "udp", address: next.relayAddress, inbound: in.Tag, source: peer.String(), metadata: Metadata{AuthUser: next.userName}}
		// The final server authenticates the body. Unverified IDs must not move a peer.
		flowKey := string(next.master) + peer.String()
		_ = flows.send(flowKey, q, packet, func(b []byte, _ string) error {
			_, err := packets.WriteTo(b, peer)
			return err
		})
	}
}
