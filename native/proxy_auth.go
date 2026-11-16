package native

import (
	"crypto/rand"
	"net"
)

func vlessClient(conn net.Conn, o Outbound, network, address string) (net.Conn, error) {
	var err error
	id, _ := parseUUID(o.UUID)
	header := append([]byte{0}, id[:]...)
	command := byte(1)
	if network == "udp" {
		command = 2
	} else if network == "mux" {
		command = 3
	}
	if o.Flow != "" {
		header = append(header, byte(2+len(visionFlow)), 10, byte(len(visionFlow)))
		header = append(header, visionFlow...)
		header = append(header, command)
	} else {
		header = append(header, 0, command)
	}
	var destination []byte
	if command != 3 {
		destination, err = vlessAddress(address)
	}
	if err == nil {
		header = append(header, destination...)
		err = writeAll(conn, header)
	}
	conn = &vlessConn{Conn: conn}
	if err == nil && o.Flow != "" {
		conn, err = newVisionConn(conn, id)
	}
	if network == "udp" {
		conn = &streamPacketConn{Conn: conn, address: address}
	}
	return conn, err
}

func vmessClient(conn net.Conn, o Outbound, user vmessUser, network, address string) (net.Conn, error) {
	var err error
	security, _ := vmessSecurity(o.Security)
	q := vmessRequest{security: security, options: 5, command: 1, address: address, legacy: o.AlterID > 0}
	if o.GlobalPadding {
		q.options |= 8
	}
	if o.AuthenticatedLength {
		q.options |= 16
	}
	if security == 5 {
		q.options = 5
	}
	if security == 6 {
		q.options = 0
		q.security = 5
	}
	if network == "udp" {
		q.command = 2
		if security == 6 {
			q.security = 5
			q.options = 5
		}
	}
	if network == "mux" {
		q.command = 3
	}
	var random [33]byte
	_, err = rand.Read(random[:])
	if err == nil {
		copy(q.iv[:], random[:16])
		copy(q.key[:], random[16:32])
		q.response = random[32]
		err = writeVMessRequest(conn, user, q)
	}
	conn = newVMessConn(conn, q, true)
	return conn, err
}
