package native

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"
)

// System DNS wire queries retain records that net.Resolver's typed lookup API
// cannot represent. No resolv.conf changes or external resolver process is used.
func (r *resolver) localDNSMessage(ctx context.Context, query []byte) ([]byte, error) {
	r.mu.Lock()
	servers := append([]string{}, r.systemServers...)
	r.mu.Unlock()
	if len(servers) == 0 {
		servers = r.localNetwork.snapshot().servers
	}
	if len(servers) == 0 {
		return nil, errors.New("system DNS has no configured nameserver; configure an explicit resolver")
	}
	var last error
	for i, address := range servers {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			last = e
			continue
		}
		n, e := strconv.ParseUint(port, 10, 16)
		if e != nil {
			last = e
			continue
		}
		call, cancel := ctx, func() {}
		if deadline, ok := ctx.Deadline(); ok {
			call, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(servers)-i))
		}
		reply, e := r.exchangeOn(call, DNSServer{Type: "udp", Server: host, ServerPort: uint16(n)}, query)
		cancel()
		if e != nil {
			last = e
			continue
		}
		if _, _, _, e = validateDNSQuestionResponse(query, reply); e != nil {
			last = e
			continue
		}
		return reply, nil
	}
	return nil, last
}
