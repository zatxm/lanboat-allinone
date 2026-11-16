package native

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func ocRekeyDuration(value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil || d < time.Second || d > 7*24*time.Hour || d%time.Second != 0 {
		return 0, errors.New("OpenConnect rekey interval requires whole seconds in1s-168h")
	}
	return d, nil
}

func ocRekeyAdvice(h http.Header, channel string) (time.Duration, string, error) {
	if len(h.Values("X-"+channel+"-Rekey-Method")) > 1 || len(h.Values("X-"+channel+"-Rekey-Time")) > 1 {
		return 0, "", errors.New("duplicate OpenConnect rekey advice")
	}
	method := strings.ToLower(strings.TrimSpace(h.Get("X-" + channel + "-Rekey-Method")))
	if method == "" || method == "none" {
		return 0, "none", nil
	}
	if method != "new-tunnel" && method != "ssl" {
		return 0, "", errors.New("unsupported OpenConnect rekey method")
	}
	n, err := strconv.ParseUint(h.Get("X-"+channel+"-Rekey-Time"), 10, 32)
	if err != nil || n < 1 || n > 7*24*3600 {
		return 0, "", errors.New("invalid OpenConnect rekey interval")
	}
	return time.Duration(n) * time.Second, method, nil
}

func (o OpenConnectOptions) rekeyHeaders() http.Header {
	h := http.Header{}
	for _, field := range []struct{ channel, value string }{{"CSTP", o.RekeyTime}, {"DTLS", o.DTLSRekeyTime}} {
		if d, _ := ocRekeyDuration(field.value); d != 0 {
			method := "new-tunnel"
			if field.channel == "CSTP" && o.RekeyMethod != "" {
				method = o.RekeyMethod
			}
			if field.channel == "DTLS" && o.DTLSRekeyMethod != "" {
				method = o.DTLSRekeyMethod
			}
			h["X-"+field.channel+"-Rekey-Method"] = []string{method}
			h["X-"+field.channel+"-Rekey-Time"] = []string{fmt.Sprint(int64(d / time.Second))}
		}
	}
	return h
}

func ocCSTPTLS(conn net.Conn) *ocTLS12 {
	for {
		if c, ok := conn.(*bufferedConn); ok {
			conn = c.Conn
			continue
		}
		if c, ok := conn.(*ocTLS12); ok {
			return c
		}
		return nil
	}
}

func ocTLSVersion(conn net.Conn) uint16 {
	for {
		if c, ok := conn.(*bufferedConn); ok {
			conn = c.Conn
			continue
		}
		if c, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
			return c.ConnectionState().Version
		}
		return 0
	}
}
