package native

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
)

type ocServer struct {
	key  [32]byte
	dtls *ocDTLSListener
}

func newOCServer() *ocServer { s := new(ocServer); rand.Read(s.key[:]); return s }
func (s *ocServer) cookie(user string, now time.Time) string {
	b := make([]byte, 24, 24+len(user)+32)
	binary.BigEndian.PutUint64(b, uint64(now.Add(time.Hour).Unix()))
	rand.Read(b[8:])
	b = append(b, user...)
	m := hmac.New(sha256.New, s.key[:])
	m.Write(b)
	b = append(b, m.Sum(nil)...)
	return base64.RawURLEncoding.EncodeToString(b)
}
func (s *ocServer) user(cookie string, now time.Time) string {
	if len(cookie) > 1024 {
		return ""
	}
	b, e := base64.RawURLEncoding.DecodeString(cookie)
	if e != nil || len(b) < 57 {
		return ""
	}
	data, signature := b[:len(b)-32], b[len(b)-32:]
	m := hmac.New(sha256.New, s.key[:])
	m.Write(data)
	if !hmac.Equal(signature, m.Sum(nil)) {
		return ""
	}
	expires := int64(binary.BigEndian.Uint64(data))
	if expires <= now.Unix() || expires > now.Add(time.Hour).Unix() {
		return ""
	}
	return string(data[24:])
}
func ocReply(c net.Conn, status int, h http.Header, body []byte) error {
	if h == nil {
		h = make(http.Header)
	}
	h.Set("Content-Length", fmt.Sprint(len(body)))
	h.Set("Connection", "close")
	h.Set("Cache-Control", "no-store")
	response := &http.Response{Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, StatusCode: status, Header: h, ContentLength: int64(len(body)), Body: io.NopCloser(bytes.NewReader(body)), Close: true}
	return response.Write(c)
}
func (r *Runtime) serveOpenConnect(in Inbound, c *bufferedConn) error {
	header, e := readHTTPHeader(c.reader)
	if e != nil {
		return e
	}
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(header), c.reader))
	req, e := http.ReadRequest(reader)
	if e != nil {
		return e
	}
	if req.Method == "CONNECT" && req.RequestURI == "/CSCOSSLC/tunnel" {
		cookie, e := req.Cookie("webvpn")
		user := ""
		if e == nil {
			user = r.ocServers[in.Tag].user(cookie.Value, time.Now())
		}
		valid := false
		for _, u := range in.Users {
			name := u.Username
			if name == "" {
				name = u.Name
			}
			if user != "" && name == user {
				valid = true
			}
		}
		if !valid {
			ocReply(c, 401, nil, nil)
			return errors.New("OpenConnect authentication failed")
		}
		if req.ContentLength > 0 || len(req.TransferEncoding) > 0 || req.Header.Get("X-CSTP-Version") != "1" {
			ocReply(c, 400, nil, nil)
			return errors.New("invalid CSTP CONNECT request")
		}
		mtu := 1280
		if in.MTU > 0 {
			mtu = in.MTU
		}
		if v := req.Header.Get("X-CSTP-MTU"); v != "" {
			var n int
			if _, e = fmt.Sscan(v, &n); e != nil || n < 1280 || n > 65535 {
				ocReply(c, 400, nil, nil)
				return errors.New("invalid CSTP MTU")
			}
			mtu = min(mtu, n)
		}
		h := http.Header{"X-CSTP-Version": {"1"}, "X-CSTP-MTU": {fmt.Sprint(mtu)}, "X-CSTP-DPD": {"30"}, "X-CSTP-Keepalive": {"20"}, "X-CSTP-Rekey-Method": {"none"}, "X-CSTP-Lease-Duration": {"3600"}}
		for name, values := range in.dnsHeaders() {
			h[name] = values
		}
		for name, values := range in.routeHeaders() {
			h[name] = values
		}
		var addresses []netip.Addr
		for _, p := range ocDefaultAddresses(in.Address) {
			a := p.Addr()
			addresses = append(addresses, a)
			if a.Is4() {
				h["X-CSTP-Address"] = []string{a.String()}
				h["X-CSTP-Netmask"] = []string{net.IP(net.CIDRMask(p.Bits(), 32)).String()}
			} else {
				h["X-CSTP-Address-IP6"] = []string{p.String()}
			}
		}
		t := newOCTunnel(r, &bufferedConn{Conn: c.Conn, reader: reader}, in.Tag, addresses, mtu, user, 30*time.Second)
		defer t.close()
		t.rekeyAfter, _ = ocRekeyDuration(in.RekeyTime)
		t.rekeyMethod = in.RekeyMethod
		t.dtlsRekeyAfter, _ = ocRekeyDuration(in.DTLSRekeyTime)
		t.dtlsRekeyMethod = in.DTLSRekeyMethod
		for name, values := range in.rekeyHeaders() {
			h[name] = values
		}
		if secured := ocCSTPTLS(c.Conn); t.rekeyMethod == "ssl" && (secured == nil || !secured.secure || !secured.ems) {
			t.rekeyMethod = "new-tunnel"
			h["X-CSTP-Rekey-Method"] = []string{"new-tunnel"}
		}
		if s := r.ocServers[in.Tag].dtls; s != nil {
			s.negotiate(t, in.OpenConnectOptions, req.Header, h, mtu)
		}
		if e = writeAll(c, []byte("HTTP/1.1 200 CONNECTED\r\n")); e == nil {
			e = h.Write(c)
		}
		if e == nil {
			e = writeAll(c, []byte("\r\n"))
		}
		if e != nil {
			return e
		}
		c.SetDeadline(time.Time{})
		t.run()
		return nil
	}
	if req.Method != "POST" || req.URL.Path != "/" && req.URL.Path != "/auth" {
		ocReply(c, 404, nil, nil)
		return nil
	}
	if req.ContentLength > 65536 {
		ocReply(c, 413, nil, nil)
		return errors.New("OpenConnect authentication body too large")
	}
	body, e := ocBody(req.Body)
	if e != nil {
		ocReply(c, 400, nil, nil)
		return e
	}
	var message ocXML
	if e = xml.Unmarshal(body, &message); e != nil {
		ocReply(c, 400, nil, nil)
		return errors.New("invalid OpenConnect authentication XML")
	}
	response := ocXML{Client: "vpn", Type: "auth-request", Version: "1.0", Auth: &ocAuth{ID: "main", Form: &ocForm{Method: "post", Action: "/auth", Inputs: []ocInput{{Type: "text", Name: "username", Label: "Username"}, {Type: "password", Name: "password", Label: "Password"}}, Selects: []ocSelect{{Name: "group_list", Label: "Group", Options: []ocOption{{Value: in.group(), Text: in.group(), Selected: "true"}}}}}}}
	h := http.Header{"Content-Type": {"application/xml; charset=utf-8"}}
	switch message.Type {
	case "init":
		if message.Group != "" && message.Group != in.group() {
			ocReply(c, 401, nil, nil)
			return errors.New("OpenConnect authentication failed")
		}
	case "auth-reply":
		values := map[string]string{}
		if message.Auth != nil {
			for _, f := range message.Auth.Fields {
				if _, ok := values[f.XMLName.Local]; ok {
					ocReply(c, 400, nil, nil)
					return errors.New("duplicate authentication field")
				}
				values[f.XMLName.Local] = f.Value
			}
		}
		user, password := values["username"], values["password"]
		valid := false
		for _, u := range in.Users {
			name := u.Username
			if name == "" {
				name = u.Name
			}
			match := subtle.ConstantTimeCompare([]byte(user), []byte(name)) & subtle.ConstantTimeCompare([]byte(password), []byte(u.Password))
			valid = valid || match == 1
		}
		group := message.Group
		if group == "" {
			group = values["group_list"]
		}
		if !valid || group != "" && group != in.group() {
			ocReply(c, 401, nil, nil)
			return errors.New("OpenConnect authentication failed")
		}
		token := r.ocServers[in.Tag].cookie(user, time.Now())
		response = ocXML{Client: "vpn", Type: "complete", Version: "1.0", Token: token, Auth: &ocAuth{ID: "success"}}
		h.Add("Set-Cookie", (&http.Cookie{Name: "webvpn", Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 3600}).String())
	default:
		ocReply(c, 400, nil, nil)
		return errors.New("invalid OpenConnect authentication message")
	}
	body, e = ocMarshal(response)
	if e != nil {
		return e
	}
	return ocReply(c, 200, h, body)
}
