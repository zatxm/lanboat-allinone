package native

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

func validACMERecord(name string) bool {
	_, err := netip.ParseAddr(strings.TrimSuffix(name, "."))
	return err != nil && validRuleDomain(strings.TrimSuffix(name, ".")) && !strings.Contains(name, "*")
}
func acmeDNSID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
func (c *acmeClient) dnsHTTP(ctx context.Context, method, address, token string, body []byte) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, method, address, strings.NewReader(string(body)))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, e := c.http.Do(req)
	if e != nil {
		return nil, errors.New("DNS01 provider HTTP request failed")
	}
	data, e := acmeResponse(resp)
	if e != nil {
		return nil, e
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("DNS01 provider returned HTTP%d", resp.StatusCode)
	}
	return data, nil
}
func (c *acmeClient) dnsResolver(server string) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if server != "" {
			address = server
			if _, _, e := net.SplitHostPort(address); e != nil {
				address = net.JoinHostPort(server, "53")
			}
		}
		// Resolver distinguishes UDP from stream framing by net.PacketConn.
		// Keep the concrete UDPConn here; its lifetime is owned by Resolver and
		// bounded by the issuance context, including runtime shutdown.
		return (&net.Dialer{Control: c.p.r.socketControl}).DialContext(ctx, network, address)
	}}
}
func (c *acmeClient) presentDNS(ctx context.Context, domain, authorization string) (func(), error) {
	options := c.p.options.DNS01Challenge
	name := "_acme-challenge." + strings.TrimPrefix(domain, "*.")
	if options.OverrideDomain != "" {
		name = strings.TrimSuffix(options.OverrideDomain, ".")
	} else {
		resolver := ""
		if len(options.Resolvers) > 0 {
			resolver = options.Resolvers[0]
		}
		query, cancel := context.WithTimeout(ctx, 5*time.Second)
		canonical, e := c.dnsResolver(resolver).LookupCNAME(query, name)
		cancel()
		if e == nil && canonical != "" {
			name = strings.TrimSuffix(canonical, ".")
		}
	}
	if !validACMERecord(name) {
		return nil, errors.New("invalid DNS01 challenge record name")
	}
	digest := sha256.Sum256([]byte(authorization))
	value := acmeB64(digest[:])
	ttl := 120
	if options.TTL != "" {
		duration, _ := time.ParseDuration(options.TTL)
		ttl = int(duration / time.Second)
	}
	var remove func(context.Context) error
	var e error
	switch options.Provider {
	case "cloudflare":
		remove, e = c.cloudflareTXT(ctx, name, value, ttl)
	case "alidns":
		remove, e = c.aliDNSTXT(ctx, name, value, ttl)
	case "acmedns":
		remove, e = c.acmeDNSTXT(ctx, name, value)
	}
	if e != nil {
		return nil, e
	}
	cleanup := func() {
		call, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if e := remove(call); e != nil {
			c.p.r.logger.Warn("DNS01 challenge cleanup failed", zap.String("provider", options.Provider), zap.Error(e))
		}
	}
	if e = c.waitTXT(ctx, name, value); e != nil {
		cleanup()
		return nil, e
	}
	return cleanup, nil
}
func (c *acmeClient) waitTXT(ctx context.Context, name, value string) error {
	o := c.p.options.DNS01Challenge
	if o.PropagationDelay != "" {
		d, _ := time.ParseDuration(o.PropagationDelay)
		if e := acmePause(ctx, d); e != nil {
			return e
		}
	}
	if o.PropagationTimeout == "-1" {
		return nil
	}
	timeout := 2 * time.Minute
	if o.PropagationTimeout != "" {
		timeout, _ = time.ParseDuration(o.PropagationTimeout)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	servers := o.Resolvers
	if len(servers) == 0 {
		servers = []string{""}
	}
	for {
		ready := true
		for _, server := range servers {
			query, done := context.WithTimeout(ctx, 5*time.Second)
			values, e := c.dnsResolver(server).LookupTXT(query, name)
			done()
			found := false
			for _, v := range values {
				if v == value {
					found = true
					break
				}
			}
			if e != nil || !found {
				ready = false
				break
			}
		}
		if ready {
			return nil
		}
		if e := acmePause(ctx, 2*time.Second); e != nil {
			return errors.New("DNS01 TXT propagation did not complete")
		}
	}
}
func (c *acmeClient) cloudflareTXT(ctx context.Context, name, value string, ttl int) (func(context.Context) error, error) {
	o := c.p.options.DNS01Challenge
	zoneToken := o.ZoneToken
	if zoneToken == "" {
		zoneToken = o.APIToken
	}
	zone := ""
	parts := strings.Split(name, ".")
	for i := 0; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		address := "https://api.cloudflare.com/client/v4/zones?" + url.Values{"name": {candidate}, "status": {"active"}, "per_page": {"50"}}.Encode()
		data, e := c.dnsHTTP(ctx, "GET", address, zoneToken, nil)
		if e != nil {
			return nil, e
		}
		var result struct {
			Success bool `json:"success"`
			Result  []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"result"`
		}
		if json.Unmarshal(data, &result) != nil || !result.Success {
			return nil, errors.New("Cloudflare DNS01 zone lookup failed")
		}
		for _, v := range result.Result {
			if strings.EqualFold(v.Name, candidate) && acmeDNSID(v.ID) {
				zone = v.ID
				break
			}
		}
		if zone != "" {
			break
		}
	}
	if zone == "" {
		return nil, errors.New("Cloudflare DNS01 zone not found")
	}
	base := "https://api.cloudflare.com/client/v4/zones/" + zone + "/dns_records"
	data, e := c.dnsHTTP(ctx, "POST", base, o.APIToken, acmeJSON(map[string]any{"type": "TXT", "name": name, "content": value, "ttl": ttl}))
	if e != nil {
		return nil, e
	}
	var result struct {
		Success bool `json:"success"`
		Result  struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if json.Unmarshal(data, &result) != nil || !result.Success || !acmeDNSID(result.Result.ID) {
		return nil, errors.New("Cloudflare DNS01 TXT creation failed")
	}
	return func(ctx context.Context) error {
		data, e := c.dnsHTTP(ctx, "DELETE", base+"/"+result.Result.ID, o.APIToken, nil)
		if e != nil {
			return e
		}
		var deleted struct {
			Success bool `json:"success"`
		}
		if json.Unmarshal(data, &deleted) != nil || !deleted.Success {
			return errors.New("Cloudflare DNS01 TXT deletion failed")
		}
		return nil
	}, nil
}
func acmeAliEscape(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }
func acmeAliSignature(values url.Values, secret string) string {
	canonical := strings.ReplaceAll(values.Encode(), "+", "%20")
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte("POST&%2F&" + acmeAliEscape(canonical)))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
func (c *acmeClient) aliDNS(ctx context.Context, action string, values url.Values) ([]byte, error) {
	o := c.p.options.DNS01Challenge
	values.Set("Action", action)
	values.Set("Version", "2015-01-09")
	values.Set("Format", "JSON")
	values.Set("AccessKeyId", o.AccessKeyID)
	values.Set("SignatureMethod", "HMAC-SHA1")
	values.Set("SignatureVersion", "1.0")
	values.Set("Timestamp", time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return nil, e
	}
	values.Set("SignatureNonce", acmeB64(nonce[:]))
	if o.RegionID != "" {
		values.Set("RegionId", o.RegionID)
	}
	if o.SecurityToken != "" {
		values.Set("SecurityToken", o.SecurityToken)
	}
	values.Set("Signature", acmeAliSignature(values, o.AccessKeySecret))
	req, e := http.NewRequestWithContext(ctx, "POST", "https://alidns.aliyuncs.com/", strings.NewReader(values.Encode()))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, e := c.http.Do(req)
	if e != nil {
		return nil, errors.New("AliDNS HTTP request failed")
	}
	data, e := acmeResponse(resp)
	if e != nil {
		return nil, e
	}
	var result struct {
		Code string `json:"Code"`
	}
	if json.Unmarshal(data, &result) != nil || resp.StatusCode != 200 || result.Code != "" {
		return nil, errors.New("AliDNS request rejected")
	}
	return data, nil
}
func (c *acmeClient) aliDNSTXT(ctx context.Context, name, value string, ttl int) (func(context.Context) error, error) {
	parts := strings.Split(name, ".")
	zone := ""
	for i := 1; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		data, e := c.aliDNS(ctx, "DescribeDomainInfo", url.Values{"DomainName": {candidate}})
		if e != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		var result struct {
			DomainName string `json:"DomainName"`
		}
		if json.Unmarshal(data, &result) == nil && strings.EqualFold(result.DomainName, candidate) {
			zone = candidate
			break
		}
	}
	if zone == "" {
		return nil, errors.New("AliDNS DNS01 zone not found")
	}
	rr := strings.TrimSuffix(name, "."+zone)
	data, e := c.aliDNS(ctx, "AddDomainRecord", url.Values{"DomainName": {zone}, "RR": {rr}, "Type": {"TXT"}, "Value": {value}, "TTL": {strconv.Itoa(ttl)}})
	if e != nil {
		return nil, e
	}
	var result struct {
		RecordID string `json:"RecordId"`
	}
	if json.Unmarshal(data, &result) != nil || !acmeDNSID(result.RecordID) {
		return nil, errors.New("AliDNS returned invalid record ID")
	}
	return func(ctx context.Context) error {
		_, e := c.aliDNS(ctx, "DeleteDomainRecord", url.Values{"RecordId": {result.RecordID}})
		return e
	}, nil
}
func (c *acmeClient) acmeDNSTXT(ctx context.Context, name, value string) (func(context.Context) error, error) {
	o := c.p.options.DNS01Challenge
	endpoint, _ := acmeURL(o.ServerURL)
	endpoint.Path = strings.TrimSuffix(endpoint.Path, "/") + "/update"
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint.String(), strings.NewReader(string(acmeJSON(map[string]string{"subdomain": o.Subdomain, "txt": value}))))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-User", o.Username)
	req.Header.Set("X-Api-Key", o.Password)
	resp, e := c.http.Do(req)
	if e != nil {
		return nil, errors.New("ACME-DNS update request failed")
	}
	_, e = acmeResponse(resp)
	if e != nil {
		return nil, e
	}
	if resp.StatusCode != 200 {
		return nil, errors.New("ACME-DNS update rejected")
	}
	// ACME-DNS maintains a rolling pair of TXT values and has no deletion API.
	return func(context.Context) error { return nil }, nil
}
