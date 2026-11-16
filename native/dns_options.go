package native

import (
	"context"
	"encoding/json"
	"time"
)

type dnsNoCacheKey struct{}
type dnsQueryOptionsKey struct{}
type resolverReference string
type resolverOptions struct {
	Server                 string  `json:"server,omitempty"`
	Strategy               string  `json:"strategy,omitempty"`
	DisableCache           bool    `json:"disable_cache,omitempty"`
	DisableOptimisticCache bool    `json:"disable_optimistic_cache,omitempty"`
	RewriteTTL             *uint32 `json:"rewrite_ttl,omitempty"`
	Timeout                string  `json:"timeout,omitempty"`
	ClientSubnet           string  `json:"client_subnet,omitempty"`
}

func (o *resolverReference) UnmarshalJSON(b []byte) error {
	var tag string
	if json.Unmarshal(b, &tag) == nil {
		*o = resolverReference(tag)
		return nil
	}
	var options resolverOptions
	if e := decodeOptions(b, &options); e != nil {
		return e
	}
	*o = resolverReference(b)
	return nil
}
func (o resolverReference) MarshalJSON() ([]byte, error) {
	if len(o) > 0 && o[0] == '{' {
		return []byte(o), nil
	}
	return json.Marshal(string(o))
}
func (o resolverReference) options() resolverOptions {
	if len(o) > 0 && o[0] == '{' {
		var v resolverOptions
		json.Unmarshal([]byte(o), &v)
		return v
	}
	return resolverOptions{Server: string(o)}
}
func (o resolverReference) tag() string { return o.options().Server }
func (o resolverReference) apply(ctx context.Context) (context.Context, context.CancelFunc) {
	v := o.options()
	ctx = context.WithValue(ctx, dnsQueryOptionsKey{}, v)
	if v.DisableCache {
		ctx = context.WithValue(ctx, dnsNoCacheKey{}, true)
	}
	d, _ := optionDuration(v.Timeout, 10*time.Second)
	return context.WithTimeout(ctx, d)
}

func outboundResolvers(nodes []Outbound) (refs []resolverReference) {
	for _, o := range nodes {
		refs = append(refs, o.DomainResolver)
	}
	return
}
