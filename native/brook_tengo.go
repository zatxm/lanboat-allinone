package native

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
)

func (o *BrookOptions) prepare(kind string) error {
	if o.Tengo == "" && o.TengoFile == "" {
		return nil
	}
	if kind != "brook" || o.Tengo != "" && o.TengoFile != "" {
		return errors.New("brook accepts one of tengo or tengo_file")
	}
	source := o.Tengo
	if o.TengoFile != "" {
		file, err := os.Open(o.TengoFile)
		if err != nil {
			return fmt.Errorf("open Tengo script: %w", err)
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, (256<<10)+1))
		if err != nil {
			return err
		}
		source = string(data)
	}
	if source == "" {
		return errors.New("Tengo script is empty")
	}
	program, err := NewTengoProgram(source, nil)
	if err != nil {
		return err
	}
	o.tengoProgram = program
	return nil
}

type brookDecision struct {
	address, detour string
	bypass          bool
}

func (o BrookOptions) addressDecision(ctx context.Context, network, address, source string, metadata Metadata) (brookDecision, error) {
	decision := brookDecision{address: address}
	if o.tengoProgram == nil {
		return decision, nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return decision, err
	}
	input := map[string]any{"network": network, "ipaddress": "", "domainaddress": "", "from": source, "processname": metadata.ProcessName, "processpath": metadata.ProcessPath}
	if _, err := netip.ParseAddr(host); err == nil {
		input["ipaddress"] = address
	} else {
		input["domainaddress"] = address
	}
	value, err := o.tengoProgram.Run(ctx, map[string]any{"in_address": input})
	if err != nil || value == nil {
		return decision, err
	}
	result, ok := value.(map[string]any)
	if !ok {
		return decision, errors.New("Tengo in_address must return a map or undefined")
	}
	rewrites := 0
	for key, value := range result {
		switch key {
		case "block", "bypass":
			enabled, ok := value.(bool)
			if !ok {
				return decision, fmt.Errorf("Tengo %s must be boolean", key)
			}
			if key == "block" && enabled {
				return decision, ErrRejected
			}
			if key == "bypass" {
				decision.bypass = enabled
			}
		case "address", "ipaddress", "domainaddress", "detour":
			text, ok := value.(string)
			if !ok {
				return decision, fmt.Errorf("Tengo %s must be a string", key)
			}
			if key == "detour" {
				decision.detour = text
			} else if text != "" {
				rewrites++
				decision.address = text
			}
		default:
			return decision, fmt.Errorf("unsupported Tengo in_address result %q", key)
		}
	}
	if rewrites > 1 || decision.bypass && decision.detour != "" {
		return decision, errors.New("conflicting Tengo address decisions")
	}
	if _, err := encodeAddress(decision.address); err != nil {
		return decision, err
	}
	return decision, nil
}

// A script may select an existing outbound, but must not create a dial loop.
type brookScriptPathKey struct{}

func brookScriptPath(ctx context.Context, tag string) (context.Context, error) {
	path, _ := ctx.Value(brookScriptPathKey{}).([]string)
	if len(path) >= 16 {
		return ctx, errors.New("Tengo detour depth limit")
	}
	for _, previous := range path {
		if previous == tag {
			return ctx, errors.New("Tengo detour cycle")
		}
	}
	return context.WithValue(ctx, brookScriptPathKey{}, append(append([]string{}, path...), tag)), nil
}

func (r *Runtime) brookInboundDecision(ctx context.Context, q *request) (brookDecision, error) {
	for _, in := range r.config.Inbounds {
		if in.Tag == q.inbound && in.Type == "brook" && in.tengoProgram != nil {
			return in.addressDecision(ctx, q.network, q.address, q.source, q.metadata)
		}
	}
	return brookDecision{address: q.address}, nil
}
