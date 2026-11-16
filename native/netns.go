package native

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
)

type NetworkNamespaceOptions struct {
	Type    string `json:"type,omitempty"`
	Tag     string `json:"tag"`
	Path    string `json:"path,omitempty"`
	PIDFile string `json:"pid_file,omitempty"`
}

func namespacePath(ref string) (string, error) {
	if ref == "" || len(ref) > 4096 || strings.ContainsAny(ref, "\x00\r\n") {
		return "", errors.New("invalid network namespace reference")
	}
	if !strings.ContainsRune(ref, '/') {
		if ref == "." || ref == ".." {
			return "", errors.New("invalid network namespace name")
		}
		return filepath.Join("/run/netns", ref), nil
	}
	if !filepath.IsAbs(ref) {
		return "", errors.New("network namespace paths must be absolute")
	}
	return filepath.Clean(ref), nil
}

func validateNamespaces(list []NetworkNamespaceOptions) error {
	if len(list) > 64 || len(list) != 0 && runtime.GOOS != "linux" {
		return errors.New("network_namespaces supports up to 64 Linux namespaces")
	}
	tags := map[string]bool{}
	for _, n := range list {
		if n.Tag == "" || n.Tag == "." || n.Tag == ".." || len(n.Tag) > 255 || strings.ContainsAny(n.Tag, "/\x00\r\n") || tags[n.Tag] {
			return errors.New("invalid or duplicate network namespace tag")
		}
		tags[n.Tag] = true
		switch n.Type {
		case "", "default":
			if _, err := namespacePath(n.Path); err != nil {
				return err
			}
			if n.PIDFile != "" {
				return errors.New("pid_file requires an unshare namespace")
			}
		case "unshare":
			if n.Path != "" || strings.ContainsAny(n.PIDFile, "\x00\r\n") {
				return errors.New("unshare namespace cannot specify path or an invalid pid_file")
			}
		default:
			return fmt.Errorf("unsupported network namespace type %q", n.Type)
		}
	}
	return nil
}

func (r *Runtime) inboundNamespace(tag string) *networkNamespace {
	for _, in := range r.config.Inbounds {
		if in.Tag == tag {
			return in.namespace
		}
	}
	return nil
}

func (r *Runtime) bindNamespaces() error {
	attach := func(ref string) (*networkNamespace, error) {
		if ref == "" {
			return nil, nil
		}
		if n := r.namespaces[ref]; n != nil {
			return n, nil
		}
		path, err := namespacePath(ref)
		if err != nil {
			return nil, err
		}
		unique := map[*networkNamespace]bool{}
		for _, n := range r.namespaces {
			if n.matches(path) {
				r.namespaces[ref] = n
				return n, nil
			}
			unique[n] = true
		}
		if len(unique) >= 64 {
			return nil, errors.New("too many network namespaces")
		}
		n, err := startNamespace(r.ctx, NetworkNamespaceOptions{Path: path}, r.config.Route)
		if err != nil {
			return nil, fmt.Errorf("network namespace %q: %w", ref, err)
		}
		if r.namespaces == nil {
			r.namespaces = map[string]*networkNamespace{}
		}
		r.namespaces[ref] = n
		return n, nil
	}
	for _, o := range r.config.NetworkNamespaces {
		if o.Type != "unshare" {
			path, err := namespacePath(o.Path)
			if err != nil {
				return err
			}
			var shared *networkNamespace
			for _, n := range r.namespaces {
				if n.matches(path) {
					shared = n
					break
				}
			}
			if shared != nil {
				r.namespaces[o.Tag] = shared
				continue
			}
		}
		n, err := startNamespace(r.ctx, o, r.config.Route)
		if err != nil {
			return fmt.Errorf("network namespace %q: %w", o.Tag, err)
		}
		if r.namespaces == nil {
			r.namespaces = map[string]*networkNamespace{}
		}
		r.namespaces[o.Tag] = n
	}
	// Resolve references once; socket and packet paths only read pointers.
	var walk func(reflect.Value) error
	walk = func(v reflect.Value) error {
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return nil
			}
			return walk(v.Elem())
		}
		if v.Type() == reflect.TypeFor[clientReference]() {
			ref := v.Interface().(clientReference)
			if len(ref) > 0 && ref[0] == '{' {
				var o HTTPClientOptions
				if err := json.Unmarshal([]byte(ref), &o); err != nil {
					return err
				}
				_, err := attach(o.NetNS)
				return err
			}
			return nil
		}
		if v.Kind() != reflect.Struct && v.Kind() != reflect.Slice {
			return nil
		}
		if v.Kind() == reflect.Struct && v.CanAddr() && v.CanInterface() {
			switch o := v.Addr().Interface().(type) {
			case *DialOptions:
				var err error
				o.namespace, err = attach(o.NetNS)
				return err
			case *ListenOptions:
				var err error
				o.namespace, err = attach(o.NetNS)
				return err
			}
		}
		switch v.Kind() {
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).IsExported() {
					if err := walk(v.Field(i)); err != nil {
						return err
					}
				}
			}
		case reflect.Slice:
			if k := v.Type().Elem().Kind(); k != reflect.Struct && k != reflect.Pointer && k != reflect.Slice {
				return nil
			}
			for i := 0; i < v.Len(); i++ {
				if err := walk(v.Index(i)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(reflect.ValueOf(&r.config)); err != nil {
		return err
	}
	for i := range r.config.Outbounds {
		o := &r.config.Outbounds[i]
		if o.wgEndpoint != nil {
			o.wgEndpoint.DialOptions = o.DialOptions
		}
		if o.ocEndpoint != nil {
			o.ocEndpoint.DialOptions = o.DialOptions
		}
	}
	return nil
}
