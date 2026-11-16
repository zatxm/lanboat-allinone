package native

import (
	"context"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type LuaOptions struct {
	Script     string `json:"script,omitempty"`
	ScriptPath string `json:"script_path,omitempty"`
	File       string `json:"file,omitempty"`
	program    *luaNode
	nodeTLS    *TLSOptions
	nodeConfig *tls.Config
}

func (o *LuaOptions) prepare(kind string) error {
	if kind != "lua" {
		if o.Script != "" || o.ScriptPath != "" || o.File != "" {
			return errors.New("Lua options require lua type")
		}
		return nil
	}
	if o.Script != "" && o.ScriptPath != "" || o.File != "" && (o.Script != "" || o.ScriptPath != "") {
		return errors.New("Lua accepts one of script, script_path or file")
	}
	source := o.Script
	if o.ScriptPath != "" {
		f, e := os.Open(o.ScriptPath)
		if e != nil {
			return fmt.Errorf("open Lua script: %w", e)
		}
		defer f.Close()
		b, e := io.ReadAll(io.LimitReader(f, (256<<10)+1))
		if e != nil {
			return e
		}
		if len(b) == 0 {
			return errors.New("Lua script file is empty")
		}
		source = string(b)
	}
	if source == "" {
		switch o.File {
		case "", "lightsword-backend.lua":
			source = luaLightswordScript
		case "http-backend.lua":
			source = luaHTTPScript
		case "trojan-backend.lua":
			source = luaTrojanScript
		default:
			return errors.New("unknown Lua backend file")
		}
	}
	p, e := luaCompile(source)
	if e != nil {
		return e
	}
	o.program = p
	return nil
}

var luaSequence atomic.Uint64

type luaBackendConn struct {
	net.Conn
	vm                  *luaVM
	mu, readMu, writeMu sync.Mutex
	once                sync.Once
	queued              string
	pending             []byte
	readErr             error
	uid                 string
}

func newLuaBackend(c net.Conn, o Outbound, address string) (*luaBackendConn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	number, e := strconv.Atoi(port)
	if e != nil || number < 1 || number > 65535 {
		return nil, errors.New("Lua invalid destination port")
	}
	b := &luaBackendConn{Conn: c, vm: newLuaVM(), uid: strconv.FormatUint(luaSequence.Add(1), 10)}
	vm := b.vm
	atyp := float64(3)
	var ip []byte
	if p := net.ParseIP(host); p != nil {
		if p.To4() != nil {
			atyp = 1
			ip = p.To4()
		} else {
			atyp = 4
			ip = p.To16()
		}
	}
	api := luaModule(map[string]any{
		"ADDRESS": luaModule(map[string]any{"IPV4": float64(1), "DOMAIN": float64(3), "IPV6": float64(4)}),
		"PROXY":   luaModule(map[string]any{"TCP": float64(1), "UDP": float64(3)}),
		"RESULT":  luaModule(map[string]any{"SUCCESS": float64(0), "HANDSHAKE": float64(1), "DIRECT": float64(2), "IGNORE": float64(2), "ERROR": float64(-1)}),
		"SUPPORT": luaModule(map[string]any{"DIRECT_WRITE": float64(1)}),
	})
	for k, x := range map[string]any{"get_uuid": b.uid, "get_proxy_type": float64(1), "get_address_type": atyp, "get_address_host": host, "get_address_port": float64(number), "get_address_bytes": string(ip)} {
		api.values[k] = luaBuiltin(func(_ *luaVM, _ []any) []any { return []any{x} })
	}
	api.values["write"] = luaBuiltin(func(vm *luaVM, a []any) []any {
		s := luaString(a, 1)
		if len(b.queued)+len(s) > luaStringLimit {
			panic(errors.New("Lua queued write exceeds1MiB"))
		}
		vm.alloc(len(b.queued) + len(s))
		b.queued += s
		return []any{float64(len(s))}
	})
	api.values["free"] = luaBuiltin(func(_ *luaVM, _ []any) []any { return nil })
	// debug is intentionally silent: user scripts may pass credentials or payloads.
	api.values["debug"] = luaBuiltin(func(_ *luaVM, _ []any) []any { return nil })
	network := luaModule(map[string]any{"htons": luaBuiltin(func(_ *luaVM, a []any) []any {
		n := luaInt(luaArg(a, 0))
		if n < 0 || n > 65535 {
			panic(errors.New("Lua port outside0-65535"))
		}
		return []any{string([]byte{byte(n >> 8), byte(n)})}
	}), "ntohs": luaBuiltin(func(_ *luaVM, a []any) []any {
		s := luaString(a, 0)
		if len(s) != 2 {
			panic(errors.New("Lua ntohs requires2bytes"))
		}
		return []any{float64(binary.BigEndian.Uint16([]byte(s)))}
	})})
	crypto := luaCryptoModule()
	modules := map[string]any{"backend": api, "network": network, "crypto": crypto, "http": luaModule(map[string]any{})}
	vm.globals.values["crypto"] = crypto
	vm.globals.values["require"] = luaBuiltin(func(_ *luaVM, a []any) []any {
		x := modules[luaString(a, 0)]
		if x == nil {
			panic(errors.New("Lua module is not available"))
		}
		return []any{x}
	})
	method := o.Method
	if method == "" {
		method = "aes-256-cfb"
	}
	vm.globals.values["settings"] = luaModule(map[string]any{"server": net.JoinHostPort(o.Server, strconv.Itoa(int(o.ServerPort))), "username": o.Username, "password": o.Password, "method": method})
	_, e = vm.run(func() []any { _, j := vm.block(o.program, luaScope(vm.globals)); return j.values })
	if e != nil {
		return nil, e
	}
	switch vm.globals.get("wa_lua_on_handshake_cb").(type) {
	case *luaFunction, *luaClosure, *luaBuiltinFunction:
	default:
		return nil, errors.New("Lua handshake callback missing")
	}
	if len(b.queued) > 0 {
		return nil, errors.New("Lua cannot write outside callbacks")
	}
	return b, nil
}
func luaCryptoModule() *luaTable {
	digest := luaBuiltin(func(vm *luaVM, a []any) []any {
		var h hash.Hash
		switch strings.ToUpper(strings.ReplaceAll(luaString(a, 0), "-", "")) {
		case "MD5":
			h = md5.New()
		case "SHA1":
			h = sha1.New()
		case "SHA224":
			h = sha256.New224()
		case "SHA256":
			h = sha256.New()
		case "SHA384":
			h = sha512.New384()
		case "SHA512":
			h = sha512.New()
		default:
			panic(errors.New("Lua unsupported digest"))
		}
		table := luaModule(map[string]any{"update": luaBuiltin(func(_ *luaVM, a []any) []any {
			s := luaString(a, 1)
			if len(s) > luaStringLimit {
				panic(errors.New("Lua digest input limit"))
			}
			h.Write([]byte(s))
			return nil
		}), "final": luaBuiltin(func(_ *luaVM, _ []any) []any { return []any{hex.EncodeToString(h.Sum(nil))} })})
		table.retained = 1024
		vm.alloc(table.retained)
		return []any{table}
	})
	crypto := luaModule(map[string]any{"digest": luaModule(map[string]any{"new": digest})})
	crypto.values["cipher_info"] = luaBuiltin(func(_ *luaVM, a []any) []any {
		key, iv, ok := ssStreamParameters(luaString(a, 0))
		if !ok {
			return luaCipherFailure()
		}
		return []any{luaModule(map[string]any{"key": float64(key), "iv": float64(iv)})}
	})
	crypto.values["base64"] = luaModule(map[string]any{"encode": luaBuiltin(func(vm *luaVM, a []any) []any {
		s := luaString(a, 0)
		vm.alloc(base64.StdEncoding.EncodedLen(len(s)))
		return []any{base64.StdEncoding.EncodeToString([]byte(s))}
	}), "decode": luaBuiltin(func(vm *luaVM, a []any) []any {
		s := luaString(a, 0)
		vm.alloc(base64.StdEncoding.DecodedLen(len(s)))
		b, e := base64.StdEncoding.DecodeString(s)
		if e != nil {
			panic(errors.New("Lua invalid base64"))
		}
		return []any{string(b)}
	})})
	crypto.values["rand"] = luaModule(map[string]any{"bytes": luaBuiltin(func(vm *luaVM, a []any) []any {
		n := luaInteger(a, 0, 0)
		vm.alloc(n)
		b := make([]byte, n)
		if _, e := rand.Read(b); e != nil {
			panic(e)
		}
		return []any{string(b)}
	})})
	for name, decrypt := range map[string]bool{"encrypt": false, "decrypt": true} {
		crypto.values[name] = luaModule(map[string]any{"new": luaBuiltin(func(vm *luaVM, a []any) []any {
			method, key, iv := luaString(a, 0), []byte(luaString(a, 1)), []byte(luaString(a, 2))
			ks, ivs, ok := ssStreamParameters(method)
			ofb := strings.HasSuffix(method, "-ofb") && strings.HasPrefix(method, "aes-")
			if ofb {
				switch method {
				case "aes-128-ofb":
					ks = 16
				case "aes-192-ofb":
					ks = 24
				case "aes-256-ofb":
					ks = 32
				default:
					panic(errors.New("Lua unsupported cipher"))
				}
				ivs, ok = 16, true
			}
			if !ok || len(key) != ks || len(iv) != ivs {
				panic(errors.New("Lua cipher key or IV length mismatch"))
			}
			base := method
			if ofb {
				base = strings.TrimSuffix(method, "-ofb") + "-cfb"
			}
			k := &ssKey{method: base, master: key}
			if method == "table" {
				enc, dec := ssTable(string(key))
				k.tableEnc, k.tableDec = &enc, &dec
			}
			var e error
			k.streamBlock, e = newSSStreamBlock(k.method, key)
			if e != nil {
				panic(e)
			}
			var stream cipher.Stream
			if ofb {
				stream = cipher.NewOFB(k.streamBlock, iv)
			} else {
				stream, e = k.stream(iv, decrypt)
				if e != nil {
					panic(e)
				}
			}
			table := luaModule(map[string]any{"update": luaBuiltin(func(vm *luaVM, a []any) []any {
				s := luaString(a, 1)
				vm.alloc(len(s))
				out := make([]byte, len(s))
				stream.XORKeyStream(out, []byte(s))
				return []any{string(out)}
			}), "final": luaBuiltin(func(_ *luaVM, _ []any) []any { return []any{""} })})
			table.retained = 8192
			vm.alloc(table.retained)
			return []any{table}
		})})
	}
	return crypto
}
func (b *luaBackendConn) invoke(name string, data []byte) (values []any, queued string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	fn := b.vm.globals.get(name)
	if fn == nil {
		return nil, "", nil
	}
	args := []any{b.uid}
	if data != nil {
		args = append(args, string(data))
	}
	values, err = b.vm.run(func() []any { b.vm.alloc(len(data)); return b.vm.call(fn, args) })
	queued = b.queued
	b.queued = ""
	return
}
func luaResult(values []any, input []byte) ([]byte, error) {
	if len(values) == 0 {
		return input, nil
	}
	status, ok := values[0].(float64)
	if !ok || status != 0 && status != 1 && status != 2 && status != -1 {
		return nil, errors.New("Lua callback returned invalid status")
	}
	if status == -1 {
		return nil, errors.New("Lua backend rejected data")
	}
	if len(values) < 2 || values[1] == nil {
		return nil, nil
	}
	s, ok := values[1].(string)
	if !ok || len(s) > luaStringLimit {
		return nil, errors.New("Lua callback returned invalid data")
	}
	return []byte(s), nil
}
func (b *luaBackendConn) handshake() error {
	_, q, e := b.invoke("wa_lua_on_flags_cb", nil)
	if e != nil {
		return e
	}
	if e = writeAll(b.Conn, []byte(q)); e != nil {
		return e
	}
	var buffer [32768]byte
	for round := 0; round < 1024; round++ {
		values, q, e := b.invoke("wa_lua_on_handshake_cb", nil)
		if e != nil {
			return e
		}
		if e = writeAll(b.Conn, []byte(q)); e != nil {
			return e
		}
		if len(values) == 0 {
			return errors.New("Lua handshake callback must return boolean")
		}
		ready, ok := values[0].(bool)
		if !ok {
			return errors.New("Lua handshake callback must return boolean")
		}
		if ready {
			return nil
		}
		n, readErr := b.Conn.Read(buffer[:])
		if n == 0 && readErr != nil {
			return readErr
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		values, q, e = b.invoke("wa_lua_on_read_cb", buffer[:n])
		if e != nil {
			return e
		}
		if e = writeAll(b.Conn, []byte(q)); e != nil {
			return e
		}
		data, e := luaResult(values, nil)
		if e != nil {
			return e
		}
		if len(b.pending)+len(data) > luaStringLimit {
			return errors.New("Lua handshake buffered data limit")
		}
		b.pending = append(b.pending, data...)
		if readErr != nil {
			b.readErr = readErr
		}
	}
	return errors.New("Lua handshake round limit")
}
func (b *luaBackendConn) Read(p []byte) (int, error) {
	b.readMu.Lock()
	defer b.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if len(b.pending) > 0 {
			n := copy(p, b.pending)
			b.pending = b.pending[n:]
			return n, nil
		}
		if b.readErr != nil {
			return 0, b.readErr
		}
		b.mu.Lock()
		passthrough := b.vm.globals.get("wa_lua_on_read_cb") == nil
		b.mu.Unlock()
		if passthrough {
			return b.Conn.Read(p)
		}
		var buffer [32768]byte
		n, e := b.Conn.Read(buffer[:])
		if n == 0 {
			return 0, e
		}
		b.readErr = e
		values, queued, e := b.invoke("wa_lua_on_read_cb", buffer[:n])
		if e != nil {
			return 0, e
		}
		if queued != "" {
			b.writeMu.Lock()
			e = writeAll(b.Conn, []byte(queued))
			b.writeMu.Unlock()
			if e != nil {
				return 0, e
			}
		}
		b.pending, e = luaResult(values, buffer[:n])
		if e != nil {
			return 0, e
		}
	}
}
func (b *luaBackendConn) Write(p []byte) (int, error) {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	b.mu.Lock()
	passthrough := b.vm.globals.get("wa_lua_on_write_cb") == nil
	b.mu.Unlock()
	if passthrough {
		return b.Conn.Write(p)
	}
	total := 0
	for len(p) > 0 {
		part := p[:min(len(p), 32768)]
		values, queued, e := b.invoke("wa_lua_on_write_cb", part)
		if e != nil {
			return total, e
		}
		data, e := luaResult(values, part)
		if e != nil {
			return total, e
		}
		if e = writeAll(b.Conn, []byte(queued)); e != nil {
			return total, e
		}
		if e = writeAll(b.Conn, data); e != nil {
			return total, e
		}
		total += len(part)
		p = p[len(part):]
	}
	return total, nil
}
func (b *luaBackendConn) Close() error {
	e := b.Conn.Close()
	b.once.Do(func() { b.invoke("wa_lua_on_close_cb", nil) })
	return e
}
func (b *luaBackendConn) CloseWrite() error {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	if c, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return nil
}
func (r *Runtime) dialLua(ctx context.Context, o Outbound, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("Lua backend callbacks carry TCP only")
	}
	c, e := r.dialProxyTransport(ctx, o)
	if e != nil {
		return nil, e
	}
	wire := c
	stop := context.AfterFunc(ctx, func() { wire.Close() })
	defer stop()
	deadline := time.Now().Add(handshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	success := false
	defer func() {
		if !success {
			wire.Close()
		}
	}()
	if o.nodeConfig != nil {
		securityContext := ctx
		if o.nodeTLS.ECH != nil && o.nodeTLS.ECH.Enabled && o.DomainResolver != "" {
			child, cancel := o.DomainResolver.apply(ctx)
			defer cancel()
			securityContext = context.WithValue(child, dnsBootstrapKey{}, o.DomainResolver.tag())
		}
		config, err := prepareClientTLS(securityContext, o.nodeConfig, *o.nodeTLS, r.resolver)
		if err != nil {
			return nil, err
		}
		if o.nodeTLS.realityEnabled() {
			c, e = dialReality(ctx, c, config, *o.nodeTLS)
		} else {
			secured := clientTLS(c, config, *o.nodeTLS)
			e = secured.HandshakeContext(ctx)
			if e == nil {
				c = secured
			}
		}
		if e != nil {
			return nil, e
		}
	}
	b, e := newLuaBackend(c, o, address)
	if e != nil {
		return nil, e
	}
	if e = b.handshake(); e != nil {
		b.Close()
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		b.Close()
		return nil, e
	}
	c.SetDeadline(time.Time{})
	owned, e := r.own(b)
	success = e == nil
	return owned, e
}

func luaCipherFailure() []any { panic(errors.New("Lua backend requires a stream cipher")) }
