package native

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func tengoBuiltin(fn func(*luaVM, []any) any) *luaBuiltinFunction {
	return luaBuiltin(func(v *luaVM, args []any) []any { return []any{fn(v, args)} })
}
func tengoArgument(args []any, i int) any {
	if i >= len(args) {
		return nil
	}
	return args[i]
}
func tengoCollectionArg(args []any, i int) *tengoCollection {
	collection, ok := tengoArgument(args, i).(*tengoCollection)
	if !ok {
		panic(errors.New("Tengo expected collection"))
	}
	return collection
}
func (v *luaVM) tengoModule(entries map[string]func(*luaVM, []any) any) *tengoCollection {
	result := &tengoCollection{object: map[string]any{}, immutable: true}
	for name, function := range entries {
		result.object[name] = tengoBuiltin(function)
	}
	return result
}
func (v *luaVM) installTengo() {
	g := v.globals.values
	g["len"] = tengoBuiltin(func(_ *luaVM, a []any) any { return int64(tengoLength(tengoArgument(a, 0))) })
	g["time"] = tengoBuiltin(func(_ *luaVM, a []any) any {
		switch value := tengoArgument(a, 0).(type) {
		case time.Time:
			return value
		case int64:
			return time.Unix(value, 0)
		}
		return tengoArgument(a, 1)
	})
	g["__tengo_varargs"] = tengoBuiltin(func(v *luaVM, a []any) any {
		v.alloc(64 + 16*len(a))
		return &tengoCollection{array: append([]any{}, a...)}
	})
	g["string"] = tengoBuiltin(func(_ *luaVM, a []any) any { return tengoText(tengoArgument(a, 0)) })
	g["bool"] = tengoBuiltin(func(_ *luaVM, a []any) any { return tengoTruthy(tengoArgument(a, 0)) })
	g["int"] = tengoBuiltin(func(_ *luaVM, a []any) any {
		value := tengoArgument(a, 0)
		if s, ok := value.(string); ok {
			n, err := strconv.ParseInt(s, 10, 64)
			if err == nil {
				return n
			}
			if len(a) > 1 {
				return a[1]
			}
			return nil
		}
		if b, ok := value.(bool); ok {
			if b {
				return int64(1)
			}
			return int64(0)
		}
		return tengoInt(value)
	})
	g["float"] = tengoBuiltin(func(_ *luaVM, a []any) any {
		value := tengoArgument(a, 0)
		if s, ok := value.(string); ok {
			n, err := strconv.ParseFloat(s, 64)
			if err == nil {
				return n
			}
			if len(a) > 1 {
				return a[1]
			}
			return nil
		}
		return tengoFloat(value)
	})
	g["char"] = tengoBuiltin(func(_ *luaVM, a []any) any {
		value := tengoArgument(a, 0)
		if text, ok := value.(string); ok {
			r := []rune(text)
			if len(r) == 1 {
				return tengoChar(r[0])
			}
			return nil
		}
		n := tengoInt(value)
		if n < 0 || n > 0x10ffff {
			return nil
		}
		return tengoChar(n)
	})
	g["bytes"] = tengoBuiltin(func(v *luaVM, a []any) any {
		switch value := tengoArgument(a, 0).(type) {
		case string:
			v.alloc(len(value))
			return &tengoCollection{bytes: []byte(value)}
		case *tengoCollection:
			if value.bytes != nil {
				v.alloc(len(value.bytes))
				return &tengoCollection{bytes: append([]byte{}, value.bytes...)}
			}
		}
		count := tengoInt(tengoArgument(a, 0))
		if count < 0 || count > luaStringLimit {
			panic(errors.New("Tengo bytes size limit"))
		}
		v.alloc(int(count))
		return &tengoCollection{bytes: make([]byte, int(count))}
	})
	g["error"] = tengoBuiltin(func(_ *luaVM, a []any) any { return &tengoError{value: tengoArgument(a, 0)} })
	g["append"] = tengoBuiltin(func(v *luaVM, a []any) any {
		collection := tengoCollectionArg(a, 0)
		if collection.object != nil {
			panic(errors.New("Tengo append requires array or bytes"))
		}
		if tengoLength(collection)+len(a)-1 > 16384 {
			panic(errors.New("Tengo append entry limit"))
		}
		v.alloc(64 + 16*(tengoLength(collection)+len(a)))
		if collection.bytes != nil {
			out := &tengoCollection{bytes: append([]byte{}, collection.bytes...)}
			for _, item := range a[1:] {
				n := tengoInt(item)
				if n < 0 || n > 255 {
					panic(errors.New("Tengo invalid byte"))
				}
				out.bytes = append(out.bytes, byte(n))
			}
			return out
		}
		return &tengoCollection{array: append(append([]any{}, collection.array...), a[1:]...)}
	})
	g["delete"] = tengoBuiltin(func(_ *luaVM, a []any) any {
		collection := tengoCollectionArg(a, 0)
		if collection.object == nil || collection.immutable {
			panic(errors.New("Tengo delete requires mutable map"))
		}
		delete(collection.object, tengoText(tengoArgument(a, 1)))
		return nil
	})
	g["splice"] = tengoBuiltin(func(v *luaVM, a []any) any {
		collection := tengoCollectionArg(a, 0)
		if collection.array == nil || collection.immutable {
			panic(errors.New("Tengo splice requires mutable array"))
		}
		start := int(tengoInt(tengoArgument(a, 1)))
		count := len(collection.array) - start
		if len(a) > 2 {
			count = int(tengoInt(a[2]))
		}
		if start < 0 || count < 0 || start+count > len(collection.array) || len(collection.array)-count+max(0, len(a)-3) > 16384 {
			panic(errors.New("Tengo splice bounds"))
		}
		v.alloc(64 + 16*(len(collection.array)+len(a)))
		removed := append([]any{}, collection.array[start:start+count]...)
		replacement := []any{}
		if len(a) > 3 {
			replacement = a[3:]
		}
		collection.array = append(append(append([]any{}, collection.array[:start]...), replacement...), collection.array[start+count:]...)
		return &tengoCollection{array: removed}
	})
	g["copy"] = tengoBuiltin(func(v *luaVM, a []any) any {
		return v.tengoCopy(tengoArgument(a, 0), false, map[*tengoCollection]*tengoCollection{})
	})
	g["immutable"] = tengoBuiltin(func(v *luaVM, a []any) any {
		value := tengoArgument(a, 0)
		if collection, ok := value.(*tengoCollection); ok && collection.bytes == nil {
			v.alloc(64)
			return &tengoCollection{array: collection.array, object: collection.object, immutable: true}
		}
		return value
	})
	predicates := map[string]func(any) bool{
		"is_time": func(x any) bool { _, ok := x.(time.Time); return ok },
		"is_int":  func(x any) bool { _, ok := x.(int64); return ok }, "is_float": func(x any) bool { _, ok := x.(float64); return ok }, "is_bool": func(x any) bool { _, ok := x.(bool); return ok }, "is_string": func(x any) bool { _, ok := x.(string); return ok }, "is_char": func(x any) bool { _, ok := x.(tengoChar); return ok }, "is_undefined": func(x any) bool { return x == nil }, "is_error": func(x any) bool { _, ok := x.(*tengoError); return ok }, "is_function": func(x any) bool {
			switch x.(type) {
			case *luaFunction, *luaBuiltinFunction:
				return true
			}
			return false
		},
		"is_array": func(x any) bool { c, ok := x.(*tengoCollection); return ok && c.array != nil && !c.immutable }, "is_immutable_array": func(x any) bool { c, ok := x.(*tengoCollection); return ok && c.array != nil && c.immutable }, "is_map": func(x any) bool { c, ok := x.(*tengoCollection); return ok && c.object != nil && !c.immutable }, "is_immutable_map": func(x any) bool { c, ok := x.(*tengoCollection); return ok && c.object != nil && c.immutable }, "is_bytes": func(x any) bool { c, ok := x.(*tengoCollection); return ok && c.bytes != nil },
	}
	for name, predicate := range predicates {
		test := predicate
		g[name] = tengoBuiltin(func(_ *luaVM, a []any) any { return test(tengoArgument(a, 0)) })
	}
	g["type_name"] = tengoBuiltin(func(_ *luaVM, a []any) any {
		value := tengoArgument(a, 0)
		for name, predicate := range predicates {
			if predicate(value) {
				return strings.TrimPrefix(name, "is_")
			}
		}
		return "undefined"
	})
	g["import"] = tengoBuiltin(func(v *luaVM, a []any) any { return v.importTengoModule(tengoText(tengoArgument(a, 0))) })
}
func (v *luaVM) tengoCopy(value any, immutable bool, seen map[*tengoCollection]*tengoCollection) any {
	v.tick()
	source, ok := value.(*tengoCollection)
	if !ok {
		return value
	}
	if copy := seen[source]; copy != nil {
		return copy
	}
	out := &tengoCollection{immutable: immutable}
	seen[source] = out
	v.alloc(64 + 48*tengoLength(source))
	if source.bytes != nil {
		out.bytes = append([]byte{}, source.bytes...)
	} else if source.array != nil {
		out.array = make([]any, len(source.array))
		for i, item := range source.array {
			out.array[i] = v.tengoCopy(item, immutable, seen)
		}
	} else {
		out.object = map[string]any{}
		for key, item := range source.object {
			out.object[key] = v.tengoCopy(item, immutable, seen)
		}
	}
	return out
}
func (v *luaVM) importTengoModule(name string) any {
	if entries, ok := v.tengo.modules[name]; ok {
		module := &tengoCollection{object: map[string]any{}, immutable: true}
		for key, function := range entries {
			fn := function
			module.object[key] = tengoBuiltin(func(v *luaVM, args []any) any {
				input := make([]any, len(args))
				for i, arg := range args {
					value, err := exportTengo(arg, map[*tengoCollection]bool{})
					if err != nil {
						return &tengoError{err.Error()}
					}
					input[i] = value
				}
				result, err := fn(v.tengo.ctx, input)
				if err != nil {
					return &tengoError{err.Error()}
				}
				return v.tengoImport(result, 0)
			})
		}
		return module
	}
	stringArg := func(a []any, i int) string { return tengoText(tengoArgument(a, i)) }
	switch name {
	case "text":
		functions := map[string]func(*luaVM, []any) any{}
		tests := map[string]func(string, string) bool{"contains": strings.Contains, "has_prefix": strings.HasPrefix, "has_suffix": strings.HasSuffix, "equal_fold": strings.EqualFold}
		for name, function := range tests {
			fn := function
			functions[name] = func(_ *luaVM, a []any) any { return fn(stringArg(a, 0), stringArg(a, 1)) }
		}
		unary := map[string]func(string) string{"to_lower": strings.ToLower, "to_upper": strings.ToUpper, "trim_space": strings.TrimSpace, "title": strings.ToTitle}
		for name, function := range unary {
			fn := function
			functions[name] = func(_ *luaVM, a []any) any { return fn(stringArg(a, 0)) }
		}
		functions["trim"] = func(_ *luaVM, a []any) any { return strings.Trim(stringArg(a, 0), stringArg(a, 1)) }
		functions["trim_prefix"] = func(_ *luaVM, a []any) any { return strings.TrimPrefix(stringArg(a, 0), stringArg(a, 1)) }
		functions["trim_suffix"] = func(_ *luaVM, a []any) any { return strings.TrimSuffix(stringArg(a, 0), stringArg(a, 1)) }
		functions["index"] = func(_ *luaVM, a []any) any { return int64(strings.Index(stringArg(a, 0), stringArg(a, 1))) }
		functions["last_index"] = func(_ *luaVM, a []any) any { return int64(strings.LastIndex(stringArg(a, 0), stringArg(a, 1))) }
		functions["count"] = func(_ *luaVM, a []any) any { return int64(strings.Count(stringArg(a, 0), stringArg(a, 1))) }
		functions["split"] = func(v *luaVM, a []any) any {
			values := strings.SplitN(stringArg(a, 0), stringArg(a, 1), 16385)
			if len(values) > 16384 {
				panic(errors.New("Tengo split entry limit"))
			}
			out := make([]any, len(values))
			for i, value := range values {
				out[i] = value
			}
			return v.tengoImport(out, 0)
		}
		functions["join"] = func(_ *luaVM, a []any) any {
			items := tengoCollectionArg(a, 0)
			values := make([]string, len(items.array))
			size := 0
			for i, value := range items.array {
				values[i] = tengoText(value)
				size += len(values[i]) + len(stringArg(a, 1))
			}
			if size > luaStringLimit {
				panic(errors.New("Tengo join size limit"))
			}
			return strings.Join(values, stringArg(a, 1))
		}
		functions["replace"] = func(_ *luaVM, a []any) any {
			n := -1
			if len(a) > 3 {
				n = int(tengoInt(a[3]))
			}
			source, old, replacement := stringArg(a, 0), stringArg(a, 1), stringArg(a, 2)
			count := strings.Count(source, old)
			if n >= 0 {
				count = min(count, n)
			}
			if len(source)+count*max(0, len(replacement)-len(old)) > luaStringLimit {
				panic(errors.New("Tengo replace size limit"))
			}
			return strings.Replace(source, old, replacement, n)
		}
		functions["repeat"] = func(v *luaVM, a []any) any {
			source := stringArg(a, 0)
			n := tengoInt(tengoArgument(a, 1))
			if n < 0 || n > luaStringLimit || n > 0 && len(source) > luaStringLimit/int(n) {
				panic(errors.New("Tengo repeat size limit"))
			}
			v.alloc(len(source) * int(n))
			return strings.Repeat(source, int(n))
		}
		functions["re_match"] = func(_ *luaVM, a []any) any {
			pattern, err := regexp.Compile(stringArg(a, 0))
			if err != nil {
				return &tengoError{err.Error()}
			}
			return pattern.MatchString(stringArg(a, 1))
		}
		return v.tengoModule(functions)
	case "json":
		return v.tengoModule(map[string]func(*luaVM, []any) any{
			"encode": func(v *luaVM, a []any) any {
				value, err := exportTengo(tengoArgument(a, 0), map[*tengoCollection]bool{})
				if err != nil {
					return &tengoError{err.Error()}
				}
				data, err := json.Marshal(value)
				if err != nil {
					return &tengoError{err.Error()}
				}
				v.alloc(len(data))
				return &tengoCollection{bytes: data}
			},
			"decode": func(v *luaVM, a []any) any {
				source := stringArg(a, 0)
				if len(source) > luaStringLimit {
					panic(errors.New("Tengo JSON size limit"))
				}
				decoder := json.NewDecoder(strings.NewReader(source))
				decoder.UseNumber()
				var value any
				if err := decoder.Decode(&value); err != nil {
					return &tengoError{err.Error()}
				}
				return v.tengoJSON(value, 0)
			},
		})
	case "base64", "hex":
		encode := func(_ *luaVM, a []any) any {
			data := []byte(stringArg(a, 0))
			if len(data) > luaStringLimit/2 {
				panic(errors.New("Tengo encoded value size limit"))
			}
			if name == "hex" {
				return hex.EncodeToString(data)
			}
			return base64.StdEncoding.EncodeToString(data)
		}
		decode := func(v *luaVM, a []any) any {
			var data []byte
			var err error
			if name == "hex" {
				data, err = hex.DecodeString(stringArg(a, 0))
			} else {
				data, err = base64.StdEncoding.DecodeString(stringArg(a, 0))
			}
			if err != nil {
				return &tengoError{err.Error()}
			}
			v.alloc(len(data))
			return &tengoCollection{bytes: data}
		}
		return v.tengoModule(map[string]func(*luaVM, []any) any{"encode": encode, "decode": decode})
	case "fmt":
		return v.tengoModule(map[string]func(*luaVM, []any) any{"sprintf": func(v *luaVM, a []any) any {
			pattern := stringArg(a, 0)
			if len(pattern) > 4096 {
				panic(errors.New("Tengo format limit"))
			}
			var out strings.Builder
			argument := 1
			for i := 0; i < len(pattern); i++ {
				if pattern[i] != '%' {
					out.WriteByte(pattern[i])
					continue
				}
				i++
				if i == len(pattern) {
					panic(errors.New("Tengo incomplete format"))
				}
				if pattern[i] == '%' {
					out.WriteByte('%')
					continue
				}
				// shortcut: no width or precision modifiers; add bounded parsing when needed.
				if !strings.ContainsRune("vsdtqxXfgeE", rune(pattern[i])) || argument >= len(a) {
					panic(errors.New("Tengo unsupported format or missing argument"))
				}
				value, err := exportTengo(a[argument], map[*tengoCollection]bool{})
				if err != nil {
					panic(err)
				}
				argument++
				part := fmt.Sprintf("%"+pattern[i:i+1], value)
				if out.Len()+len(part) > luaStringLimit {
					panic(errors.New("Tengo format output limit"))
				}
				out.WriteString(part)
			}
			v.alloc(out.Len())
			return out.String()
		}})
	case "math":
		functions := map[string]func(*luaVM, []any) any{}
		unary := map[string]func(float64) float64{"abs": math.Abs, "acos": math.Acos, "asin": math.Asin, "atan": math.Atan, "ceil": math.Ceil, "cos": math.Cos, "exp": math.Exp, "floor": math.Floor, "log": math.Log, "log10": math.Log10, "round": math.Round, "sin": math.Sin, "sqrt": math.Sqrt, "tan": math.Tan, "trunc": math.Trunc}
		for name, function := range unary {
			fn := function
			functions[name] = func(_ *luaVM, a []any) any { return fn(tengoFloat(tengoArgument(a, 0))) }
		}
		functions["pow"] = func(_ *luaVM, a []any) any {
			return math.Pow(tengoFloat(tengoArgument(a, 0)), tengoFloat(tengoArgument(a, 1)))
		}
		functions["min"] = func(_ *luaVM, a []any) any {
			return math.Min(tengoFloat(tengoArgument(a, 0)), tengoFloat(tengoArgument(a, 1)))
		}
		functions["max"] = func(_ *luaVM, a []any) any {
			return math.Max(tengoFloat(tengoArgument(a, 0)), tengoFloat(tengoArgument(a, 1)))
		}
		module := v.tengoModule(functions)
		module.object["pi"] = math.Pi
		module.object["e"] = math.E
		return module
	case "rand":
		return v.tengoModule(map[string]func(*luaVM, []any) any{"int": func(_ *luaVM, a []any) any {
			var value [8]byte
			rand.Read(value[:])
			var n uint64
			for _, b := range value {
				n = n<<8 | uint64(b)
			}
			return int64(n & math.MaxInt64)
		}})
	case "times":
		return v.tengoModule(map[string]func(*luaVM, []any) any{"now": func(_ *luaVM, _ []any) any { return time.Now() }, "unix": func(_ *luaVM, a []any) any {
			var nanos int64
			if len(a) > 1 {
				nanos = tengoInt(a[1])
			}
			return time.Unix(tengoInt(tengoArgument(a, 0)), nanos)
		}, "sleep": func(v *luaVM, a []any) any {
			duration := time.Duration(tengoInt(tengoArgument(a, 0)))
			if duration < 0 || duration > 2*time.Second {
				panic(errors.New("Tengo sleep limit"))
			}
			timer := time.NewTimer(duration)
			defer timer.Stop()
			select {
			case <-timer.C:
				return nil
			case <-v.tengo.ctx.Done():
				return &tengoError{v.tengo.ctx.Err().Error()}
			}
		}})
	case "brook":
		return v.tengoModule(map[string]func(*luaVM, []any) any{
			"splithostport": func(v *luaVM, a []any) any {
				host, port, err := net.SplitHostPort(stringArg(a, 0))
				if err != nil {
					return &tengoError{err.Error()}
				}
				return v.tengoImport(map[string]any{"host": host, "port": port}, 0)
			},
			"joinhostport": func(_ *luaVM, a []any) any { return net.JoinHostPort(stringArg(a, 0), stringArg(a, 1)) },
			"isprivate": func(_ *luaVM, a []any) any {
				address, err := netip.ParseAddr(stringArg(a, 0))
				return err == nil && (address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast())
			},
			"country": func(_ *luaVM, a []any) any {
				address, err := netip.ParseAddr(stringArg(a, 0))
				if err != nil {
					return &tengoError{err.Error()}
				}
				if address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
					return "ZZ"
				}
				return &tengoError{"country lookup requires a configured host module"}
			},
		})
	}
	panic(fmt.Errorf("Tengo module %q is not registered", name))
}
func (v *luaVM) tengoJSON(value any, depth int) any {
	if depth > 96 {
		panic(errors.New("Tengo JSON depth limit"))
	}
	switch x := value.(type) {
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n
		}
		n, err := x.Float64()
		if err != nil {
			panic(err)
		}
		return n
	case []any:
		if len(x) > 16384 {
			panic(errors.New("Tengo array entry limit"))
		}
		v.alloc(64 + 16*len(x))
		out := &tengoCollection{array: make([]any, len(x))}
		for i, item := range x {
			out.array[i] = v.tengoJSON(item, depth+1)
		}
		return out
	case map[string]any:
		if len(x) > 16384 {
			panic(errors.New("Tengo map entry limit"))
		}
		v.alloc(64 + 48*len(x))
		out := &tengoCollection{object: map[string]any{}}
		for key, item := range x {
			out.object[key] = v.tengoJSON(item, depth+1)
		}
		return out
	default:
		return value
	}
}
