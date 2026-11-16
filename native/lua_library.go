package native

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"sort"
	"strconv"
	"strings"
)

func luaModule(entries map[string]any) *luaTable {
	m := &luaTable{values: map[any]any{}}
	for k, x := range entries {
		m.values[k] = x
	}
	return m
}
func luaString(a []any, i int) string { return luaText(luaArg(a, i)) }
func luaInteger(a []any, i int, def int) int {
	if i >= len(a) || a[i] == nil {
		return def
	}
	n := luaInt(a[i])
	if n < math.MinInt32 || n > math.MaxInt32 {
		panic(errors.New("Lua integer outside supported range"))
	}
	return int(n)
}
func luaTableArg(a []any, i int) *luaTable {
	if t, ok := luaArg(a, i).(*luaTable); ok {
		return t
	}
	panic(errors.New("Lua expected table"))
}
func luaBounds(length, start, end int) (int, int) {
	if start < 0 {
		start = length + start + 1
	}
	if end < 0 {
		end = length + end + 1
	}
	start = max(1, start)
	end = min(length, end)
	if start > end {
		return 0, 0
	}
	return start - 1, end
}
func luaType(v any) string {
	switch v.(type) {
	case nil:
		return "nil"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	case *luaTable:
		return "table"
	case *luaFunction, *luaClosure, *luaBuiltinFunction:
		return "function"
	}
	return "userdata"
}
func luaDescribe(v any) string {
	switch v.(type) {
	case string, float64:
		return luaText(v)
	case nil:
		return "nil"
	case bool:
		return strconv.FormatBool(v.(bool))
	}
	return luaType(v)
}
func newLuaVM() *luaVM {
	v := &luaVM{globals: luaScope(nil)}
	g := v.globals.values
	g["_VERSION"] = "Lanboat Lua backend1 (Lua5.3 core syntax)"
	g["type"] = luaBuiltin(func(_ *luaVM, a []any) []any { return []any{luaType(luaArg(a, 0))} })
	g["tostring"] = luaBuiltin(func(_ *luaVM, a []any) []any { return []any{luaDescribe(luaArg(a, 0))} })
	g["tonumber"] = luaBuiltin(func(_ *luaVM, a []any) []any {
		if n, ok := luaArg(a, 0).(float64); ok {
			return []any{n}
		}
		s, ok := luaArg(a, 0).(string)
		if !ok {
			return []any{nil}
		}
		if len(a) > 1 && a[1] != nil {
			base := luaInteger(a, 1, 10)
			if base < 2 || base > 36 {
				panic(errors.New("Lua invalid numeric base"))
			}
			n, e := strconv.ParseInt(strings.TrimSpace(s), base, 64)
			if e == nil {
				return []any{float64(n)}
			}
		} else if n, e := strconv.ParseFloat(strings.TrimSpace(s), 64); e == nil {
			return []any{n}
		}
		return []any{nil}
	})
	g["assert"] = luaBuiltin(func(_ *luaVM, a []any) []any {
		if !luaTruthy(luaArg(a, 0)) {
			panic(errors.New("Lua assertion failed"))
		}
		return a
	})
	g["error"] = luaBuiltin(func(_ *luaVM, _ []any) []any { panic(errors.New("Lua script raised an error")) })
	g["pcall"] = luaBuiltin(luaProtected)
	g["select"] = luaBuiltin(func(_ *luaVM, a []any) []any {
		if luaArg(a, 0) == "#" {
			return []any{float64(len(a) - 1)}
		}
		n := luaInteger(a, 0, 1)
		if n < 0 {
			n = len(a) + n
		}
		if n < 1 {
			panic(errors.New("Lua select index"))
		}
		return a[min(n, len(a)):]
	})
	g["rawequal"] = luaBuiltin(func(_ *luaVM, a []any) []any { return []any{luaEqual(luaArg(a, 0), luaArg(a, 1))} })
	g["rawget"] = luaBuiltin(func(vm *luaVM, a []any) []any { return []any{vm.index(luaTableArg(a, 0), luaArg(a, 1))} })
	g["rawset"] = luaBuiltin(func(vm *luaVM, a []any) []any { vm.set(luaTableArg(a, 0), luaArg(a, 1), luaArg(a, 2)); return a[:1] })
	next := luaBuiltin(func(vm *luaVM, a []any) []any {
		t := luaTableArg(a, 0)
		previous := luaArg(a, 1)
		keys := make([]any, 0, len(t.values))
		for k := range t.values {
			vm.tick()
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			vm.tick()
			x, y := keys[i], keys[j]
			tx, ty := luaType(x), luaType(y)
			if tx != ty {
				return tx < ty
			}
			switch x := x.(type) {
			case float64:
				return x < y.(float64)
			case string:
				return x < y.(string)
			case bool:
				return !x && y.(bool)
			}
			return fmt.Sprintf("%p", x) < fmt.Sprintf("%p", y)
		})
		found := previous == nil
		for _, key := range keys {
			if found {
				return []any{key, t.values[key]}
			}
			if luaEqual(key, previous) {
				found = true
			}
		}
		if !found {
			panic(errors.New("Lua invalid next key"))
		}
		return []any{nil}
	})
	g["next"] = next
	g["pairs"] = luaBuiltin(func(vm *luaVM, a []any) []any {
		t := luaTableArg(a, 0)
		vm.alloc(64 + len(t.values)*32)
		keys := make([]any, 0, len(t.values))
		for k := range t.values {
			keys = append(keys, k)
		}
		position := 0
		iterator := luaBuiltin(func(vm *luaVM, _ []any) []any {
			for position < len(keys) {
				vm.tick()
				k := keys[position]
				position++
				if x := t.values[k]; x != nil {
					return []any{k, x}
				}
			}
			return []any{nil}
		})
		return []any{&luaClosure{fn: iterator, roots: append([]any{t}, keys...)}, t, nil}
	})
	g["ipairs"] = luaBuiltin(func(_ *luaVM, a []any) []any {
		t := luaTableArg(a, 0)
		f := luaBuiltin(func(vm *luaVM, a []any) []any {
			n := luaNum(luaArg(a, 1)) + 1
			x := vm.index(t, n)
			if x == nil {
				return []any{nil}
			}
			return []any{n, x}
		})
		return []any{&luaClosure{fn: f, roots: []any{t}}, t, float64(0)}
	})
	stringLib := map[string]any{}
	stringLib["len"] = luaBuiltin(func(_ *luaVM, a []any) []any { return []any{float64(len(luaString(a, 0)))} })
	stringLib["sub"] = luaBuiltin(func(_ *luaVM, a []any) []any {
		s := luaString(a, 0)
		i, j := luaBounds(len(s), luaInteger(a, 1, 1), luaInteger(a, 2, -1))
		return []any{strings.Clone(s[i:j])}
	})
	stringLib["byte"] = luaBuiltin(func(vm *luaVM, a []any) []any {
		s := luaString(a, 0)
		start := luaInteger(a, 1, 1)
		i, j := luaBounds(len(s), start, luaInteger(a, 2, start))
		if j-i > 4096 {
			panic(errors.New("Lua byte result limit"))
		}
		out := make([]any, j-i)
		vm.alloc(len(out) * 16)
		for k := range out {
			out[k] = float64(s[i+k])
		}
		return out
	})
	stringLib["char"] = luaBuiltin(func(vm *luaVM, a []any) []any {
		vm.alloc(len(a))
		b := make([]byte, len(a))
		for i, x := range a {
			n := luaInt(x)
			if n < 0 || n > 255 {
				panic(errors.New("Lua character outside0-255"))
			}
			b[i] = byte(n)
		}
		return []any{string(b)}
	})
	stringLib["rep"] = luaBuiltin(func(vm *luaVM, a []any) []any {
		s := luaString(a, 0)
		n := luaInteger(a, 1, 0)
		sep := ""
		if luaArg(a, 2) != nil {
			sep = luaString(a, 2)
		}
		if n <= 0 {
			return []any{""}
		}
		if n > luaStringLimit || len(s)+len(sep) > luaStringLimit/n {
			panic(errors.New("Lua repetition limit"))
		}
		vm.alloc((len(s) + len(sep)) * n)
		return []any{strings.TrimSuffix(strings.Repeat(s+sep, n), sep)}
	})
	stringLib["reverse"] = luaBuiltin(func(vm *luaVM, a []any) []any {
		s := luaString(a, 0)
		vm.alloc(len(s))
		b := []byte(s)
		for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
		return []any{string(b)}
	})
	stringLib["lower"] = luaBuiltin(func(vm *luaVM, a []any) []any {
		s := luaString(a, 0)
		vm.alloc(len(s))
		return []any{luaASCIIcase(s, false)}
	})
	stringLib["upper"] = luaBuiltin(func(vm *luaVM, a []any) []any {
		s := luaString(a, 0)
		vm.alloc(len(s))
		return []any{luaASCIIcase(s, true)}
	})
	stringLib["format"] = luaBuiltin(luaFormat)
	stringLib["find"] = luaBuiltin(func(vm *luaVM, a []any) []any {
		s, pat := luaString(a, 0), luaString(a, 1)
		start := luaInteger(a, 2, 1)
		if start < 0 {
			start = len(s) + start + 1
		}
		start = max(1, start) - 1
		if start > len(s) {
			return []any{nil}
		}
		if luaTruthy(luaArg(a, 3)) {
			i := strings.Index(s[start:], pat)
			if i < 0 {
				return []any{nil}
			}
			return []any{float64(start + i + 1), float64(start + i + len(pat))}
		}
		i, j, c, ok := luaSearch(vm, s, pat, start)
		if !ok {
			return []any{nil}
		}
		return append([]any{float64(i + 1), float64(j)}, c...)
	})
	stringLib["match"] = luaBuiltin(func(vm *luaVM, a []any) []any {
		s := luaString(a, 0)
		start := luaInteger(a, 2, 1)
		if start < 0 {
			start = len(s) + start + 1
		}
		start = max(start, 1) - 1
		if start > len(s) {
			return []any{nil}
		}
		i, j, c, ok := luaSearch(vm, s, luaString(a, 1), start)
		if !ok {
			return []any{nil}
		}
		if len(c) > 0 {
			return c
		}
		return []any{strings.Clone(s[i:j])}
	})
	stringLib["gmatch"] = luaBuiltin(func(_ *luaVM, a []any) []any {
		s, pat := luaString(a, 0), luaString(a, 1)
		position, last := 0, -1
		return []any{&luaClosure{roots: []any{s, pat}, fn: luaBuiltin(func(vm *luaVM, _ []any) []any {
			for position <= len(s) {
				i, j, c, ok := luaSearch(vm, s, pat, position)
				if !ok {
					return []any{nil}
				}
				position = j
				if j == last {
					position++
					continue
				}
				last = j
				if len(c) > 0 {
					return c
				}
				return []any{strings.Clone(s[i:j])}
			}
			return []any{nil}
		})}}
	})
	stringLib["gsub"] = luaBuiltin(luaGsub)
	g["string"] = luaModule(stringLib)
	table := map[string]any{}
	table["concat"] = luaBuiltin(func(vm *luaVM, a []any) []any {
		t := luaTableArg(a, 0)
		sep := ""
		if luaArg(a, 1) != nil {
			sep = luaString(a, 1)
		}
		start, end := luaInteger(a, 2, 1), luaInteger(a, 3, luaLength(t))
		var b strings.Builder
		for i := start; i <= end; i++ {
			vm.tick()
			if i > start {
				vm.alloc(len(sep))
				b.WriteString(sep)
			}
			s := luaText(t.values[float64(i)])
			vm.alloc(len(s))
			b.WriteString(s)
			if b.Len() > luaStringLimit {
				panic(errors.New("Lua concat limit"))
			}
		}
		return []any{b.String()}
	})
	table["insert"] = luaBuiltin(func(vm *luaVM, a []any) []any {
		t := luaTableArg(a, 0)
		n := luaLength(t)
		pos := n + 1
		x := luaArg(a, 1)
		if len(a) > 2 {
			pos = luaInteger(a, 1, n+1)
			x = a[2]
		}
		if pos < 1 || pos > n+1 {
			panic(errors.New("Lua insert index"))
		}
		for i := n; i >= pos; i-- {
			vm.tick()
			vm.set(t, float64(i+1), t.values[float64(i)])
		}
		vm.set(t, float64(pos), x)
		return nil
	})
	table["remove"] = luaBuiltin(func(vm *luaVM, a []any) []any {
		t := luaTableArg(a, 0)
		n := luaLength(t)
		pos := luaInteger(a, 1, n)
		if pos < 1 || pos > n {
			return []any{nil}
		}
		x := t.values[float64(pos)]
		for i := pos; i < n; i++ {
			vm.tick()
			t.values[float64(i)] = t.values[float64(i+1)]
		}
		delete(t.values, float64(n))
		return []any{x}
	})
	table["unpack"] = luaBuiltin(func(vm *luaVM, a []any) []any {
		t := luaTableArg(a, 0)
		start, end := luaInteger(a, 1, 1), luaInteger(a, 2, luaLength(t))
		if end-start > 4096 {
			panic(errors.New("Lua unpack limit"))
		}
		var out []any
		for i := start; i <= end; i++ {
			vm.tick()
			out = append(out, t.values[float64(i)])
		}
		return out
	})
	table["pack"] = luaBuiltin(func(vm *luaVM, a []any) []any {
		t := luaModule(map[string]any{"n": float64(len(a))})
		for i, x := range a {
			vm.set(t, float64(i+1), x)
		}
		return []any{t}
	})
	table["sort"] = luaBuiltin(func(vm *luaVM, a []any) []any {
		t := luaTableArg(a, 0)
		items := make([]any, luaLength(t))
		for i := range items {
			items[i] = t.values[float64(i+1)]
		}
		sort.SliceStable(items, func(i, j int) bool {
			vm.tick()
			if luaArg(a, 1) != nil {
				return luaTruthy(luaOne(vm.call(a[1], []any{items[i], items[j]})))
			}
			if s, ok := items[i].(string); ok {
				return s < luaText(items[j])
			}
			return luaNum(items[i]) < luaNum(items[j])
		})
		for i, x := range items {
			t.values[float64(i+1)] = x
		}
		return nil
	})
	g["table"] = luaModule(table)
	g["unpack"] = table["unpack"]
	mathLib := map[string]any{"pi": math.Pi, "huge": math.Inf(1)}
	for name, f := range map[string]func(float64) float64{"abs": math.Abs, "floor": math.Floor, "ceil": math.Ceil, "sqrt": math.Sqrt, "exp": math.Exp, "log": math.Log, "sin": math.Sin, "cos": math.Cos, "tan": math.Tan, "asin": math.Asin, "acos": math.Acos, "deg": func(x float64) float64 { return x * 180 / math.Pi }, "rad": func(x float64) float64 { return x * math.Pi / 180 }} {
		mathLib[name] = luaBuiltin(func(_ *luaVM, a []any) []any { return []any{f(luaNum(luaArg(a, 0)))} })
	}
	for name, f := range map[string]func(float64, float64) float64{"min": math.Min, "max": math.Max, "pow": math.Pow, "fmod": math.Mod} {
		mathLib[name] = luaBuiltin(func(_ *luaVM, a []any) []any {
			x := luaNum(luaArg(a, 0))
			for _, y := range a[1:] {
				x = f(x, luaNum(y))
			}
			return []any{x}
		})
	}
	mathLib["random"] = luaBuiltin(func(_ *luaVM, a []any) []any {
		var b [8]byte
		if _, e := rand.Read(b[:]); e != nil {
			panic(e)
		}
		n := binary.BigEndian.Uint64(b[:])
		if len(a) == 0 {
			return []any{float64(n>>11) / (1 << 53)}
		}
		lo, hi := 1, luaInteger(a, 0, 1)
		if len(a) > 1 {
			lo, hi = hi, luaInteger(a, 1, 1)
		}
		if hi < lo {
			panic(errors.New("Lua empty random interval"))
		}
		return []any{float64(lo + int(n%uint64(int64(hi)-int64(lo)+1)))}
	})
	g["math"] = luaModule(mathLib)
	bit := map[string]any{}
	for name, f := range map[string]func(uint32, uint32) uint32{"band": func(a, b uint32) uint32 { return a & b }, "bor": func(a, b uint32) uint32 { return a | b }, "bxor": func(a, b uint32) uint32 { return a ^ b }} {
		bit[name] = luaBuiltin(func(_ *luaVM, a []any) []any {
			x := uint32(luaInt(luaArg(a, 0)))
			for _, y := range a[1:] {
				x = f(x, uint32(luaInt(y)))
			}
			return []any{float64(x)}
		})
	}
	bit["bnot"] = luaBuiltin(func(_ *luaVM, a []any) []any { return []any{float64(^uint32(luaInt(luaArg(a, 0))))} })
	for _, name := range []string{"lshift", "rshift", "arshift", "lrotate", "rrotate", "rol", "ror"} {
		bit[name] = luaBuiltin(func(_ *luaVM, a []any) []any {
			x, n := uint32(luaInt(luaArg(a, 0))), luaInteger(a, 1, 0)
			switch name {
			case "lrotate", "rol":
				x = bits.RotateLeft32(x, n)
			case "rrotate", "ror":
				x = bits.RotateLeft32(x, -n)
			case "arshift":
				if n < 0 {
					x <<= uint(-n)
				} else {
					x = uint32(int32(x) >> uint(n))
				}
			case "lshift":
				if n < 0 {
					x >>= uint(-n)
				} else {
					x <<= uint(n)
				}
			default:
				if n < 0 {
					x <<= uint(-n)
				} else {
					x >>= uint(n)
				}
			}
			return []any{float64(x)}
		})
	}
	g["bit32"] = luaModule(bit)
	return v
}
func luaProtected(vm *luaVM, a []any) (out []any) {
	defer func() {
		if p := recover(); p != nil {
			if e, ok := p.(error); ok {
				out = []any{false, e.Error()}
			} else {
				panic(p)
			}
		}
	}()
	return append([]any{true}, vm.call(luaArg(a, 0), a[1:])...)
}
func luaFormat(vm *luaVM, a []any) []any {
	s := luaString(a, 0)
	index := 1
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		vm.tick()
		if s[i] != '%' {
			out.WriteByte(s[i])
			continue
		}
		start := i
		i++
		if i < len(s) && s[i] == '%' {
			out.WriteByte('%')
			continue
		}
		for i < len(s) && strings.ContainsRune("-+ #0.123456789", rune(s[i])) {
			i++
		}
		if i == len(s) || i-start > 12 {
			panic(errors.New("Lua invalid format"))
		}
		spec := s[start : i+1]
		var x any
		switch s[i] {
		case 's':
			x = luaString(a, index)
		case 'q':
			x = luaString(a, index)
			spec = "%q"
		case 'c':
			x = rune(luaInt(luaArg(a, index)))
		case 'd', 'i', 'o', 'u', 'x', 'X':
			x = luaInt(luaArg(a, index))
			if s[i] == 'i' || s[i] == 'u' {
				spec = spec[:len(spec)-1] + "d"
			}
		case 'e', 'E', 'f', 'g', 'G':
			x = luaNum(luaArg(a, index))
		default:
			panic(errors.New("Lua unsupported format"))
		}
		index++
		// Width and precision must be bounded before fmt allocates.
		for _, part := range strings.FieldsFunc(spec, func(r rune) bool { return r < '0' || r > '9' }) {
			n, e := strconv.Atoi(part)
			if e != nil || n > 4096 {
				panic(errors.New("Lua format width limit"))
			}
		}
		text := fmt.Sprintf(spec, x)
		vm.alloc(len(text))
		out.WriteString(text)
		if out.Len() > luaStringLimit {
			panic(errors.New("Lua format limit"))
		}
	}
	return []any{out.String()}
}
func luaGsub(vm *luaVM, a []any) []any {
	s, pat := luaString(a, 0), luaString(a, 1)
	replacement := luaArg(a, 2)
	maximum := luaInteger(a, 3, len(s)+1)
	var out strings.Builder
	position, count, last := 0, 0, -1
	for position <= len(s) && count < maximum {
		vm.tick()
		i, j, c, ok := luaSearch(vm, s, pat, position)
		if !ok {
			break
		}
		if j == last {
			if position < len(s) {
				out.WriteByte(s[position])
				position++
				continue
			}
			break
		}
		out.WriteString(s[position:i])
		matched := strings.Clone(s[i:j])
		args := c
		if len(args) == 0 {
			args = []any{matched}
		}
		var text any
		switch r := replacement.(type) {
		case string:
			var b strings.Builder
			for k := 0; k < len(r); k++ {
				if r[k] != '%' {
					b.WriteByte(r[k])
					continue
				}
				k++
				if k == len(r) {
					panic(errors.New("Lua invalid replacement"))
				}
				if r[k] == '%' {
					b.WriteByte('%')
				} else if r[k] == '0' {
					b.WriteString(matched)
				} else if r[k] >= '1' && r[k] <= '9' && int(r[k]-'1') < len(args) {
					b.WriteString(luaDescribe(args[int(r[k]-'1')]))
				} else {
					panic(errors.New("Lua invalid replacement capture"))
				}
			}
			text = b.String()
		case *luaTable:
			text = vm.index(r, args[0])
		case *luaFunction, *luaClosure, *luaBuiltinFunction:
			text = luaOne(vm.call(r, args))
		default:
			panic(errors.New("Lua invalid replacement type"))
		}
		if text == nil || text == false {
			text = matched
		}
		chunk := luaText(text)
		vm.alloc(len(chunk))
		out.WriteString(chunk)
		if out.Len() > luaStringLimit {
			panic(errors.New("Lua substitution limit"))
		}
		count++
		position = j
		last = j
		if strings.HasPrefix(pat, "^") {
			break
		}
	}
	out.WriteString(s[position:])
	vm.alloc(out.Len())
	return []any{out.String(), float64(count)}
}

func luaASCIIcase(s string, upper bool) string {
	b := []byte(s)
	for i, c := range b {
		if upper && c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
		if !upper && c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
