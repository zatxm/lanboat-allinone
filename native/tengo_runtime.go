package native

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

type tengoChar rune
type tengoError struct{ value any }
type tengoCollection struct {
	array     []any
	object    map[string]any
	bytes     []byte
	immutable bool
}
type TengoFunction func(context.Context, []any) (any, error)
type TengoProgram struct {
	program *luaNode
	modules map[string]map[string]TengoFunction
}
type tengoExecution struct {
	ctx     context.Context
	modules map[string]map[string]TengoFunction
}

func NewTengoProgram(source string, modules map[string]map[string]TengoFunction) (*TengoProgram, error) {
	program, err := compileTengo(source)
	if err != nil {
		return nil, err
	}
	copied := map[string]map[string]TengoFunction{}
	for name, entries := range modules {
		copy := map[string]TengoFunction{}
		for key, value := range entries {
			copy[key] = value
		}
		copied[name] = copy
	}
	return &TengoProgram{program: program, modules: copied}, nil
}
func (p *TengoProgram) Run(ctx context.Context, input map[string]any) (any, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	vm := &luaVM{globals: luaScope(nil), tengo: &tengoExecution{ctx: ctx, modules: p.modules}}
	values, err := vm.run(func() []any {
		vm.installTengo()
		for name, value := range input {
			vm.globals.values[name] = vm.tengoImport(value, 0)
		}
		scope, jump := vm.block(p.program, vm.globals)
		if jump.kind == "return" {
			return jump.values
		}
		if jump.kind != "" {
			panic(errors.New("Tengo loop control outside a loop"))
		}
		return []any{scope.get("out")}
	})
	if err != nil {
		return nil, fmt.Errorf("%s", strings.ReplaceAll(err.Error(), "Lua", "Tengo"))
	}
	return exportTengo(luaOne(values), map[*tengoCollection]bool{})
}
func tengoTruthy(value any) bool {
	switch value := value.(type) {
	case nil:
		return false
	case bool:
		return value
	case int64:
		return value != 0
	case float64:
		return !math.IsNaN(value)
	case *tengoError:
		return false
	case time.Time:
		return !value.IsZero()
	case tengoChar:
		return value != 0
	case string:
		return value != ""
	case *tengoCollection:
		return len(value.array)+len(value.object)+len(value.bytes) > 0
	}
	return true
}
func tengoLength(value any) int {
	switch v := value.(type) {
	case string:
		return len(v)
	case *tengoCollection:
		return len(v.array) + len(v.object) + len(v.bytes)
	}
	panic(errors.New("Tengo len requires string,bytes,array or map"))
}
func tengoInt(value any) int64 {
	switch v := value.(type) {
	case int64:
		return v
	case tengoChar:
		return int64(v)
	case float64:
		if !math.IsInf(v, 0) && !math.IsNaN(v) && v >= math.MinInt64 && v < math.MaxInt64 {
			return int64(v)
		}
	}
	panic(errors.New("Tengo expected integer"))
}
func tengoFloat(value any) float64 {
	switch v := value.(type) {
	case int64:
		return float64(v)
	case tengoChar:
		return float64(v)
	case float64:
		return v
	}
	panic(errors.New("Tengo expected number"))
}
func tengoText(value any) string {
	switch v := value.(type) {
	case nil:
		return "<undefined>"
	case string:
		return v
	case tengoChar:
		return string(rune(v))
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'g', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	case *tengoError:
		return "error: " + tengoText(v.value)
	case time.Time:
		return v.String()
	case *tengoCollection:
		if v.bytes != nil {
			return string(v.bytes)
		}
		value, err := exportTengo(v, map[*tengoCollection]bool{})
		if err != nil {
			panic(err)
		}
		data, err := json.Marshal(value)
		if err != nil || len(data) > luaStringLimit {
			panic(errors.New("Tengo string conversion exceeds limit"))
		}
		return string(data)
	}
	return fmt.Sprint(value)
}
func (v *luaVM) tengoImport(value any, depth int) any {
	if depth > 96 {
		panic(errors.New("Tengo input nesting limit"))
	}
	switch x := value.(type) {
	case string:
		v.alloc(len(x))
		return x
	case nil, bool, int64, float64, tengoChar, time.Time, *tengoCollection, *tengoError, *luaBuiltinFunction, *luaFunction:
		return value
	case int:
		return int64(x)
	case uint:
		if uint64(x) > math.MaxInt64 {
			panic(errors.New("Tengo integer overflow"))
		}
		return int64(x)
	case uint64:
		if x > math.MaxInt64 {
			panic(errors.New("Tengo integer overflow"))
		}
		return int64(x)
	case int32:
		return int64(x)
	case []byte:
		v.alloc(len(x))
		return &tengoCollection{bytes: append([]byte{}, x...)}
	case []any:
		if len(x) > 16384 {
			panic(errors.New("Tengo array entry limit"))
		}
		v.alloc(64 + len(x)*16)
		out := &tengoCollection{array: make([]any, len(x))}
		for i, item := range x {
			out.array[i] = v.tengoImport(item, depth+1)
		}
		return out
	case map[string]any:
		if len(x) > 16384 {
			panic(errors.New("Tengo map entry limit"))
		}
		v.alloc(64 + len(x)*48)
		out := &tengoCollection{object: map[string]any{}}
		for key, item := range x {
			out.object[key] = v.tengoImport(item, depth+1)
		}
		return out
	case error:
		return &tengoError{value: x.Error()}
	}
	panic(errors.New("Tengo unsupported host value"))
}
func exportTengo(value any, seen map[*tengoCollection]bool) (any, error) {
	budget := luaHeapLimit
	return exportTengoValue(value, seen, 0, &budget)
}
func exportTengoValue(value any, seen map[*tengoCollection]bool, depth int, budget *int) (any, error) {
	*budget -= 16
	if depth > 96 || *budget < 0 {
		return nil, errors.New("Tengo output exceeds size or nesting limit")
	}
	switch x := value.(type) {
	case string:
		*budget -= len(x)
		if *budget < 0 {
			return nil, errors.New("Tengo output exceeds size limit")
		}
		return x, nil
	case *tengoError:
		value, err := exportTengoValue(x.value, seen, depth+1, budget)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("Tengo error: %v", value)
	case tengoChar:
		return rune(x), nil
	case *tengoCollection:
		if seen[x] {
			return nil, errors.New("Tengo cyclic output")
		}
		seen[x] = true
		defer delete(seen, x)
		if x.bytes != nil {
			*budget -= len(x.bytes)
			if *budget < 0 {
				return nil, errors.New("Tengo output exceeds size limit")
			}
			return append([]byte{}, x.bytes...), nil
		}
		if x.object != nil {
			out := map[string]any{}
			for key, item := range x.object {
				*budget -= 48 + len(key)
				converted, err := exportTengoValue(item, seen, depth+1, budget)
				if err != nil {
					return nil, err
				}
				out[key] = converted
			}
			return out, nil
		}
		out := make([]any, len(x.array))
		for i, item := range x.array {
			converted, err := exportTengoValue(item, seen, depth+1, budget)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	case *luaFunction, *luaBuiltinFunction:
		return nil, errors.New("Tengo cannot export a function")
	default:
		return value, nil
	}
}
func (v *luaVM) tengoIndex(value, key any) any {
	switch x := value.(type) {
	case *tengoError:
		if key == "value" {
			return x.value
		}
		return nil
	case *tengoCollection:
		if x.object != nil {
			k, ok := key.(string)
			if !ok {
				panic(errors.New("Tengo map index must be a string"))
			}
			return x.object[k]
		}
		i := tengoInt(key)
		if i < 0 || i >= int64(tengoLength(x)) {
			return nil
		}
		if x.bytes != nil {
			return int64(x.bytes[i])
		}
		return x.array[i]
	case string:
		i := tengoInt(key)
		if i < 0 || i >= int64(len(x)) {
			return nil
		}
		return tengoChar(x[i])
	}
	panic(errors.New("Tengo index requires a collection"))
}
func (v *luaVM) tengoSet(value, key, item any) {
	x, ok := value.(*tengoCollection)
	if !ok || x.immutable {
		panic(errors.New("Tengo assignment requires a mutable collection"))
	}
	if x.object != nil {
		k, ok := key.(string)
		if !ok {
			panic(errors.New("Tengo map index must be a string"))
		}
		if _, present := x.object[k]; !present {
			if len(x.object) >= 16384 {
				panic(errors.New("Tengo map entry limit"))
			}
			v.alloc(48 + len(k))
		}
		x.object[k] = item
		return
	}
	i := tengoInt(key)
	if i < 0 || i >= int64(tengoLength(x)) {
		panic(errors.New("Tengo index outside collection"))
	}
	if x.bytes != nil {
		n := tengoInt(item)
		if n < 0 || n > 255 {
			panic(errors.New("Tengo byte outside0..255"))
		}
		x.bytes[i] = byte(n)
	} else {
		x.array[i] = item
	}
}
func (v *luaVM) tengoEqual(a, b any, seen map[[2]*tengoCollection]bool) bool {
	v.tick()
	if x, ok := a.(time.Time); ok {
		y, ok := b.(time.Time)
		return ok && x.Equal(y)
	}
	x, xa := a.(*tengoCollection)
	y, ya := b.(*tengoCollection)
	if xa || ya {
		if !xa || !ya {
			return false
		}
		if x == y {
			return true
		}
		if (x.object == nil) != (y.object == nil) || (x.bytes == nil) != (y.bytes == nil) || tengoLength(x) != tengoLength(y) {
			return false
		}
		pair := [2]*tengoCollection{x, y}
		if seen[pair] {
			return true
		}
		seen[pair] = true
		if x.object != nil {
			for key, item := range x.object {
				other, present := y.object[key]
				if !present || !v.tengoEqual(item, other, seen) {
					return false
				}
			}
		} else if x.bytes != nil {
			for i, item := range x.bytes {
				if item != y.bytes[i] {
					return false
				}
			}
		} else {
			for i, item := range x.array {
				if !v.tengoEqual(item, y.array[i], seen) {
					return false
				}
			}
		}
		return true
	}
	if reflect.TypeOf(a) != reflect.TypeOf(b) {
		return false
	}
	return a == b
}
func (v *luaVM) tengoBinary(op string, a, b any) any {
	if op == "==" || op == "!=" {
		equal := v.tengoEqual(a, b, map[[2]*tengoCollection]bool{})
		return equal == (op == "==")
	}
	if x, ok := a.(time.Time); ok {
		if y, ok := b.(time.Time); ok {
			switch op {
			case "-":
				return int64(x.Sub(y))
			case "<":
				return x.Before(y)
			case "<=":
				return !x.After(y)
			case ">":
				return x.After(y)
			case ">=":
				return !x.Before(y)
			}
		} else if y, ok := b.(int64); ok {
			if op == "+" {
				return x.Add(time.Duration(y))
			}
			if op == "-" {
				return x.Add(-time.Duration(y))
			}
		}
		panic(errors.New("Tengo invalid time operand"))
	}
	if x, ok := a.(*tengoCollection); ok && x.array != nil && op == "+" {
		y, ok := b.(*tengoCollection)
		if !ok || y.array == nil || len(x.array)+len(y.array) > 16384 {
			panic(errors.New("Tengo invalid array concatenation"))
		}
		v.alloc(64 + 16*(len(x.array)+len(y.array)))
		return &tengoCollection{array: append(append([]any{}, x.array...), y.array...)}
	}
	if x, ok := a.(string); ok {
		y, ok := b.(string)
		if !ok {
			panic(errors.New("Tengo incompatible string operand"))
		}
		switch op {
		case "+":
			v.alloc(len(x) + len(y))
			return x + y
		case "<":
			return x < y
		case ">":
			return x > y
		case "<=":
			return x <= y
		case ">=":
			return x >= y
		}
	}
	_, af := a.(float64)
	_, bf := b.(float64)
	if af || bf {
		x, y := tengoFloat(a), tengoFloat(b)
		switch op {
		case "+":
			return x + y
		case "-":
			return x - y
		case "*":
			return x * y
		case "/":
			if y == 0 {
				panic(errors.New("Tengo division by zero"))
			}
			return x / y
		case "<":
			return x < y
		case ">":
			return x > y
		case "<=":
			return x <= y
		case ">=":
			return x >= y
		}
	}
	x, y := tengoInt(a), tengoInt(b)
	switch op {
	case "+":
		return x + y
	case "-":
		return x - y
	case "*":
		return x * y
	case "/":
		if y == 0 {
			panic(errors.New("Tengo division by zero"))
		}
		return x / y
	case "%":
		if y == 0 {
			panic(errors.New("Tengo remainder by zero"))
		}
		return x % y
	case "&":
		return x & y
	case "|":
		return x | y
	case "^":
		return x ^ y
	case "&^":
		return x &^ y
	case "<<":
		if y < 0 {
			panic(errors.New("Tengo negative shift"))
		}
		return x << uint64(y)
	case ">>":
		if y < 0 {
			panic(errors.New("Tengo negative shift"))
		}
		return x >> uint64(y)
	case "<":
		return x < y
	case ">":
		return x > y
	case "<=":
		return x <= y
	case ">=":
		return x >= y
	}
	panic(errors.New("Tengo invalid binary operation"))
}
func (v *luaVM) tengoEval(n *luaNode, e *luaEnv) []any {
	value := func(i int) any { return luaOne(v.eval(n.children[i], e)) }
	one := func(value any) []any { return []any{value} }
	switch n.text {
	case "array":
		v.alloc(64 + 16*len(n.children))
		a := &tengoCollection{array: make([]any, len(n.children))}
		for i := range n.children {
			a.array[i] = value(i)
		}
		return one(a)
	case "map":
		v.alloc(64 + 24*len(n.children))
		m := &tengoCollection{object: map[string]any{}}
		for i := 0; i < len(n.children); i += 2 {
			m.object[value(i).(string)] = value(i + 1)
		}
		return one(m)
	case "index":
		return one(v.tengoIndex(value(0), value(1)))
	case "unary":
		a := value(0)
		switch n.value.(string) {
		case "!":
			return one(!tengoTruthy(a))
		case "+":
			return one(a)
		case "-":
			if x, ok := a.(float64); ok {
				return one(-x)
			}
			return one(-tengoInt(a))
		case "^":
			return one(^tengoInt(a))
		}
	case "binary":
		a := value(0)
		op := n.value.(string)
		if op == "&&" {
			if !tengoTruthy(a) {
				return one(a)
			}
			return one(value(1))
		}
		if op == "||" {
			if tengoTruthy(a) {
				return one(a)
			}
			return one(value(1))
		}
		return one(v.tengoBinary(op, a, value(1)))
	case "conditional":
		if tengoTruthy(value(0)) {
			return one(value(1))
		}
		return one(value(2))
	case "call":
		fn := value(0)
		var args []any
		for _, arg := range n.children[1:] {
			if arg.op == "tengo_expr" && arg.text == "spread" {
				array, ok := luaOne(v.eval(arg.children[0], e)).(*tengoCollection)
				if !ok || array.array == nil {
					panic(errors.New("Tengo spread requires array"))
				}
				args = append(args, array.array...)
			} else {
				args = append(args, v.eval(arg, e)...)
			}
			if len(args) > 16384 {
				panic(errors.New("Tengo argument limit"))
			}
		}
		return v.call(fn, args)
	case "slice":
		a := value(0)
		length := tengoLength(a)
		from, to := int64(0), int64(length)
		if n.children[1] != nil {
			from = tengoInt(value(1))
		}
		if n.children[2] != nil {
			to = tengoInt(value(2))
		}
		if from < 0 || to < from || to > int64(length) {
			panic(errors.New("Tengo slice outside bounds"))
		}
		if text, ok := a.(string); ok {
			v.alloc(int(to - from))
			return one(text[from:to])
		}
		collection := a.(*tengoCollection)
		v.alloc(int(to-from)*16 + 64)
		if collection.bytes != nil {
			return one(&tengoCollection{bytes: append([]byte{}, collection.bytes[from:to]...), immutable: collection.immutable})
		}
		if collection.object != nil {
			panic(errors.New("Tengo map cannot be sliced"))
		}
		return one(&tengoCollection{array: append([]any{}, collection.array[from:to]...), immutable: collection.immutable})
	}
	panic(errors.New("Tengo invalid expression"))
}
func (v *luaVM) tengoBlockStatement(n *luaNode, e *luaEnv) (*luaEnv, luaJump) {
	value := func(node *luaNode, scope *luaEnv) any { return luaOne(v.eval(node, scope)) }
	switch n.text {
	case "expression":
		v.eval(n.children[0], e)
	case "return":
		return e, luaJump{kind: "return", values: v.values(n.children, e)}
	case "break", "continue":
		return e, luaJump{kind: n.text}
	case "if":
		scope := luaScope(e)
		if n.children[0] != nil {
			scope, _ = v.tengoBlockStatement(n.children[0], scope)
		}
		branch := 2
		if !tengoTruthy(value(n.children[1], scope)) {
			branch = 3
		}
		if branch < len(n.children) {
			_, jump := v.block(n.children[branch], luaScope(scope))
			return e, jump
		}
	case "for":
		scope := luaScope(e)
		if n.children[0] != nil {
			scope, _ = v.tengoBlockStatement(n.children[0], scope)
		}
		for tengoTruthy(value(n.children[1], scope)) {
			v.tick()
			_, jump := v.block(n.children[3], luaScope(scope))
			if jump.kind == "return" {
				return e, jump
			}
			if jump.kind == "break" {
				break
			}
			if n.children[2] != nil {
				scope, _ = v.tengoBlockStatement(n.children[2], scope)
			}
		}
	case "each":
		collection := value(n.children[0], e)
		names := n.value.([]string)
		var keys, values []any
		switch x := collection.(type) {
		case nil:
			return e, luaJump{}
		case *tengoCollection:
			if x.object != nil {
				var sorted []string
				for key := range x.object {
					sorted = append(sorted, key)
				}
				sort.Strings(sorted)
				for _, key := range sorted {
					keys = append(keys, key)
					values = append(values, x.object[key])
				}
			} else if x.bytes != nil {
				for i, b := range x.bytes {
					keys = append(keys, int64(i))
					values = append(values, int64(b))
				}
			} else {
				for i, item := range x.array {
					keys = append(keys, int64(i))
					values = append(values, item)
				}
			}
		case string:
			for i, r := range x {
				keys = append(keys, int64(i))
				values = append(values, tengoChar(r))
			}
		default:
			panic(errors.New("Tengo iteration requires collection"))
		}
		for i, key := range keys {
			v.tick()
			scope := luaScope(e)
			if len(names) == 1 {
				scope.values[names[0]] = values[i]
			} else {
				scope.values[names[0]] = key
				scope.values[names[1]] = values[i]
			}
			_, jump := v.block(n.children[1], scope)
			if jump.kind == "return" {
				return e, jump
			}
			if jump.kind == "break" {
				break
			}
		}
	default:
		count := n.value.(int)
		type target struct {
			scope           *luaEnv
			name            string
			collection, key any
		}
		targets := make([]target, count)
		if n.text == ":=" {
			e = luaScope(e)
			v.alloc(64 + count*32)
		}
		for i, node := range n.children[:count] {
			if node.op == "name" {
				scope := e
				if n.text != ":=" {
					for scope != nil {
						if _, found := scope.values[node.text]; found {
							break
						}
						scope = scope.parent
					}
					if scope == nil {
						panic(errors.New("Tengo assignment to undefined variable"))
					}
				}
				targets[i] = target{scope: scope, name: node.text}
			} else {
				targets[i] = target{collection: value(node.children[0], e), key: value(node.children[1], e)}
			}
		}
		vals := v.values(n.children[count:], e)
		for i, to := range targets {
			result := luaArg(vals, i)
			if n.text != "=" && n.text != ":=" {
				var old any
				if to.scope != nil {
					old = to.scope.values[to.name]
				} else {
					old = v.tengoIndex(to.collection, to.key)
				}
				result = v.tengoBinary(strings.TrimSuffix(n.text, "="), old, result)
			}
			if to.scope != nil {
				to.scope.values[to.name] = result
			} else {
				v.tengoSet(to.collection, to.key, result)
			}
		}
	}
	return e, luaJump{}
}
