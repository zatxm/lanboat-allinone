package native

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// A source interpreter for the sandboxed backend language. Programs are immutable
// and shared; environments, instruction budgets and callback state are per stream.
type luaToken struct {
	text  string
	value any
	line  int
}
type luaNode struct {
	op       string
	text     string
	value    any
	children []*luaNode
	line     int
}
type luaParser struct {
	tokens     []luaToken
	pos, depth int
}

const luaStringLimit = 1 << 20
const luaHeapLimit = 8 << 20

func luaLex(source string) ([]luaToken, error) {
	if len(source) > 256<<10 {
		return nil, errors.New("Lua source exceeds256KiB")
	}
	var out []luaToken
	line := 1
	for i := 0; i < len(source); {
		c := source[i]
		if c == ' ' || c == '\r' || c == '\t' || c == '\n' {
			if c == '\n' {
				line++
			}
			i++
			continue
		}
		comment := strings.HasPrefix(source[i:], "--")
		if comment {
			i += 2
		}
		if i < len(source) && source[i] == '[' {
			j := i + 1
			for j < len(source) && source[j] == '=' {
				j++
			}
			if j < len(source) && source[j] == '[' {
				close := "]" + source[i+1:j] + "]"
				start := j + 1
				end := strings.Index(source[start:], close)
				if end < 0 {
					return nil, fmt.Errorf("Lua line%d: unfinished long string", line)
				}
				s := source[start : start+end]
				ln := line
				line += strings.Count(s, "\n")
				if strings.HasPrefix(s, "\r\n") {
					s = s[2:]
				} else {
					s = strings.TrimPrefix(s, "\n")
				}
				if !comment {
					out = append(out, luaToken{"string", s, ln})
				}
				i = start + end + len(close)
				continue
			}
		}
		if comment {
			for i < len(source) && source[i] != '\n' {
				i++
			}
			continue
		}
		ln := line
		if c == '\'' || c == '"' {
			quote := c
			i++
			var b strings.Builder
			for i < len(source) && source[i] != quote {
				c = source[i]
				i++
				if c == '\n' || c == '\r' {
					return nil, fmt.Errorf("Lua line%d: newline in string", ln)
				}
				if c == '\\' {
					if i == len(source) {
						break
					}
					c = source[i]
					i++
					switch c {
					case 'a':
						c = 7
					case 'b':
						c = 8
					case 'f':
						c = 12
					case 'n':
						c = 10
					case 'r':
						c = 13
					case 't':
						c = 9
					case 'v':
						c = 11
					case '\\', '\'', '"':
					case '\n':
						line++
						c = '\n'
					case 'z':
						for i < len(source) && strings.ContainsRune(" \t\r\n", rune(source[i])) {
							if source[i] == '\n' {
								line++
							}
							i++
						}
						continue
					case 'x':
						if i+2 > len(source) {
							return nil, errors.New("Lua invalid hex escape")
						}
						n, e := strconv.ParseUint(source[i:i+2], 16, 8)
						if e != nil {
							return nil, errors.New("Lua invalid hex escape")
						}
						c = byte(n)
						i += 2
					default:
						if c < '0' || c > '9' {
							return nil, errors.New("Lua invalid escape")
						}
						n := int(c - '0')
						for k := 0; k < 2 && i < len(source) && source[i] >= '0' && source[i] <= '9'; k++ {
							n = n*10 + int(source[i]-'0')
							i++
						}
						if n > 255 {
							return nil, errors.New("Lua decimal escape exceeds255")
						}
						c = byte(n)
					}
				}
				b.WriteByte(c)
			}
			if i == len(source) {
				return nil, fmt.Errorf("Lua line%d: unfinished string", ln)
			}
			i++
			out = append(out, luaToken{"string", b.String(), ln})
			continue
		}
		if c >= '0' && c <= '9' || c == '.' && i+1 < len(source) && source[i+1] >= '0' && source[i+1] <= '9' {
			start := i
			hex := strings.HasPrefix(strings.ToLower(source[i:]), "0x")
			if hex {
				i += 2
			}
			for i < len(source) {
				d := source[i]
				if d >= '0' && d <= '9' || hex && (d >= 'a' && d <= 'f' || d >= 'A' && d <= 'F') {
					i++
					continue
				}
				if d == '.' && !strings.HasPrefix(source[i:], "..") {
					i++
					continue
				}
				if !hex && (d == 'e' || d == 'E') || hex && (d == 'p' || d == 'P') {
					i++
					if i < len(source) && (source[i] == '+' || source[i] == '-') {
						i++
					}
					for i < len(source) && source[i] >= '0' && source[i] <= '9' {
						i++
					}
				}
				break
			}
			s := source[start:i]
			if hex && !strings.ContainsAny(s, "pP.") {
				n, e := strconv.ParseUint(s[2:], 16, 64)
				if e != nil {
					return nil, errors.New("Lua invalid number")
				}
				out = append(out, luaToken{"number", float64(n), ln})
			} else {
				if hex && !strings.ContainsAny(s, "pP") {
					s += "p0"
				}
				n, e := strconv.ParseFloat(s, 64)
				if e != nil {
					return nil, errors.New("Lua invalid number")
				}
				out = append(out, luaToken{"number", n, ln})
			}
			continue
		}
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			start := i
			i++
			for i < len(source) {
				c = source[i]
				if c != '_' && !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
					break
				}
				i++
			}
			s := source[start:i]
			kind := "name"
			if strings.Contains(" and break do else elseif end false for function goto if in local nil not or repeat return then true until while ", " "+s+" ") {
				kind = s
			}
			out = append(out, luaToken{kind, s, ln})
			continue
		}
		op := ""
		for _, s := range []string{"...", "..", "==", "~=", "<=", ">=", "//", "<<", ">>", "::"} {
			if strings.HasPrefix(source[i:], s) {
				op = s
				break
			}
		}
		if op == "" {
			if !strings.ContainsRune("+-*/%^#&~|<>=(){}[];:,.", rune(c)) {
				return nil, fmt.Errorf("Lua line%d: invalid character", line)
			}
			op = string(c)
		}
		i += len(op)
		out = append(out, luaToken{op, nil, ln})
	}
	out = append(out, luaToken{"eof", nil, line})
	return out, nil
}
func luaCompile(source string) (node *luaNode, err error) {
	defer func() {
		if v := recover(); v != nil {
			if e, ok := v.(error); ok {
				err = e
			} else {
				panic(v)
			}
		}
	}()
	tokens, e := luaLex(source)
	if e != nil {
		return nil, e
	}
	p := luaParser{tokens: tokens}
	node = p.block()
	p.need("eof")
	return
}
func (p *luaParser) token() luaToken  { return p.tokens[p.pos] }
func (p *luaParser) is(s string) bool { return p.token().text == s }
func (p *luaParser) take(s string) bool {
	if p.is(s) {
		p.pos++
		return true
	}
	return false
}
func (p *luaParser) need(s string) luaToken {
	t := p.token()
	if !p.take(s) {
		panic(fmt.Errorf("Lua line%d: expected%s, found%s", t.line, s, t.text))
	}
	return t
}
func (p *luaParser) name() string { return p.need("name").value.(string) }
func (p *luaParser) block() *luaNode {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 128 {
		panic(errors.New("Lua syntax nesting limit"))
	}
	n := &luaNode{op: "block"}
	for !p.is("end") && !p.is("else") && !p.is("elseif") && !p.is("until") && !p.is("eof") {
		if p.take(";") {
			continue
		}
		n.children = append(n.children, p.statement())
	}
	return n
}
func (p *luaParser) statement() *luaNode {
	t := p.token()
	n := &luaNode{line: t.line}
	switch {
	case p.take("local"):
		if p.take("function") {
			n.op = "localfn"
			n.text = p.name()
			n.children = []*luaNode{p.function(false)}
			return n
		}
		n.op = "local"
		for {
			n.children = append(n.children, &luaNode{op: "name", text: p.name()})
			if !p.take(",") {
				break
			}
		}
		n.value = len(n.children)
		if p.take("=") {
			n.children = append(n.children, p.list()...)
		}
		return n
	case p.take("function"):
		target := &luaNode{op: "name", text: p.name()}
		for p.take(".") {
			target = &luaNode{op: "index", children: []*luaNode{target, {op: "literal", value: p.name()}}}
		}
		method := p.take(":")
		if method {
			target = &luaNode{op: "index", children: []*luaNode{target, {op: "literal", value: p.name()}}}
		}
		n.op = "assign"
		n.value = 1
		n.children = []*luaNode{target, p.function(method)}
		return n
	case p.take("return"):
		n.op = "return"
		if !p.is("end") && !p.is("else") && !p.is("elseif") && !p.is("until") && !p.is("eof") && !p.is(";") {
			n.children = p.list()
		}
		p.take(";")
		return n
	case p.take("break"):
		n.op = "break"
		return n
	case p.take("if"):
		n.op = "if"
		for {
			n.children = append(n.children, p.expr(0))
			p.need("then")
			n.children = append(n.children, p.block())
			if !p.take("elseif") {
				break
			}
		}
		if p.take("else") {
			n.children = append(n.children, &luaNode{op: "literal", value: true}, p.block())
		}
		p.need("end")
		return n
	case p.take("while"):
		n.op = "while"
		n.children = append(n.children, p.expr(0))
		p.need("do")
		n.children = append(n.children, p.block())
		p.need("end")
		return n
	case p.take("repeat"):
		n.op = "repeat"
		n.children = append(n.children, p.block())
		p.need("until")
		n.children = append(n.children, p.expr(0))
		return n
	case p.take("do"):
		n = p.block()
		p.need("end")
		return n
	case p.take("for"):
		n.op = "for"
		n.children = append(n.children, &luaNode{op: "name", text: p.name()})
		if p.take("=") {
			n.children = append(n.children, p.expr(0))
			p.need(",")
			n.children = append(n.children, p.expr(0))
			if p.take(",") {
				n.children = append(n.children, p.expr(0))
			} else {
				n.children = append(n.children, &luaNode{op: "literal", value: float64(1)})
			}
		} else {
			n.op = "each"
			for p.take(",") {
				n.children = append(n.children, &luaNode{op: "name", text: p.name()})
			}
			n.value = len(n.children)
			p.need("in")
			n.children = append(n.children, p.list()...)
		}
		p.need("do")
		n.children = append(n.children, p.block())
		p.need("end")
		return n
	default:
		first := p.expr(0)
		if !p.is("=") && !p.is(",") {
			if first.op != "call" && first.op != "method" {
				panic(fmt.Errorf("Lua line%d: expected assignment or call", t.line))
			}
			return first
		}
		n.op = "assign"
		n.children = append(n.children, first)
		for p.take(",") {
			n.children = append(n.children, p.expr(0))
		}
		n.value = len(n.children)
		for _, v := range n.children {
			if v.op != "name" && v.op != "index" {
				panic(errors.New("Lua invalid assignment target"))
			}
		}
		p.need("=")
		n.children = append(n.children, p.list()...)
		return n
	}
}
func (p *luaParser) list() []*luaNode {
	out := []*luaNode{p.expr(0)}
	for p.take(",") {
		out = append(out, p.expr(0))
	}
	return out
}
func (p *luaParser) function(method bool) *luaNode {
	n := &luaNode{op: "function"}
	p.need("(")
	var names []string
	if method {
		names = append(names, "self")
	}
	if !p.is(")") {
		for {
			if p.take("...") {
				n.text = "vararg"
				break
			}
			names = append(names, p.name())
			if !p.take(",") {
				break
			}
		}
	}
	p.need(")")
	n.value = names
	n.children = []*luaNode{p.block()}
	p.need("end")
	return n
}
func luaPrecedence(op string) (int, bool) {
	switch op {
	case "or":
		return 1, false
	case "and":
		return 2, false
	case "<", ">", "<=", ">=", "~=", "==":
		return 3, false
	case "|":
		return 4, false
	case "~":
		return 5, false
	case "&":
		return 6, false
	case "<<", ">>":
		return 7, false
	case "..":
		return 8, true
	case "+", "-":
		return 9, false
	case "*", "/", "//", "%":
		return 10, false
	case "^":
		return 12, true
	}
	return 0, false
}
func (p *luaParser) expr(minimum int) *luaNode {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 128 {
		panic(errors.New("Lua expression nesting limit"))
	}
	t := p.token()
	p.pos++
	n := &luaNode{line: t.line}
	switch t.text {
	case "nil":
		n.op = "literal"
	case "true", "false":
		n.op = "literal"
		n.value = t.text == "true"
	case "number", "string":
		n.op = "literal"
		n.value = t.value
	case "name":
		n.op = "name"
		n.text = t.value.(string)
	case "...":
		n.op = "vararg"
	case "function":
		n = p.function(false)
	case "not", "-", "#", "~":
		n.op = "unary"
		n.text = t.text
		n.children = []*luaNode{p.expr(11)}
	case "(":
		n.op = "paren"
		n.children = []*luaNode{p.expr(0)}
		p.need(")")
	case "{":
		n.op = "table"
		index := 1
		for !p.take("}") {
			var key, value *luaNode
			if p.take("[") {
				key = p.expr(0)
				p.need("]")
				p.need("=")
				value = p.expr(0)
			} else if p.is("name") && p.tokens[p.pos+1].text == "=" {
				key = &luaNode{op: "literal", value: p.name()}
				p.need("=")
				value = p.expr(0)
			} else {
				key = &luaNode{op: "literal", text: "array", value: float64(index)}
				index++
				value = p.expr(0)
			}
			n.children = append(n.children, key, value)
			if !p.take(",") && !p.take(";") {
				p.need("}")
				break
			}
		}
	default:
		panic(fmt.Errorf("Lua line%d: unexpected%s", t.line, t.text))
	}
	for {
		if p.take(".") {
			n = &luaNode{op: "index", children: []*luaNode{n, {op: "literal", value: p.name()}}}
			continue
		}
		if p.take("[") {
			n = &luaNode{op: "index", children: []*luaNode{n, p.expr(0)}}
			p.need("]")
			continue
		}
		method := ""
		if p.take(":") {
			method = p.name()
		}
		if p.is("(") || p.is("{") || p.is("string") || method != "" {
			var args []*luaNode
			if p.take("(") {
				if !p.is(")") {
					args = p.list()
				}
				p.need(")")
			} else {
				args = []*luaNode{p.expr(13)}
			}
			if method != "" {
				n = &luaNode{op: "method", text: method, children: append([]*luaNode{n}, args...)}
			} else {
				n = &luaNode{op: "call", children: append([]*luaNode{n}, args...)}
			}
			continue
		}
		prec, right := luaPrecedence(p.token().text)
		if prec == 0 || prec < minimum {
			break
		}
		op := p.token().text
		p.pos++
		next := prec + 1
		if right {
			next = prec
		}
		n = &luaNode{op: "binary", text: op, children: []*luaNode{n, p.expr(next)}}
	}
	return n
}

type luaTable struct {
	values   map[any]any
	retained int
}
type luaEnv struct {
	parent  *luaEnv
	values  map[string]any
	varargs []any
}
type luaFunction struct {
	node *luaNode
	env  *luaEnv
}
type luaNativeFunc func(*luaVM, []any) []any
type luaBuiltinFunction struct{ fn luaNativeFunc }

func luaBuiltin(fn luaNativeFunc) *luaBuiltinFunction { return &luaBuiltinFunction{fn} }

type luaClosure struct {
	fn       *luaBuiltinFunction
	roots    []any
	retained int
}
type luaVM struct {
	tengo                   *tengoExecution
	globals                 *luaEnv
	steps, depth, allocated int
	expressions             int
	frames                  []*luaEnv
	roots                   []any
	deadline                time.Time
}
type luaJump struct {
	kind   string
	values []any
}

func luaScope(parent *luaEnv) *luaEnv { return &luaEnv{parent: parent, values: map[string]any{}} }
func (e *luaEnv) get(s string) any {
	for ; e != nil; e = e.parent {
		if v, ok := e.values[s]; ok {
			return v
		}
	}
	return nil
}
func luaTruthy(v any) bool { return v != nil && v != false }
func luaOne(v []any) any {
	if len(v) > 0 {
		return v[0]
	}
	return nil
}
func luaNum(v any) float64 {
	if n, ok := v.(float64); ok {
		return n
	}
	if s, ok := v.(string); ok {
		if n, e := strconv.ParseFloat(s, 64); e == nil {
			return n
		}
	}
	panic(errors.New("Lua expected number"))
}
func luaInt(v any) int64 {
	n := luaNum(v)
	if math.IsNaN(n) || math.IsInf(n, 0) || n < math.MinInt64 || n >= math.MaxInt64 || n != math.Trunc(n) {
		panic(errors.New("Lua expected integer"))
	}
	return int64(n)
}
func luaText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	}
	panic(errors.New("Lua expected string"))
}
func (v *luaVM) tick() {
	v.steps--
	if v.steps < 0 {
		panic(errors.New("Lua instruction limit"))
	}
	if v.steps&1023 == 0 && v.tengo != nil && v.tengo.ctx.Err() != nil {
		panic(v.tengo.ctx.Err())
	}
	if v.steps&1023 == 0 && time.Now().After(v.deadline) {
		panic(errors.New("Lua execution time limit"))
	}
}
func (v *luaVM) alloc(n int) {
	if n < 0 || n > luaStringLimit {
		panic(errors.New("Lua value exceeds1MiB"))
	}
	v.steps -= n / 256
	if v.steps < 0 || n > 4096 && time.Now().After(v.deadline) {
		panic(errors.New("Lua execution work limit"))
	}
	v.allocated += n
	if v.allocated > 1<<20 {
		roots := append([]any{v.globals}, v.roots...)
		for _, e := range v.frames {
			roots = append(roots, e)
		}
		if luaHeap(roots) > luaHeapLimit {
			panic(errors.New("Lua retained heap exceeds8MiB"))
		}
		v.allocated = 0
	}
}
func luaHeap(pending []any) int {
	seen := map[any]bool{}
	n := 0
	for len(pending) > 0 {
		item := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		n += 16
		switch t := item.(type) {
		case string:
			n += len(t)
		case *tengoError:
			if seen[t] {
				continue
			}
			seen[t] = true
			pending = append(pending, t.value)
		case *tengoCollection:
			if seen[t] {
				continue
			}
			seen[t] = true
			n += 64 + 16*len(t.array) + len(t.bytes) + 48*len(t.object)
			pending = append(pending, t.array...)
			for key, value := range t.object {
				n += len(key)
				pending = append(pending, value)
			}
		case *luaTable:
			if seen[t] {
				continue
			}
			seen[t] = true
			n += 64 + t.retained
			for k, x := range t.values {
				pending = append(pending, k, x)
			}
		case *luaEnv:
			if t == nil || seen[t] {
				continue
			}
			seen[t] = true
			n += 64
			pending = append(pending, t.parent)
			for k, x := range t.values {
				pending = append(pending, k, x)
			}
			pending = append(pending, t.varargs)
		case *luaFunction:
			if seen[t] {
				continue
			}
			seen[t] = true
			pending = append(pending, t.env)
		case *luaClosure:
			if seen[t] {
				continue
			}
			seen[t] = true
			n += t.retained
			pending = append(pending, t.roots)
		case []any:
			pending = append(pending, t...)
		case *[]any:
			pending = append(pending, (*t)...)
		}
		if n > luaHeapLimit || len(pending) > luaHeapLimit/16 {
			return luaHeapLimit + 1
		}
	}
	return n
}
func (v *luaVM) run(fn func() []any) (out []any, err error) {
	defer func() {
		if p := recover(); p != nil {
			if e, ok := p.(error); ok {
				err = e
			} else {
				panic(p)
			}
		}
	}()
	v.steps = 200000
	v.depth = 0
	v.deadline = time.Now().Add(2 * time.Second)
	out = fn()
	return
}
func (v *luaVM) call(fn any, args []any) []any {
	v.tick()
	v.depth++
	defer func() { v.depth-- }()
	if v.depth > 96 {
		panic(errors.New("Lua call depth limit"))
	}
	switch f := fn.(type) {
	case *luaBuiltinFunction:
		out := f.fn(v, args)
		v.roots = append(v.roots, out)
		defer func() { v.roots = v.roots[:len(v.roots)-1] }()
		for _, value := range out {
			if text, ok := value.(string); ok {
				v.alloc(len(text))
			}
		}
		return out
	case *luaClosure:
		return v.call(f.fn, args)
	case *luaFunction:
		e := luaScope(f.env)
		e.varargs = []any{}
		names := f.node.value.([]string)
		if v.tengo != nil && (len(args) < len(names) || f.node.text != "vararg" && len(args) != len(names)) {
			panic(errors.New("Tengo function argument count mismatch"))
		}
		for i, name := range names {
			e.values[name] = luaArg(args, i)
		}
		if f.node.text == "vararg" && len(args) > len(names) {
			e.varargs = args[len(names):]
		}
		_, j := v.block(f.node.children[0], e)
		if j.kind == "break" || j.kind == "continue" {
			panic(errors.New("script loop control outside loop"))
		}
		return j.values
	}
	panic(errors.New("Lua attempted to call non-function"))
}
func luaArg(a []any, i int) any {
	if i < len(a) {
		return a[i]
	}
	return nil
}
func (v *luaVM) values(nodes []*luaNode, e *luaEnv) []any {
	var out []any
	v.roots = append(v.roots, &out)
	defer func() { v.roots = v.roots[:len(v.roots)-1] }()
	for i, n := range nodes {
		r := v.eval(n, e)
		if i == len(nodes)-1 {
			out = append(out, r...)
		} else {
			out = append(out, luaOne(r))
		}
	}
	return out
}
func (v *luaVM) index(t, k any) any {
	if s, ok := t.(string); ok {
		_ = s
		t = v.globals.get("string")
	}
	if tab, ok := t.(*luaTable); ok {
		return tab.values[k]
	}
	panic(errors.New("Lua attempted to index non-table"))
}
func (v *luaVM) set(t, k, x any) {
	tab, ok := t.(*luaTable)
	if !ok {
		panic(errors.New("Lua assignment to non-table"))
	}
	if k == nil {
		panic(errors.New("Lua nil table key"))
	}
	if f, ok := k.(float64); ok && math.IsNaN(f) {
		panic(errors.New("Lua NaN table key"))
	}
	if _, ok := tab.values[k]; !ok {
		if len(tab.values) >= 16384 {
			panic(errors.New("Lua table entry limit"))
		}
		v.alloc(48)
	}
	if x == nil {
		delete(tab.values, k)
	} else {
		tab.values[k] = x
	}
}
func (v *luaVM) eval(n *luaNode, e *luaEnv) []any {
	v.tick()
	v.expressions++
	defer func() { v.expressions-- }()
	if v.expressions > 256 {
		panic(errors.New("Lua expression depth limit"))
	}
	one := func(x any) []any { return []any{x} }
	arg := func(i int) any { return luaOne(v.eval(n.children[i], e)) }
	switch n.op {
	case "tengo_expr":
		return v.tengoEval(n, e)
	case "literal":
		return one(n.value)
	case "name":
		for scope := e; scope != nil; scope = scope.parent {
			v.tick()
			if value, ok := scope.values[n.text]; ok {
				return one(value)
			}
		}
		return one(nil)
	case "vararg":
		for ; e != nil; e = e.parent {
			if e.varargs != nil {
				return e.varargs
			}
		}
		return nil
	case "paren":
		return one(arg(0))
	case "function":
		v.alloc(32)
		return one(&luaFunction{n, e})
	case "table":
		v.alloc(64)
		t := &luaTable{values: map[any]any{}}
		v.roots = append(v.roots, t)
		defer func() { v.roots = v.roots[:len(v.roots)-1] }()
		for i := 0; i < len(n.children); i += 2 {
			key := luaOne(v.eval(n.children[i], e))
			vals := v.eval(n.children[i+1], e)
			if i+2 == len(n.children) && n.children[i].text == "array" {
				if num, ok := key.(float64); ok {
					for j, x := range vals {
						v.set(t, num+float64(j), x)
					}
					continue
				}
			}
			v.set(t, key, luaOne(vals))
		}
		return one(t)
	case "index":
		return one(v.index(arg(0), arg(1)))
	case "call":
		return v.call(arg(0), v.values(n.children[1:], e))
	case "method":
		t := arg(0)
		return v.call(v.index(t, n.text), append([]any{t}, v.values(n.children[1:], e)...))
	case "unary":
		a := arg(0)
		switch n.text {
		case "not":
			return one(!luaTruthy(a))
		case "-":
			return one(-luaNum(a))
		case "~":
			return one(float64(^luaInt(a)))
		case "#":
			switch x := a.(type) {
			case string:
				return one(float64(len(x)))
			case *luaTable:
				return one(float64(luaLength(x)))
			}
		}
		panic(errors.New("Lua invalid unary operand"))
	case "binary":
		a := arg(0)
		if n.text == "and" {
			if !luaTruthy(a) {
				return one(a)
			}
			return one(arg(1))
		}
		if n.text == "or" {
			if luaTruthy(a) {
				return one(a)
			}
			return one(arg(1))
		}
		b := arg(1)
		switch n.text {
		case "==", "~=":
			eq := luaEqual(a, b)
			return one(eq == (n.text == "=="))
		case "..":
			s, t := luaText(a), luaText(b)
			v.alloc(len(s) + len(t))
			return one(s + t)
		case "<", ">", "<=", ">=":
			var less, equal bool
			if s, ok := a.(string); ok {
				t, ok := b.(string)
				if !ok {
					panic(errors.New("Lua incomparable types"))
				}
				less = s < t
				equal = s == t
			} else {
				x, y := luaNum(a), luaNum(b)
				if math.IsNaN(x) || math.IsNaN(y) {
					return one(false)
				}
				less = x < y
				equal = x == y
			}
			switch n.text {
			case "<":
				return one(less)
			case "<=":
				return one(less || equal)
			case ">":
				return one(!less && !equal)
			default:
				return one(!less)
			}
		case "&":
			return one(float64(luaInt(a) & luaInt(b)))
		case "|":
			return one(float64(luaInt(a) | luaInt(b)))
		case "~":
			return one(float64(luaInt(a) ^ luaInt(b)))
		case "<<", ">>":
			x, y := uint64(luaInt(a)), luaInt(b)
			if y < 0 {
				y = -y
				if n.text == "<<" {
					return one(float64(x >> uint64(y)))
				}
				return one(float64(x << uint64(y)))
			}
			if n.text == "<<" {
				return one(float64(x << uint64(y)))
			}
			return one(float64(x >> uint64(y)))
		}
		x, y := luaNum(a), luaNum(b)
		switch n.text {
		case "+":
			return one(x + y)
		case "-":
			return one(x - y)
		case "*":
			return one(x * y)
		case "/":
			return one(x / y)
		case "//":
			if y == 0 {
				panic(errors.New("Lua division by zero"))
			}
			return one(math.Floor(x / y))
		case "%":
			if y == 0 {
				panic(errors.New("Lua division by zero"))
			}
			return one(x - math.Floor(x/y)*y)
		case "^":
			return one(math.Pow(x, y))
		}
	}
	panic(errors.New("Lua invalid expression"))
}
func luaEqual(a, b any) bool { return a == b }
func luaLength(t *luaTable) int {
	n := 0
	for t.values[float64(n+1)] != nil {
		n++
	}
	return n
}
func (v *luaVM) block(n *luaNode, e *luaEnv) (*luaEnv, luaJump) {
	frame := len(v.frames)
	v.frames = append(v.frames, e)
	defer func() { v.frames = v.frames[:frame] }()
	for _, s := range n.children {
		v.frames[frame] = e
		v.tick()
		switch s.op {
		case "tengo_stmt":
			var jump luaJump
			e, jump = v.tengoBlockStatement(s, e)
			if jump.kind != "" {
				return e, jump
			}
		case "local":
			count := s.value.(int)
			vals := v.values(s.children[count:], e)
			e = luaScope(e)
			for i, key := range s.children[:count] {
				e.values[key.text] = luaArg(vals, i)
			}
			v.alloc(64 + count*32)
		case "localfn":
			e = luaScope(e)
			e.values[s.text] = &luaFunction{s.children[0], e}
			v.alloc(96)
		case "assign":
			count := s.value.(int)
			type target struct {
				env        *luaEnv
				name       string
				table, key any
			}
			targets := make([]target, count)
			for i, n := range s.children[:count] {
				if n.op == "name" {
					scope := e
					for scope.parent != nil {
						v.tick()
						if _, ok := scope.values[n.text]; ok {
							break
						}
						scope = scope.parent
					}
					targets[i] = target{env: scope, name: n.text}
				} else {
					targets[i] = target{table: luaOne(v.eval(n.children[0], e)), key: luaOne(v.eval(n.children[1], e))}
				}
			}
			vals := v.values(s.children[count:], e)
			for i, t := range targets {
				if t.env != nil {
					t.env.values[t.name] = luaArg(vals, i)
				} else {
					v.set(t.table, t.key, luaArg(vals, i))
				}
			}
		case "return":
			return e, luaJump{"return", v.values(s.children, e)}
		case "break":
			return e, luaJump{kind: "break"}
		case "if":
			for i := 0; i < len(s.children); i += 2 {
				if luaTruthy(luaOne(v.eval(s.children[i], e))) {
					_, j := v.block(s.children[i+1], luaScope(e))
					if j.kind != "" {
						return e, j
					}
					break
				}
			}
		case "while", "repeat":
			for {
				v.tick()
				if s.op == "while" && !luaTruthy(luaOne(v.eval(s.children[0], e))) {
					break
				}
				bi := 1
				if s.op == "repeat" {
					bi = 0
				}
				scope, j := v.block(s.children[bi], luaScope(e))
				if j.kind == "return" {
					return e, j
				}
				if j.kind == "break" {
					break
				}
				if s.op == "repeat" && luaTruthy(luaOne(v.eval(s.children[1], scope))) {
					break
				}
			}
		case "for":
			a := luaNum(luaOne(v.eval(s.children[1], e)))
			end := luaNum(luaOne(v.eval(s.children[2], e)))
			step := luaNum(luaOne(v.eval(s.children[3], e)))
			if step == 0 || math.IsNaN(step) {
				panic(errors.New("Lua invalid for step"))
			}
			for x := a; step > 0 && x <= end || step < 0 && x >= end; x += step {
				v.tick()
				scope := luaScope(e)
				v.alloc(96)
				scope.values[s.children[0].text] = x
				_, j := v.block(s.children[4], scope)
				if j.kind == "return" {
					return e, j
				}
				if j.kind == "break" {
					break
				}
			}
		case "each":
			count := s.value.(int)
			vals := v.values(s.children[count:len(s.children)-1], e)
			fn, state, control := luaArg(vals, 0), luaArg(vals, 1), luaArg(vals, 2)
			for {
				v.tick()
				r := v.call(fn, []any{state, control})
				control = luaOne(r)
				if control == nil {
					break
				}
				scope := luaScope(e)
				for i, n := range s.children[:count] {
					scope.values[n.text] = luaArg(r, i)
				}
				_, j := v.block(s.children[len(s.children)-1], scope)
				if j.kind == "return" {
					return e, j
				}
				if j.kind == "break" {
					break
				}
			}
		case "block":
			_, j := v.block(s, luaScope(e))
			if j.kind != "" {
				return e, j
			}
		default:
			v.eval(s, e)
		}
	}
	return e, luaJump{}
}
