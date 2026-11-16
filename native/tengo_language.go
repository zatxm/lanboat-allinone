package native

import (
	"errors"
	"fmt"
	"go/scanner"
	"go/token"
	"strconv"
	"strings"
)

type tengoParser struct {
	tokens    []luaToken
	at, depth int
}

func tengoNode(kind string, children ...*luaNode) *luaNode {
	return &luaNode{op: "tengo_expr", text: kind, children: children}
}
func tengoStatement(kind string, children ...*luaNode) *luaNode {
	return &luaNode{op: "tengo_stmt", text: kind, children: children}
}
func tengoLiteral(value any) *luaNode { return &luaNode{op: "literal", value: value} }
func compileTengo(source string) (program *luaNode, err error) {
	defer func() {
		if value := recover(); value != nil {
			if e, ok := value.(error); ok {
				err = e
			} else {
				panic(value)
			}
		}
	}()
	if len(source) > 256<<10 {
		return nil, errors.New("Tengo source exceeds256KiB")
	}
	set := token.NewFileSet()
	file := set.AddFile("script.tengo", set.Base(), len(source))
	var scan scanner.Scanner
	var lexical error
	scan.Init(file, []byte(source), func(position token.Position, message string) {
		if !strings.Contains(message, "U+003F") {
			lexical = fmt.Errorf("Tengo line%d: %s", position.Line, message)
		}
	}, 0)
	p := &tengoParser{}
	for {
		position, kind, text := scan.Scan()
		t := luaToken{text: kind.String(), line: file.Line(position)}
		switch kind {
		case token.IDENT:
			t.text = "name"
			t.value = text
		case token.INT:
			value, e := strconv.ParseInt(strings.ReplaceAll(text, "_", ""), 0, 64)
			if e != nil {
				panic(errors.New("Tengo integer literal outside64-bit range"))
			}
			t.text = "literal"
			t.value = value
		case token.FLOAT:
			value, e := strconv.ParseFloat(strings.ReplaceAll(text, "_", ""), 64)
			if e != nil {
				panic(errors.New("Tengo invalid float literal"))
			}
			t.text = "literal"
			t.value = value
		case token.STRING, token.CHAR:
			value, e := strconv.Unquote(text)
			if e != nil {
				panic(errors.New("Tengo invalid string literal"))
			}
			t.text = "literal"
			t.value = value
			if kind == token.CHAR {
				runes := []rune(value)
				if len(runes) != 1 {
					panic(errors.New("Tengo invalid character"))
				}
				t.value = tengoChar(runes[0])
			}
		case token.ILLEGAL:
			if text == "?" {
				t.text = "?"
			} else {
				panic(errors.New("Tengo invalid token"))
			}
		case token.EOF:
			t.text = "eof"
		}
		p.tokens = append(p.tokens, t)
		if len(p.tokens) > 65536 {
			panic(errors.New("Tengo token limit exceeded"))
		}
		if kind == token.EOF {
			break
		}
	}
	if lexical != nil {
		return nil, lexical
	}
	program = &luaNode{op: "block"}
	for !p.is("eof") {
		if p.take(";") {
			continue
		}
		program.children = append(program.children, p.statement())
	}
	return program, nil
}
func (p *tengoParser) current() luaToken { return p.tokens[p.at] }
func (p *tengoParser) is(value string) bool {
	t := p.current()
	return t.text == value || t.text == "name" && t.value == value
}
func (p *tengoParser) take(value string) bool {
	if !p.is(value) {
		return false
	}
	p.at++
	return true
}
func (p *tengoParser) need(value string) luaToken {
	t := p.current()
	if !p.take(value) {
		panic(fmt.Errorf("Tengo line%d: expected%s", t.line, value))
	}
	return t
}
func (p *tengoParser) name() string { return p.need("name").value.(string) }
func (p *tengoParser) block() *luaNode {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 256 {
		panic(errors.New("Tengo block depth limit"))
	}
	p.need("{")
	n := &luaNode{op: "block"}
	for !p.take("}") {
		if p.is("eof") {
			p.need("}")
		}
		if p.take(";") {
			continue
		}
		n.children = append(n.children, p.statement())
	}
	return n
}
func (p *tengoParser) statement() *luaNode {
	switch {
	case p.take("return"), p.take("export"):
		n := tengoStatement("return")
		if !p.is(";") && !p.is("}") && !p.is("eof") {
			n.children = append(n.children, p.expression(0))
		}
		return n
	case p.take("break"):
		return tengoStatement("break")
	case p.take("continue"):
		return tengoStatement("continue")
	case p.take("if"):
		first := p.simple()
		n := tengoStatement("if")
		if p.take(";") {
			n.children = append(n.children, first, p.expression(0))
		} else {
			if first.text != "expression" {
				panic(errors.New("Tengo if requires condition"))
			}
			n.children = append(n.children, nil, first.children[0])
		}
		n.children = append(n.children, p.block())
		if p.take("else") {
			if p.is("if") {
				n.children = append(n.children, &luaNode{op: "block", children: []*luaNode{p.statement()}})
			} else {
				n.children = append(n.children, p.block())
			}
		}
		return n
	case p.take("for"):
		if p.is("{") {
			return tengoStatement("for", nil, tengoLiteral(true), nil, p.block())
		}
		saved := p.at
		var names []string
		if p.is("name") {
			names = append(names, p.name())
			if p.take(",") {
				names = append(names, p.name())
			}
		}
		if len(names) > 0 && p.take("in") {
			n := tengoStatement("each", p.expression(0), p.block())
			n.value = names
			return n
		}
		p.at = saved
		var first *luaNode
		if !p.is(";") {
			first = p.simple()
		}
		if !p.take(";") {
			if first == nil || first.text != "expression" {
				panic(errors.New("Tengo invalid for condition"))
			}
			return tengoStatement("for", nil, first.children[0], nil, p.block())
		}
		condition := tengoLiteral(true)
		if !p.is(";") {
			condition = p.expression(0)
		}
		p.need(";")
		var post *luaNode
		if !p.is("{") {
			post = p.simple()
		}
		return tengoStatement("for", first, condition, post, p.block())
	case p.is("{"):
		return p.block()
	default:
		return p.simple()
	}
}
func (p *tengoParser) simple() *luaNode {
	first := p.expression(0)
	targets := []*luaNode{first}
	for p.take(",") {
		targets = append(targets, p.expression(0))
	}
	op := p.current().text
	if op == "++" || op == "--" {
		if len(targets) != 1 || first.op != "name" && !(first.op == "tengo_expr" && first.text == "index") {
			panic(errors.New("Tengo invalid increment target"))
		}
		p.at++
		n := tengoStatement("assign", first, tengoLiteral(int64(1)))
		n.value = 1
		if op == "++" {
			n.text = "+="
		} else {
			n.text = "-="
		}
		return n
	}
	if op != "=" && op != ":=" && !strings.HasSuffix(op, "=") || op == "==" || op == "!=" || op == "<=" || op == ">=" {
		if len(targets) != 1 {
			panic(errors.New("Tengo invalid expression statement"))
		}
		return tengoStatement("expression", first)
	}
	p.at++
	n := tengoStatement(op, targets...)
	n.value = len(targets)
	for {
		n.children = append(n.children, p.expression(0))
		if !p.take(",") {
			break
		}
	}
	for _, target := range targets {
		if op == ":=" && target.op != "name" {
			panic(errors.New("Tengo declaration requires a variable name"))
		}
		if target.op != "name" && !(target.op == "tengo_expr" && target.text == "index") {
			panic(errors.New("Tengo invalid assignment target"))
		}
	}
	return n
}
func tengoPrecedence(op string) int {
	switch op {
	case "||":
		return 1
	case "&&":
		return 2
	case "==", "!=", "<", ">", "<=", ">=":
		return 3
	case "+", "-", "|", "^":
		return 4
	case "*", "/", "%", "<<", ">>", "&", "&^":
		return 5
	}
	return 0
}
func (p *tengoParser) expression(minimum int) *luaNode {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 256 {
		panic(errors.New("Tengo expression depth limit"))
	}
	t := p.current()
	p.at++
	var n *luaNode
	switch t.text {
	case "literal":
		n = tengoLiteral(t.value)
	case "name":
		switch t.value {
		case "undefined":
			n = tengoLiteral(nil)
		case "true":
			n = tengoLiteral(true)
		case "false":
			n = tengoLiteral(false)
		default:
			n = &luaNode{op: "name", text: t.value.(string)}
		}
	case "import":
		n = &luaNode{op: "name", text: "import"}
	case "(":
		n = p.expression(0)
		p.need(")")
	case "!", "-", "+", "^":
		n = tengoNode("unary", p.expression(6))
		n.value = t.text
	case "[":
		n = tengoNode("array")
		for !p.take("]") {
			n.children = append(n.children, p.expression(0))
			if !p.take(",") {
				p.need("]")
				break
			}
		}
	case "{":
		n = tengoNode("map")
		for !p.take("}") {
			key := p.current()
			p.at++
			var text string
			if key.text == "name" {
				text = key.value.(string)
			} else if key.text == "literal" {
				var ok bool
				text, ok = key.value.(string)
				if !ok {
					panic(errors.New("Tengo map key must be a string"))
				}
			} else {
				panic(errors.New("Tengo invalid map key"))
			}
			p.need(":")
			n.children = append(n.children, tengoLiteral(text), p.expression(0))
			if !p.take(",") {
				p.need("}")
				break
			}
		}
	case "func":
		p.need("(")
		var names []string
		var variadic string
		for !p.take(")") {
			if p.take("...") {
				variadic = p.name()
				p.need(")")
				break
			}
			names = append(names, p.name())
			if !p.take(",") {
				p.need(")")
				break
			}
		}
		body := p.block()
		n = &luaNode{op: "function", value: names, children: []*luaNode{body}}
		if variadic != "" {
			n.text = "vararg"
			declare := tengoStatement(":=", &luaNode{op: "name", text: variadic}, tengoNode("call", &luaNode{op: "name", text: "__tengo_varargs"}, &luaNode{op: "vararg"}))
			declare.value = 1
			body.children = append([]*luaNode{declare}, body.children...)
		}
	default:
		panic(fmt.Errorf("Tengo line%d: expected expression", t.line))
	}
	for {
		switch {
		case p.take("."):
			n = tengoNode("index", n, tengoLiteral(p.name()))
			continue
		case p.take("["):
			var from, to *luaNode
			if !p.is(":") {
				from = p.expression(0)
			}
			if p.take(":") {
				if !p.is("]") {
					to = p.expression(0)
				}
				p.need("]")
				n = tengoNode("slice", n, from, to)
			} else {
				p.need("]")
				n = tengoNode("index", n, from)
			}
			continue
		case p.take("("):
			call := tengoNode("call", n)
			for !p.take(")") {
				arg := p.expression(0)
				if p.take("...") {
					arg = tengoNode("spread", arg)
				}
				call.children = append(call.children, arg)
				if !p.take(",") {
					p.need(")")
					break
				}
			}
			n = call
			continue
		}
		op := p.current().text
		precedence := tengoPrecedence(op)
		if precedence == 0 || precedence < minimum {
			break
		}
		p.at++
		next := tengoNode("binary", n, p.expression(precedence+1))
		next.value = op
		n = next
	}
	if minimum == 0 && p.take("?") {
		yes := p.expression(0)
		p.need(":")
		n = tengoNode("conditional", n, yes, p.expression(0))
	}
	return n
}
