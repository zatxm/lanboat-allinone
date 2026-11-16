package native

import (
	"errors"
	"strings"
)

type luaCapture struct{ start, end int }
type luaPattern struct {
	vm            *luaVM
	text, pattern string
	captures      []luaCapture
	depth         int
}

func luaClass(c, cl byte) bool {
	lower := cl
	if lower >= 'A' && lower <= 'Z' {
		lower += 32
	}
	hit := false
	switch lower {
	case 'a':
		hit = c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
	case 'c':
		hit = c < 32 || c == 127
	case 'd':
		hit = c >= '0' && c <= '9'
	case 'g':
		hit = c > 32 && c < 127
	case 'l':
		hit = c >= 'a' && c <= 'z'
	case 'p':
		hit = c >= 33 && c <= 126 && !luaClass(c, 'w')
	case 's':
		hit = strings.ContainsRune(" \t\r\n\v\f", rune(c))
	case 'u':
		hit = c >= 'A' && c <= 'Z'
	case 'w':
		hit = luaClass(c, 'a') || luaClass(c, 'd')
	case 'x':
		hit = luaClass(c, 'd') || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
	case 'z':
		hit = c == 0
	default:
		return c == cl
	}
	if cl != lower {
		return !hit
	}
	return hit
}
func (p *luaPattern) bracket(at int, c byte) (bool, int) {
	pat := p.pattern
	i := at + 1
	neg := false
	if i < len(pat) && pat[i] == '^' {
		neg = true
		i++
	}
	hit := false
	for i < len(pat) && pat[i] != ']' {
		p.vm.tick()
		if pat[i] == '%' {
			if i+1 >= len(pat) {
				break
			}
			hit = hit || luaClass(c, pat[i+1])
			i += 2
		} else if i+2 < len(pat) && pat[i+1] == '-' && pat[i+2] != ']' {
			hit = hit || c >= pat[i] && c <= pat[i+2]
			i += 3
		} else {
			hit = hit || c == pat[i]
			i++
		}
	}
	if i == len(pat) {
		panic(errors.New("Lua unfinished pattern class"))
	}
	return hit != neg, i + 1
}
func (p *luaPattern) atom(at int, c byte) (bool, int) {
	switch p.pattern[at] {
	case '.':
		return true, at + 1
	case '%':
		if at+1 == len(p.pattern) {
			panic(errors.New("Lua unfinished pattern escape"))
		}
		return luaClass(c, p.pattern[at+1]), at + 2
	case '[':
		return p.bracket(at, c)
	}
	return p.pattern[at] == c, at + 1
}
func (p *luaPattern) match(s, i int, caps []luaCapture) (int, []luaCapture, bool) {
	p.vm.tick()
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 128 {
		panic(errors.New("Lua pattern nesting limit"))
	}
	for i < len(p.pattern) {
		p.vm.tick()
		c := p.pattern[i]
		if c == '(' {
			if len(caps) == 32 {
				panic(errors.New("Lua capture limit"))
			}
			next := append(append([]luaCapture{}, caps...), luaCapture{s, -1})
			i++
			if i < len(p.pattern) && p.pattern[i] == ')' {
				next[len(next)-1].end = -2
				i++
			}
			return p.match(s, i, next)
		}
		if c == ')' {
			next := append([]luaCapture{}, caps...)
			found := false
			for j := len(next) - 1; j >= 0; j-- {
				if next[j].end == -1 {
					next[j].end = s
					found = true
					break
				}
			}
			if !found {
				panic(errors.New("Lua unmatched capture"))
			}
			caps = next
			i++
			continue
		}
		if c == '$' && i+1 == len(p.pattern) {
			return s, caps, s == len(p.text)
		}
		if c == '%' && i+1 < len(p.pattern) {
			next := p.pattern[i+1]
			if next == 'b' {
				if i+3 >= len(p.pattern) {
					panic(errors.New("Lua invalid balanced pattern"))
				}
				open, close := p.pattern[i+2], p.pattern[i+3]
				if s == len(p.text) || p.text[s] != open {
					return 0, nil, false
				}
				n := 1
				s++
				for s < len(p.text) && n > 0 {
					p.vm.tick()
					if p.text[s] == close {
						n--
					} else if p.text[s] == open {
						n++
					}
					s++
				}
				if n != 0 {
					return 0, nil, false
				}
				i += 4
				continue
			}
			if next == 'f' {
				if i+2 == len(p.pattern) || p.pattern[i+2] != '[' {
					panic(errors.New("Lua invalid frontier pattern"))
				}
				prev, current := byte(0), byte(0)
				if s > 0 {
					prev = p.text[s-1]
				}
				if s < len(p.text) {
					current = p.text[s]
				}
				left, _ := p.bracket(i+2, prev)
				right, end := p.bracket(i+2, current)
				if left || !right {
					return 0, nil, false
				}
				i = end
				continue
			}
			if next >= '1' && next <= '9' {
				index := int(next - '1')
				if index >= len(caps) || caps[index].end < 0 {
					panic(errors.New("Lua invalid capture reference"))
				}
				cap := caps[index]
				text := p.text[cap.start:cap.end]
				if !strings.HasPrefix(p.text[s:], text) {
					return 0, nil, false
				}
				s += len(text)
				i += 2
				continue
			}
		}
		_, end := p.atom(i, 0)
		quant := byte(0)
		if end < len(p.pattern) && strings.ContainsRune("*+-?", rune(p.pattern[end])) {
			quant = p.pattern[end]
		}
		if quant != 0 {
			max := s
			for max < len(p.text) {
				p.vm.tick()
				hit, _ := p.atom(i, p.text[max])
				if !hit {
					break
				}
				max++
				if quant == '?' {
					break
				}
			}
			low := s
			if quant == '+' {
				low++
			}
			if max < low {
				return 0, nil, false
			}
			if quant == '-' {
				for n := low; n <= max; n++ {
					if end, cp, ok := p.match(n, end+1, caps); ok {
						return end, cp, true
					}
				}
			} else {
				for n := max; n >= low; n-- {
					if end, cp, ok := p.match(n, end+1, caps); ok {
						return end, cp, true
					}
				}
			}
			return 0, nil, false
		}
		if s >= len(p.text) {
			return 0, nil, false
		}
		hit, _ := p.atom(i, p.text[s])
		if !hit {
			return 0, nil, false
		}
		s++
		i = end
	}
	for _, c := range caps {
		if c.end == -1 {
			panic(errors.New("Lua unfinished capture"))
		}
	}
	return s, caps, true
}
func luaSearch(v *luaVM, text, pat string, start int) (int, int, []any, bool) {
	p := luaPattern{vm: v, text: text, pattern: pat}
	anchor := strings.HasPrefix(pat, "^")
	if anchor {
		p.pattern = pat[1:]
	}
	for s := start; s <= len(text); s++ {
		end, caps, ok := p.match(s, 0, nil)
		if ok {
			var values []any
			for _, c := range caps {
				if c.end == -2 {
					values = append(values, float64(c.start+1))
				} else {
					values = append(values, strings.Clone(text[c.start:c.end]))
				}
			}
			return s, end, values, true
		}
		if anchor {
			break
		}
	}
	return 0, 0, nil, false
}
