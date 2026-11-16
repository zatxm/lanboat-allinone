package native

import (
	"reflect"
	"strings"
	"testing"
)

func luaTestRun(source string) ([]any, error) {
	p, e := luaCompile(source)
	if e != nil {
		return nil, e
	}
	v := newLuaVM()
	return v.run(func() []any { _, j := v.block(p, luaScope(v.globals)); return j.values })
}
func TestLuaLanguage(t *testing.T) {
	cases := []struct {
		source string
		want   []any
	}{
		{`local x=2; local function f(y) return x+y end; local x=9; return f(3), x`, []any{float64(5), float64(9)}},
		{`local function f(n) if n==0 then return 1 end return n*f(n-1) end return f(7)`, []any{float64(5040)}},
		{`local t={1,2,3}; local s=0; for i,x in ipairs(t) do s=s+i*x end; return s`, []any{float64(14)}},
		{`local t={a=2,b=5}; local s=0; for k,x in pairs(t) do s=s+x end; return s`, []any{float64(7)}},
		{`local t={3,5,1};table.sort(t);table.insert(t,2,8);table.remove(t,3);return table.concat(t,',')`, []any{"1,8,5"}},
		{`local x=0;while x<5 do x=x+1 end;repeat local y=x; x=x-1 until y==2; return x`, []any{float64(1)}},
		{`local s=0;for i=5,1,-2 do s=s+i end;return s,-2^2,2^3^2,7//2,-7%3`, []any{float64(9), float64(-4), float64(512), float64(3), float64(2)}},
		{`local t={};function t:add(x) self.x=(self.x or 0)+x return self.x end; return t:add(4),t:add(5)`, []any{float64(4), float64(9)}},
		{`local function f(...) return select('#',...),... end;return f(1,nil,3)`, []any{float64(3), float64(1), nil, float64(3)}},
		{`local function f() return 1,2 end;local a,b=f();local c,d=(f());return a,b,c,d`, []any{float64(1), float64(2), float64(1), nil}},
		{`local t={a=1,b=2,c=3};local n,s=nil,0;repeat local k,x=next(t,n);n=k;if k then s=s+x end until n==nil;return s`, []any{float64(6)}},
		{`local function f() return 2,3 end;return table.unpack({1,f()})`, []any{float64(1), float64(2), float64(3)}},
		{`return string.char(0,255):byte(1,2),string.format('%02x:%d',15,42)`, []any{float64(0), "0f:42"}},
		{`return [=[binary
string]=], '\x00\255',0xff,0x1.8p1`, []any{"binary\nstring", "\x00\xff", float64(255), float64(3)}},
		{`local ok,e=pcall(function() error('secret') end);return ok,type(e)`, []any{false, "string"}},
		{`return bit32.bxor(0xff,0x0f),bit32.rol(1,3),1<<5,~0`, []any{float64(240), float64(8), float64(32), float64(-1)}},
	}
	for i, tt := range cases {
		got, e := luaTestRun(tt.source)
		if e != nil || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("case%d got%#v error%v want%#v", i, got, e, tt.want)
		}
	}
}
func TestLuaPatterns(t *testing.T) {
	for _, source := range []string{
		`local s,e=string.find('HTTP/1.1 200 OK\r\n','^HTTP/%d%.%d 200 ');assert(s==1 and e==13)`,
		`assert(string.match('name=123','(%a+)=(%d+)')=='name')`,
		`assert(string.match('x(a(b)c)y','%b()')=='(a(b)c)')`,
		`assert(string.match('hello hello','(%a+) %1')=='hello')`,
		`assert(string.match('abc dog xyz','%f[%a]dog%f[%A]')=='dog')`,
		`local s,n=string.gsub('a12b34','(%d+)','[%1]');assert(s=='a[12]b[34]' and n==2)`,
		`local s,n=string.gsub('ab','()','%1');assert(s=='1a2b3' and n==3)`,
		`local t={};for word in string.gmatch('one two three','%a+') do table.insert(t,word) end;assert(#t==3)`,
		`assert(string.match('a123b456b','a.-b')=='a123b');assert(string.match('aaab','a+b?')=='aaab')`,
		`assert(string.gsub('hi','.',function(x)return string.upper(x)end)=='HI')`,
		`assert(string.gsub('cat dog','%w+',{cat='C',dog='D'})=='C D')`,
	} {
		if _, e := luaTestRun(source); e != nil {
			t.Errorf("%s: %v", source, e)
		}
	}
}
func TestLuaLimits(t *testing.T) {
	for _, source := range []string{
		`while true do end`, `local function f()return f()end return f()`, `return string.rep('x',2000000)`, `return string.format('%999999999s','x')`, `local t={};for i=1,20000 do t[i]=true end`, `return string.match('a', '(')`, `return io.open('/etc/passwd')`, `return os.execute('false')`, `return require 'package'`,
	} {
		if _, e := luaTestRun(source); e == nil {
			t.Errorf("expected bounded failure: %s", source)
		}
	}
	if _, e := luaCompile(strings.Repeat("(", 200) + "1" + strings.Repeat(")", 200)); e == nil {
		t.Fatal("deep source accepted")
	}
}
func FuzzLuaLanguage(f *testing.F) {
	for _, s := range []string{luaHTTPScript, luaTrojanScript, luaLightswordScript, `return string.match('abc','%a+')`, `local t={};t[t]=t;return t`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 32768 {
			return
		}
		luaTestRun(s)
	})
}
