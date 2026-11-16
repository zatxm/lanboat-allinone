package native

import (
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestLuaReferenceSemantics(t *testing.T) {
	binary := os.Getenv("LANBOAT_TEST_LUA")
	if binary == "" {
		t.Fatal("LANBOAT_TEST_LUA required")
	}
	programs := []string{
		`local a,b=1,2;a,b=b,a;return a,b`,
		`local a=2;local function f()return a end;local a=9;return f(),a`,
		`local function f(n)if n==0 then return 1 end return n*f(n-1)end;return f(8)`,
		`local function f()return 2,3 end;return table.unpack({[3]=f()})`,
		`local function f()return 2,3 end;return table.unpack({1,f()})`,
		`local t={};function t:append(x)self.x=(self.x or '')..x;return self.x end;return t:append('a'),t:append('b')`,
		`local s=0;for i=5,1,-2 do s=s+i end;return s,-2^2,2^3^2,-7%3,7//2`,
		`local function f(...) return select('#',...), ... end;return f(1,nil,3)`,
		`local t={1,2,3};local s=0;for i,x in ipairs(t)do s=s+i*x end;return s`,
		`local t={a=1,b=2,c=3};local s=0;for k,x in pairs(t)do s=s+x end;return s`,
		`local t={1,2,3};local s=0;for i=1,3 do s=s+t[i] end;return s`,
		`return string.find('HTTP/1.1 200 OK\r\n','^HTTP/%d%.%d 200 ')`,
		`return string.match('x(a(b)c)y','%b()')`,
		`return string.match('hello hello','(%a+) %1')`,
		`return string.match('abc dog xyz','%f[%a]dog%f[%A]')`,
		`return string.gsub('a12b34','(%d+)','[%1]')`,
		`return string.gsub('ab','()','%1')`,
		`return string.match('a123b456b','a.-b')`,
		`return string.gsub('hi','.',function(x)return string.upper(x)end)`,
		`return string.format('%02x:%d %.3f',15,42,3.1415926)`,
		`local f=string.sub;local t={[f]='function key'};return f==f,t[f]`,
	}
	rng := rand.New(rand.NewPCG(0x1234, 0x5678))
	for range 120 {
		a, b, c := rng.IntN(100)+1, rng.IntN(100)+1, rng.IntN(10)+1
		programs = append(programs, fmt.Sprintf(`local x=%d;local function f(y)if y%%2==0 then return x*y+%d end return x-y end;local t={};for i=1,%d do t[i]=f(i)end;return table.concat(t,','),f(%d)`, a, b, c, b))
	}
	for i, program := range programs {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			got, e := luaTestRun(program)
			if e != nil {
				t.Fatal(e)
			}
			source := `local function test() ` + program + ` end
local function dump(...)
 for i=1,select('#',...) do
  local x=select(i,...)
  if type(x)=='number' then io.write('n',string.format('%.17g',x),'\n')
  elseif type(x)=='string' then io.write('s',(x:gsub('.',function(c)return string.format('%02x',c:byte())end)),'\n')
  elseif type(x)=='boolean' then io.write('b',tostring(x),'\n')
  elseif x==nil then io.write('z\n') else error('unexpected result') end
 end
end
dump(test())`
			cmd := exec.Command(binary, "-")
			cmd.Stdin = strings.NewReader(source)
			raw, e := cmd.CombinedOutput()
			if e != nil {
				t.Fatal(e, string(raw))
			}
			var want []any
			for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
				if line == "" {
					continue
				}
				switch line[0] {
				case 'n':
					n, e := strconv.ParseFloat(line[1:], 64)
					if e != nil {
						t.Fatal(e)
					}
					want = append(want, n)
				case 's':
					s, e := hex.DecodeString(line[1:])
					if e != nil {
						t.Fatal(e)
					}
					want = append(want, string(s))
				case 'b':
					want = append(want, line[1:] == "true")
				case 'z':
					want = append(want, nil)
				default:
					t.Fatal("reference output", line)
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got%#v want%#v", got, want)
			}
		})
	}
}
