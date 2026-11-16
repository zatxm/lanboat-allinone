package native

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"testing"
)

func TestSnellKDFIndependentOracle(t *testing.T) {
	program := `import ctypes,ctypes.util,hashlib,json,sys
lib=ctypes.CDLL(ctypes.util.find_library('sodium'));lib.sodium_init()
lib.crypto_pwhash_argon2id.argtypes=[ctypes.c_void_p,ctypes.c_ulonglong,ctypes.c_void_p,ctypes.c_ulonglong,ctypes.c_void_p,ctypes.c_ulonglong,ctypes.c_size_t,ctypes.c_int]
rows=json.load(sys.stdin);out=[]
for row in rows:
 p=bytes.fromhex(row['password']);s=bytes.fromhex(row['salt']);dst=ctypes.create_string_buffer(32)
 if lib.crypto_pwhash_argon2id(dst,32,p,len(p),s,3,8192,2)!=0:raise RuntimeError('argon2id oracle failed')
 out.append({'key':dst.raw.hex(),'hash':[hashlib.blake2b(p,digest_size=n).hexdigest() for n in (16,32,64)]})
json.dump(out,sys.stdout)`
	type row struct {
		Password string `json:"password"`
		Salt     string `json:"salt"`
	}
	var rows []row
	for _, size := range []int{0, 1, 32, 127, 128, 129, 1024} {
		rows = append(rows, row{hex.EncodeToString(bytes.Repeat([]byte{byte(size)}, size)), hex.EncodeToString(bytes.Repeat([]byte{byte(size + 1)}, 16))})
	}
	input, _ := json.Marshal(rows)
	cmd := exec.Command("python3", "-c", program)
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("KDF oracle: %v %s", err, output)
	}
	var expected []struct {
		Key  string   `json:"key"`
		Hash []string `json:"hash"`
	}
	if err := json.Unmarshal(output, &expected); err != nil {
		t.Fatal(err)
	}
	for i, row := range rows {
		password, salt := unhex(t, row.Password), unhex(t, row.Salt)
		for j, size := range []int{16, 32, 64} {
			if got := hex.EncodeToString(blake2b(password, size)); got != expected[i].Hash[j] {
				t.Fatalf("BLAKE2b size %d input %d: %s != %s", size, len(password), got, expected[i].Hash[j])
			}
		}
		if got := hex.EncodeToString(snellKey(password, salt)); got != expected[i].Key {
			t.Fatalf("Argon2id input %d: %s != %s", len(password), got, expected[i].Key)
		}
	}
}
