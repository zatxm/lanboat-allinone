package native

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"os/exec"
	"testing"
)

func TestSalsa20IndependentOracle(t *testing.T) {
	// libsodium is an external test oracle; the runtime does not load it.
	program := `import ctypes,ctypes.util,json,sys
lib=ctypes.CDLL(ctypes.util.find_library('sodium'))
lib.sodium_init()
lib.crypto_stream_salsa20_xor.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_ulonglong,ctypes.c_void_p,ctypes.c_void_p]
rows=json.load(sys.stdin)
answers=[]
for row in rows:
 plain=bytes.fromhex(row['plain']);out=ctypes.create_string_buffer(len(plain))
 if lib.crypto_stream_salsa20_xor(out,plain,len(plain),bytes.fromhex(row['nonce']),bytes.fromhex(row['key']))!=0: raise RuntimeError('salsa oracle failed')
 answers.append(out.raw.hex())
json.dump(answers,sys.stdout)`
	type vector struct {
		Key   string `json:"key"`
		Nonce string `json:"nonce"`
		Plain string `json:"plain"`
	}
	var rows []vector
	random := rand.NewChaCha8([32]byte{8, 9})
	for _, size := range []int{0, 1, 31, 32, 63, 64, 65, 127, 255, 16383, 65535} {
		key, nonce, plain := make([]byte, 32), make([]byte, 8), make([]byte, size)
		for _, b := range [][]byte{key, nonce, plain} {
			_, _ = random.Read(b)
		}
		rows = append(rows, vector{hex.EncodeToString(key), hex.EncodeToString(nonce), hex.EncodeToString(plain)})
	}
	input, _ := json.Marshal(rows)
	cmd := exec.Command("python3", "-c", program)
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Salsa20 oracle unavailable: %v %s", err, output)
	}
	var expected []string
	if err := json.Unmarshal(output, &expected); err != nil {
		t.Fatal(err)
	}
	for i, row := range rows {
		key := &ssKey{method: "salsa20", master: unhex(t, row.Key)}
		stream, _ := key.stream(unhex(t, row.Nonce), false)
		plain := unhex(t, row.Plain)
		got := make([]byte, len(plain))
		split := min(7, len(plain))
		stream.XORKeyStream(got[:split], plain[:split])
		stream.XORKeyStream(got[split:], plain[split:])
		if hex.EncodeToString(got) != expected[i] {
			t.Fatal("Salsa20 disagrees with libsodium", len(plain))
		}
	}
}
