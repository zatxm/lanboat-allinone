package native

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestTwofishKnownAnswers(t *testing.T) {
	for _, v := range []struct {
		size   int
		cipher string
	}{{16, "9f589f5cf6122c32b6bfec2f2ae8c35a"}, {24, "efa71f788965bd4453f860178fc19101"}, {32, "57ff739d4dc92c1bd7fc01700cc8216f"}} {
		c, e := newTwofish(make([]byte, v.size))
		if e != nil {
			t.Fatal(e)
		}
		b := make([]byte, 16)
		c.Encrypt(b, b)
		if hex.EncodeToString(b) != v.cipher {
			t.Fatal(v.size, hex.EncodeToString(b))
		}
		c.Decrypt(b, b)
		if !bytes.Equal(b, make([]byte, 16)) {
			t.Fatal("decrypt", b)
		}
	}
}
