package colz

import (
	"bytes"
	"os"
	"testing"
	"time"
)

// TestBenchFile measures ratios on a real log: COLZ_BENCH=/path/to/raw.log
// (lines in the stored "<time>\t<source>\t<message>" form).
func TestBenchFile(t *testing.T) {
	p := os.Getenv("COLZ_BENCH")
	if p == "" {
		t.Skip("COLZ_BENCH not set")
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []Codec{Zstd{}, XZ{}, XZ{Command: "xz"}} {
		for _, plain := range []bool{true, false} {
			s := time.Now()
			var buf bytes.Buffer
			if plain {
				err = EncodePlain(&buf, raw, c)
			} else {
				err = Encode(&buf, raw, c)
			}
			if err != nil {
				t.Log(c.Name(), err)
				continue
			}
			t.Logf("%-5s cmd=%-3v columnar=%-5v %.1fx %v", c.Name(), c.(interface{ Name() string }).Name() == "xz" && c.(XZ).Command != "", !plain, float64(len(raw))/float64(buf.Len()), time.Since(s))
		}
	}
}
