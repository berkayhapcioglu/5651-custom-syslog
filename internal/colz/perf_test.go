package colz

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestPathologicalInputsAreFast guards against inputs that make the
// transform slow (log data is attacker-influenced).
func TestPathologicalInputsAreFast(t *testing.T) {
	ts := "2026-11-10T10:00:00.000000000Z\t1.2.3.4\t"
	var many, wide, keys bytes.Buffer
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(&many, "%sk%d=1 x%d=2\n", ts, i, i) // new columns and templates on every line
	}
	wide.WriteString(ts + strings.Repeat("a=1 ", 250000) + "\n")
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&keys, "%s%s\n", ts, strings.Repeat(fmt.Sprintf("k%d=v ", i%300), 200))
	}
	for name, in := range map[string][]byte{"many": many.Bytes(), "wide": wide.Bytes(), "keys": keys.Bytes()} {
		s := time.Now()
		roundTrip(t, in, storeCodec{})
		if d := time.Since(s); d > 5*time.Second {
			t.Errorf("%s took %v", name, d)
		}
		t.Logf("%s: %v", name, time.Since(s))
	}
}
