package store

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIndexNoFalseNegatives(t *testing.T) {
	var raw bytes.Buffer
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&raw, "2026-11-09T10:00:%02d.000000Z\t10.0.0.1\tdevname=FW%d action=deny user=Kullanici%d srcip=192.0.2.%d url=https://ornek%d.com.tr/x\n", i%60, i%3, i, i%250, i)
	}
	b, err := BuildIndex(bytes.NewReader(raw.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	ix, err := ParseIndex(b)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2000; i += 37 {
		for _, q := range []string{fmt.Sprintf("kullanici%d", i), fmt.Sprintf("https://ornek%d.com.tr/x", i), fmt.Sprintf("192.0.2.%d", i%250), "deny", "fw1"} {
			for _, tok := range QueryTokens([]byte(q)) {
				if !ix.MayContain(tok) {
					t.Fatalf("false negative for %q", q)
				}
			}
		}
	}
	miss := 0
	for i := 0; i < 1000; i++ {
		if ix.MayContain([]byte(fmt.Sprintf("yok%dkelime", i))) {
			miss++
		}
	}
	if miss > 30 { // about 1% expected at 10 bits per word
		t.Fatalf("false positive rate too high: %d/1000", miss)
	}
}

func TestIndexCorrupt(t *testing.T) {
	b, _ := BuildIndex(strings.NewReader("t\ts\thello world\n"))
	for _, bad := range [][]byte{nil, b[:10], append(append([]byte(nil), b[:len(b)-1]...), b[len(b)-1]^1)} {
		if _, err := ParseIndex(bad); err == nil {
			t.Fatal("corrupt index accepted")
		}
	}
	// A broken index on disk is reported as unusable, so search scans the hour.
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "fw1"), 0o750)
	os.WriteFile(filepath.Join(dir, "fw1", "10"+IndexExt), b[:len(b)-3], 0o600)
	if _, err := ReadIndex(dir, HourEntry{Device: "fw1", Hour: "10"}); err == nil {
		t.Fatal("truncated index read as valid")
	}
	if _, err := ReadIndex(dir, HourEntry{Device: "../x", Hour: "10"}); err == nil {
		t.Fatal("path escape accepted")
	}
}

func TestMatchWords(t *testing.T) {
	for _, c := range []struct {
		line, q string
		want    bool
	}{
		{"user=ali action=deny", "ali", true},
		{"user=alice action=deny", "ali", false},
		{"user=alice ali", "ali", true},
		{"srcip=10.0.0.5 dst", "10.0.0.5", true},
		{"srcip=10.0.0.55", "10.0.0.5", false},
		{"action=deny", "action=deny", true},
	} {
		if got := MatchWords([]byte(c.line), []byte(c.q)); got != c.want {
			t.Errorf("MatchWords(%q,%q)=%v", c.line, c.q, got)
		}
	}
}
