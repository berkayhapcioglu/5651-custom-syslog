package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/colz"
)

// A sealed hour made of many containers streams back byte for byte, and a
// changed file is refused before anything is written.
func TestStreamSealed(t *testing.T) {
	old := colz.ChunkSize
	colz.ChunkSize = 8 << 10
	defer func() { colz.ChunkSize = old }()

	root := t.TempDir()
	devDir := filepath.Join(root, "musteri-a", "2026-11-09", "10.0.0.1")
	if err := os.MkdirAll(devDir, 0o700); err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&raw, "2026-11-09T07:%02d:%02d.000000000Z\t10.0.0.1\t<190>date=2026-11-09 srcip=10.1.%d.%d action=accept seq=%d\n", i/60%60, i%60, i/250, i%250, i)
	}
	rawPath := filepath.Join(devDir, "10.log")
	if err := os.WriteFile(rawPath, raw.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := newSealer(root).SealHour(rawPath); err != nil {
		t.Fatal(err)
	}
	dayDir := filepath.Dir(devDir)
	hours, err := ReadHours(dayDir)
	if err != nil || len(hours) != 1 {
		t.Fatal(hours, err)
	}
	var out bytes.Buffer
	if err := StreamSealed(dayDir, hours[0], &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), raw.Bytes()) {
		t.Fatal("streamed content differs")
	}

	sealed := filepath.Join(devDir, "10"+SealedExt)
	os.Chmod(sealed, 0o600)
	b, _ := os.ReadFile(sealed)
	b[len(b)/2] ^= 1
	os.WriteFile(sealed, b, 0o600)
	out.Reset()
	if err := StreamSealed(dayDir, hours[0], &out); !errors.Is(err, ErrSealedMismatch) || out.Len() != 0 {
		t.Fatalf("tampered file: err=%v, %d bytes written", err, out.Len())
	}
}
