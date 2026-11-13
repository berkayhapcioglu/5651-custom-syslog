package web

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/colz"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/store"
)

// Many hits in one hour: the page shows the newest 500 in order, the CSV
// gets all of them, and a sealed hour streams back for search and download.
func TestSearchManyHitsAndSealedStream(t *testing.T) {
	old := colz.ChunkSize
	colz.ChunkSize = 16 << 10
	defer func() { colz.ChunkSize = old }()
	ts, dir := testServer(t)
	c := client(ts)
	login(t, ts, c, "ali", testPassword)

	devDir := filepath.Join(dir, "musteri-a", "2026-11-09", "10.0.0.1")
	os.MkdirAll(devDir, 0o700)
	var raw bytes.Buffer
	for i := 0; i < 1200; i++ {
		fmt.Fprintf(&raw, "2026-11-09T07:%02d:%02d.000000000Z\t10.0.0.1\tuser=ali seq=%04d\n", i/60, i%60, i)
	}
	os.WriteFile(filepath.Join(devDir, "10.log"), raw.Bytes(), 0o600)
	os.WriteFile(filepath.Join(devDir, "11.log"), raw.Bytes(), 0o600)

	check := func(what string) {
		t.Helper()
		_, body, _ := get(t, c, ts.URL+"/t/musteri-a/search?q=ali&from=2026-11-09&to=2026-11-09&hfrom=10&hto=10")
		first := strings.Index(body, "seq=1199")
		if first < 0 || strings.Index(body, "seq=1198") < first || strings.Contains(body, "seq=0699") {
			t.Fatalf("%s: page should list the newest 500 hits, newest first", what)
		}
		_, body, _ = get(t, c, ts.URL+"/t/musteri-a/search?q=ali&order=asc&from=2026-11-09&to=2026-11-09&hfrom=10&hto=10")
		if !strings.Contains(body, "seq=0000") || strings.Contains(body, "seq=0500") {
			t.Fatalf("%s: ascending page should hold the first 500 hits", what)
		}
		_, body, _ = get(t, c, ts.URL+"/t/musteri-a/search.csv?q=ali&from=2026-11-09&to=2026-11-09&hfrom=10&hto=11")
		if n := strings.Count(body, "user=ali"); n != 2400 {
			t.Fatalf("%s: csv has %d hits, want 2400", what, n)
		}
	}
	check("open hour")

	sl := &store.Sealer{Root: dir, Codec: colz.Zstd{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := sl.SealHour(filepath.Join(devDir, "10.log")); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(devDir, "10.idx")) // search must work without the index too
	check("sealed hour")

	code, body, h := get(t, c, ts.URL+"/t/musteri-a/d/2026-11-09/raw/10.0.0.1/10")
	if code != 200 || body != raw.String() || !strings.Contains(h.Get("Content-Disposition"), "attachment") {
		t.Fatalf("raw download: %d, %d bytes", code, len(body))
	}
	// A changed sealed file is refused with an error, not served.
	sealed := filepath.Join(devDir, "10"+store.SealedExt)
	os.Chmod(sealed, 0o600)
	b, _ := os.ReadFile(sealed)
	b[len(b)/2] ^= 1
	os.WriteFile(sealed, b, 0o600)
	if code, body, _ := get(t, c, ts.URL+"/t/musteri-a/d/2026-11-09/raw/10.0.0.1/10"); code != 500 || strings.Contains(body, "seq=") {
		t.Fatalf("tampered raw download: %d", code)
	}
}

// One user holds at most one heavy slot; others still get theirs.
func TestHeavyPerUser(t *testing.T) {
	testServer(t)
	s := lastServer
	r := httptest.NewRequest("GET", "/", nil)
	rel, ok := s.acquireHeavy(httptest.NewRecorder(), r, "ali")
	if !ok {
		t.Fatal("first job refused")
	}
	w := httptest.NewRecorder()
	if _, ok := s.acquireHeavy(w, r, "ali"); ok || w.Code != 429 {
		t.Fatalf("second job of the same user: %d", w.Code)
	}
	rel2, ok := s.acquireHeavy(httptest.NewRecorder(), r, "admin")
	if !ok {
		t.Fatal("other user refused")
	}
	rel()
	rel2()
	rel3, ok := s.acquireHeavy(httptest.NewRecorder(), r, "ali")
	if !ok {
		t.Fatal("slot not released")
	}
	rel3()
}
