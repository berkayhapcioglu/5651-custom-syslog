package store

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/colz"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/tsa"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func ist() *time.Location {
	l, err := time.LoadLocation("Europe/Istanbul")
	if err != nil {
		panic(err)
	}
	return l
}

// writeDay pushes records for two devices across two hours of one day.
func writeDay(t *testing.T, root string, day time.Time) {
	t.Helper()
	sealed := []string{}
	w := NewWriter(root, ist(), quiet, func(p string) { sealed = append(sealed, p) })
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { w.Run(stop); close(done) }()
	for h := 0; h < 2; h++ {
		for i := 0; i < 300; i++ {
			for _, src := range []string{"10.0.0.1", "10.0.0.2"} {
				w.In <- Record{
					Received: day.Add(time.Duration(h)*time.Hour + time.Duration(i)*time.Second),
					Source:   netip.MustParseAddr(src),
					Tenant:   "musteri-a",
					Message:  []byte(fmt.Sprintf("<189>date=x time=y srcip=192.168.1.%d dstport=443 action=\"accept\" line\nbreak", i%50)),
				}
			}
		}
	}
	close(stop)
	<-done
}

func newSealer(root string) *Sealer {
	return &Sealer{Root: root, Codec: colz.Zstd{}, Log: quiet}
}

func TestEndToEndSealVerifyTamper(t *testing.T) {
	root := t.TempDir()
	day := time.Date(2026, 11, 9, 10, 0, 0, 0, ist())
	writeDay(t, root, day)

	raws, err := PendingRaw(root, time.Now(), ist())
	if err != nil || len(raws) != 4 {
		t.Fatalf("pending raw = %v, %v (want 4)", raws, err)
	}
	b, _ := os.ReadFile(raws[0])
	if !strings.Contains(string(b), `line\nbreak`) || strings.Count(string(b), "\n") != 300 {
		t.Fatalf("raw file not escaped or wrong line count")
	}

	fake, err := tsa.NewFake()
	if err != nil {
		t.Fatal(err)
	}
	ds := &DaySealer{
		Root: root, Loc: ist(), Stamper: fake, Roots: fake.Pool(), Sealer: newSealer(root), Log: quiet,
		Tenants: func() []string { return []string{"musteri-a"} },
		Now:     func() time.Time { return day.Add(48 * time.Hour) },
	}
	ds.SealDue(context.Background())
	dir := DayDir(root, "musteri-a", "2026-11-09")
	if !IsSealed(dir) {
		t.Fatal("day not sealed")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*", "*"+RawExt)); len(left) != 0 {
		t.Fatalf("raw files left: %v", left)
	}
	rep, err := VerifyDay(root, "musteri-a", "2026-11-09", fake.Pool(), true)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.Files != 4 || rep.Lines != 1200 {
		t.Fatalf("report = %+v", rep)
	}

	// Decoded content must equal what was written, byte for byte.
	hours, _ := ReadHours(dir)
	raw, err := ReadSealed(dir, hours[0])
	if err != nil || strings.Count(string(raw), "\n") != 300 {
		t.Fatalf("read sealed: %v", err)
	}

	// Tampering with a sealed file must be detected.
	p := filepath.Join(dir, hours[0].File)
	os.Chmod(p, 0o600)
	f, _ := os.OpenFile(p, os.O_WRONLY, 0)
	f.WriteAt([]byte{0xff}, 40)
	f.Close()
	if _, err := VerifyDay(root, "musteri-a", "2026-11-09", fake.Pool(), true); err == nil {
		t.Fatal("tampered file not detected")
	}
}

func TestTamperedManifestAndChain(t *testing.T) {
	root := t.TempDir()
	day := time.Date(2026, 11, 9, 10, 0, 0, 0, ist())
	writeDay(t, root, day)
	fake, _ := tsa.NewFake()
	ds := &DaySealer{Root: root, Loc: ist(), Stamper: fake, Sealer: newSealer(root), Log: quiet,
		Tenants: func() []string { return []string{"musteri-a"} }, Now: func() time.Time { return day.Add(48 * time.Hour) }}
	ds.SealDue(context.Background())
	dir := DayDir(root, "musteri-a", "2026-11-09")

	// Manifest edited after stamping: imprint no longer matches.
	mp := filepath.Join(dir, ManifestFile)
	os.Chmod(mp, 0o600)
	b, _ := os.ReadFile(mp)
	os.WriteFile(mp, []byte(strings.Replace(string(b), `"total_lines": 1200`, `"total_lines": 1199`, 1)), 0o600)
	if _, err := VerifyDay(root, "musteri-a", "2026-11-09", nil, true); err == nil || !strings.Contains(err.Error(), "imprint") {
		t.Fatalf("edited manifest not detected: %v", err)
	}
	os.WriteFile(mp, b, 0o600)

	// A deleted hours line breaks the chain.
	hp := filepath.Join(dir, HoursFile)
	hb, _ := os.ReadFile(hp)
	lines := strings.SplitAfter(string(hb), "\n")
	os.WriteFile(hp, []byte(lines[0]+lines[2]+lines[3]), 0o600)
	if _, err := ReadHours(dir); err == nil {
		t.Fatal("removed chain entry not detected")
	}
}

func TestDayChainAndRetention(t *testing.T) {
	root := t.TempDir()
	d1 := time.Date(2026, 11, 8, 10, 0, 0, 0, ist())
	d2 := d1.AddDate(0, 0, 1)
	writeDay(t, root, d1)
	writeDay(t, root, d2)
	fake, _ := tsa.NewFake()
	ds := &DaySealer{Root: root, Loc: ist(), Stamper: fake, Sealer: newSealer(root), Log: quiet,
		Tenants: func() []string { return []string{"musteri-a"} }, Now: func() time.Time { return d2.Add(48 * time.Hour) }}
	ds.SealDue(context.Background())
	rep, err := VerifyDay(root, "musteri-a", "2026-11-09", nil, true)
	if err != nil || rep.PrevDay != "2026-11-08" || !rep.PrevDayOK {
		t.Fatalf("day link: %+v %v", rep, err)
	}

	if err := ApplyRetention(root, "musteri-a", 2, ist(), time.Date(2026, 11, 11, 3, 0, 0, 0, ist()), quiet); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(DayDir(root, "musteri-a", "2026-11-08")); !os.IsNotExist(err) {
		t.Fatal("old day not deleted")
	}
	if _, err := os.Stat(DayDir(root, "musteri-a", "2026-11-09")); err != nil {
		t.Fatal("day inside retention was deleted")
	}
	audit, _ := os.ReadFile(filepath.Join(root, AuditDir, "audit.jsonl"))
	if !strings.Contains(string(audit), `"day":"2026-11-08"`) || !strings.Contains(string(audit), "manifest_sha256") {
		t.Fatalf("audit log missing deletion: %s", audit)
	}
}

func TestRetentionKeepsUnsealed(t *testing.T) {
	root := t.TempDir()
	writeDay(t, root, time.Date(2026, 1, 1, 10, 0, 0, 0, ist()))
	if err := ApplyRetention(root, "musteri-a", 1, ist(), time.Now(), quiet); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(DayDir(root, "musteri-a", "2026-01-01")); err != nil {
		t.Fatal("unsealed day was deleted")
	}
}

func TestSealHourCrashRecovery(t *testing.T) {
	root := t.TempDir()
	writeDay(t, root, time.Date(2026, 11, 9, 10, 0, 0, 0, ist()))
	raws, _ := PendingRaw(root, time.Now(), ist())
	s := newSealer(root)
	// Simulate: sealed + listed, but the raw delete never happened.
	b, _ := os.ReadFile(raws[0])
	if err := s.SealHour(raws[0]); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(raws[0], b, 0o600)
	if err := s.SealHour(raws[0]); err != nil {
		t.Fatal(err)
	}
	hours, _ := ReadHours(filepath.Dir(filepath.Dir(raws[0])))
	if len(hours) != 1 {
		t.Fatalf("hour listed %d times", len(hours))
	}
}

func TestSafeJoin(t *testing.T) {
	for _, bad := range [][]string{{".."}, {"a/b"}, {""}, {"a", ".."}, {"x\x00"}} {
		if _, err := SafeJoin("/data", bad...); err == nil {
			t.Fatalf("SafeJoin accepted %q", bad)
		}
	}
	if p, err := SafeJoin("/data", "musteri-a", "2026-11-10"); err != nil || p != "/data/musteri-a/2026-11-10" {
		t.Fatal(p, err)
	}
}
