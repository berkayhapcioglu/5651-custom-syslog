package store

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/tsa"
)

// Manifest is the per tenant, per day document that gets time stamped.
type Manifest struct {
	Format   string `json:"format"`
	Tenant   string `json:"tenant"`
	Day      string `json:"day"`
	Timezone string `json:"timezone"`
	// PrevManifestSHA256 links to the tenant's previous sealed day, so days
	// cannot be removed or swapped without breaking the chain.
	PrevManifestSHA256 string      `json:"prev_manifest_sha256"`
	PrevDay            string      `json:"prev_day"`
	HoursChain         string      `json:"hours_chain"`
	Files              []HourEntry `json:"files"`
	TotalLines         int64       `json:"total_lines"`
	TotalRawBytes      int64       `json:"total_raw_bytes"`
	TotalFileBytes     int64       `json:"total_file_bytes"`
	CreatedAt          string      `json:"created_at"`
}

// SealedInfo is written to the SEALED marker.
type SealedInfo struct {
	ManifestSHA256 string `json:"manifest_sha256"`
	StampTime      string `json:"stamp_time,omitempty"`
	StampSerial    string `json:"stamp_serial,omitempty"`
	TSA            string `json:"tsa,omitempty"`
	SealedAt       string `json:"sealed_at"`
}

// DaySealer seals finished days: builds the manifest, time stamps it and
// writes the SEALED marker.
type DaySealer struct {
	Root    string
	Loc     *time.Location
	Grace   time.Duration
	Stamper tsa.Stamper // nil = no time stamp (testing only)
	Roots   *x509.CertPool
	Sealer  *Sealer
	Log     *slog.Logger
	Now     func() time.Time
	Tenants func() []string
}

func (d *DaySealer) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Run seals due days every minute until ctx ends.
func (d *DaySealer) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		d.SealDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// SealDue seals every unsealed day whose end (+grace) has passed.
func (d *DaySealer) SealDue(ctx context.Context) {
	for _, tenant := range d.Tenants() {
		days, err := ListDays(d.Root, tenant)
		if err != nil {
			d.Log.Error("list days", "tenant", tenant, "err", err)
			continue
		}
		for _, day := range days {
			if IsSealed(DayDir(d.Root, tenant, day)) || !d.due(day) {
				continue
			}
			if err := d.SealDay(ctx, tenant, day); err != nil {
				d.Log.Error("seal day", "tenant", tenant, "day", day, "err", err)
			}
		}
	}
}

func (d *DaySealer) due(day string) bool {
	start, err := time.ParseInLocation(DayLayout, day, d.Loc)
	if err != nil {
		return false
	}
	return d.now().After(start.AddDate(0, 0, 1).Add(d.Grace))
}

// SealDay seals one day. It is idempotent and safe to retry.
func (d *DaySealer) SealDay(ctx context.Context, tenant, day string) error {
	dir := DayDir(d.Root, tenant, day)
	if IsSealed(dir) {
		return nil
	}
	// Seal any raw hour left behind (e.g. the service was down at rotation).
	raws, _ := filepath.Glob(filepath.Join(dir, "*", "*"+RawExt))
	for _, r := range raws {
		if err := d.Sealer.SealHour(r); err != nil {
			return fmt.Errorf("seal leftover %s: %w", r, err)
		}
	}
	mPath := filepath.Join(dir, ManifestFile)
	mb, err := os.ReadFile(mPath) // #nosec G304 -- under data dir
	if errors.Is(err, os.ErrNotExist) {
		mb, err = d.buildManifest(tenant, day)
		if err != nil {
			return err
		}
		if err := writeFileSync(mPath, mb, 0o400); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	info := SealedInfo{ManifestSHA256: hexSum(mb), SealedAt: d.now().UTC().Format(time.RFC3339)}
	if d.Stamper != nil {
		tPath := filepath.Join(dir, StampFile)
		resp, err := os.ReadFile(tPath) // #nosec G304 -- under data dir
		if err != nil {
			resp, err = d.Stamper.Stamp(ctx, mb, mPath)
			if err != nil {
				return fmt.Errorf("time stamp: %w", err)
			}
		}
		res, err := tsa.Check(resp, mb, d.Roots)
		if err != nil {
			return err
		}
		if err := writeFileSync(tPath, resp, 0o400); err != nil {
			return err
		}
		info.StampTime = res.Time.UTC().Format(time.RFC3339Nano)
		info.StampSerial = res.Serial
		info.TSA = res.Subject
	}
	ib, _ := json.MarshalIndent(info, "", "  ")
	if err := writeFileSync(filepath.Join(dir, SealedMarker), append(ib, '\n'), 0o400); err != nil {
		return err
	}
	d.Log.Info("sealed day", "tenant", tenant, "day", day, "manifest_sha256", info.ManifestSHA256, "stamp_time", info.StampTime)
	return nil
}

func (d *DaySealer) buildManifest(tenant, day string) ([]byte, error) {
	dir := DayDir(d.Root, tenant, day)
	hours, err := ReadHours(dir)
	if err != nil {
		return nil, err
	}
	m := Manifest{
		Format:    "s5651-manifest-v1",
		Tenant:    tenant,
		Day:       day,
		Timezone:  d.Loc.String(),
		Files:     hours,
		CreatedAt: d.now().UTC().Format(time.RFC3339),
	}
	if len(hours) > 0 {
		m.HoursChain = hours[len(hours)-1].Chain
	}
	for _, h := range hours {
		m.TotalLines += h.Lines
		m.TotalRawBytes += h.RawBytes
		m.TotalFileBytes += h.FileBytes
	}
	sort.SliceStable(m.Files, func(i, j int) bool {
		if m.Files[i].Device != m.Files[j].Device {
			return m.Files[i].Device < m.Files[j].Device
		}
		return m.Files[i].Hour < m.Files[j].Hour
	})
	prevDay, prevSum, err := previousSealed(d.Root, tenant, day)
	if err != nil {
		return nil, err
	}
	m.PrevDay, m.PrevManifestSHA256 = prevDay, prevSum
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// previousSealed finds the latest sealed day before day and its manifest hash.
func previousSealed(root, tenant, day string) (string, string, error) {
	days, err := ListDays(root, tenant)
	if err != nil {
		return "", "", err
	}
	for i := len(days) - 1; i >= 0; i-- {
		if days[i] >= day {
			continue
		}
		dir := DayDir(root, tenant, days[i])
		if !IsSealed(dir) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, ManifestFile)) // #nosec G304 -- under data dir
		if err != nil {
			return "", "", err
		}
		return days[i], hexSum(b), nil
	}
	// Retention may have removed earlier days; the audit log keeps their hashes.
	return "", "", nil
}

// ListDays returns the tenant's day directories, oldest first.
func ListDays(root, tenant string) ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(root, tenant))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() && ValidDay(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// IsSealed reports whether a day directory carries the SEALED marker.
func IsSealed(dayDir string) bool {
	_, err := os.Stat(filepath.Join(dayDir, SealedMarker))
	return err == nil
}

// ReadSealedInfo reads the SEALED marker.
func ReadSealedInfo(dayDir string) (*SealedInfo, error) {
	b, err := os.ReadFile(filepath.Join(dayDir, SealedMarker)) // #nosec G304 -- under data dir
	if err != nil {
		return nil, err
	}
	var s SealedInfo
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ReadManifest parses a day's manifest.
func ReadManifest(dayDir string) (*Manifest, []byte, error) {
	b, err := os.ReadFile(filepath.Join(dayDir, ManifestFile)) // #nosec G304 -- under data dir
	if err != nil {
		return nil, nil, err
	}
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, nil, err
	}
	return &m, b, nil
}
