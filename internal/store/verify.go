package store

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/tsa"
)

// VerifyReport is the outcome of verifying one sealed day.
type VerifyReport struct {
	Tenant     string
	Day        string
	Files      int
	Lines      int64
	StampTime  string
	TSA        string
	ChainToCA  bool
	PrevDayOK  bool
	PrevDay    string
	ManifestOK bool
}

// VerifyDay checks a sealed day end to end: the time stamp covers the
// manifest, every listed file exists with the listed hash, every file
// decodes to content with the listed raw hash, the hour chain is intact and
// the link to the previous day matches.
func VerifyDay(root, tenant, day string, roots *x509.CertPool, requireStamp bool) (*VerifyReport, error) {
	dir, err := SafeJoin(root, tenant, day)
	if err != nil {
		return nil, err
	}
	rep := &VerifyReport{Tenant: tenant, Day: day, ChainToCA: roots != nil}
	m, mb, err := ReadManifest(dir)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Tenant != tenant || m.Day != day {
		return nil, fmt.Errorf("manifest names %s/%s, expected %s/%s", m.Tenant, m.Day, tenant, day)
	}
	resp, err := os.ReadFile(filepath.Join(dir, StampFile)) // #nosec G304 -- SafeJoin above
	switch {
	case err == nil:
		res, err := tsa.Check(resp, mb, roots)
		if err != nil {
			return nil, err
		}
		rep.StampTime = res.Time.UTC().Format("2006-01-02T15:04:05.000Z07:00")
		rep.TSA = res.Subject
	case requireStamp:
		return nil, fmt.Errorf("no time stamp (%s)", StampFile)
	}

	hours, err := ReadHours(dir)
	if err != nil {
		return nil, err
	}
	if len(hours) != len(m.Files) {
		return nil, fmt.Errorf("manifest lists %d files, %s has %d", len(m.Files), HoursFile, len(hours))
	}
	if len(hours) > 0 && hours[len(hours)-1].Chain != m.HoursChain {
		return nil, fmt.Errorf("hour chain head does not match the manifest")
	}
	for _, e := range m.Files {
		if !ValidDevice(e.Device) || !ValidHour(e.Hour) {
			return nil, fmt.Errorf("manifest has invalid entry %q/%q", e.Device, e.Hour)
		}
		if _, err := ReadSealed(dir, e); err != nil {
			return nil, err
		}
		rep.Files++
		rep.Lines += e.Lines
	}
	rep.ManifestOK = true
	if m.PrevDay != "" {
		rep.PrevDay = m.PrevDay
		prevDir, err := SafeJoin(root, tenant, m.PrevDay)
		if err != nil {
			return nil, err
		}
		pb, err := os.ReadFile(filepath.Join(prevDir, ManifestFile)) // #nosec G304 -- SafeJoin above
		if err == nil {
			if hexSum(pb) != m.PrevManifestSHA256 {
				return nil, fmt.Errorf("previous day %s manifest hash does not match the link", m.PrevDay)
			}
			rep.PrevDayOK = true
		}
	}
	return rep, nil
}
