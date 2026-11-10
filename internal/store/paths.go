// Package store writes incoming records to hourly raw files and seals each
// closed hour into a compressed, hashed file listed in the day's manifest.
//
// Layout under data_dir:
//
//	<tenant>/<YYYY-MM-DD>/<device>/<HH>.log      raw file of the current hour
//	<tenant>/<YYYY-MM-DD>/<device>/<HH>.s5651    sealed (columnar, compressed)
//	<tenant>/<YYYY-MM-DD>/hours.jsonl            one entry per sealed hour, hash chained
//	<tenant>/<YYYY-MM-DD>/manifest.json          day manifest (written at day seal)
//	<tenant>/<YYYY-MM-DD>/manifest.json.tsr      RFC 3161 time stamp response
//	<tenant>/<YYYY-MM-DD>/SEALED                 marker, written last
package store

import (
	"errors"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	RawExt       = ".log"
	SealedExt    = ".s5651"
	HoursFile    = "hours.jsonl"
	ManifestFile = "manifest.json"
	StampFile    = "manifest.json.tsr"
	SealedMarker = "SEALED"
	DayLayout    = "2006-01-02"
	RecordTime   = "2006-01-02T15:04:05.000000000Z07:00"
)

var (
	devicePattern = regexp.MustCompile(`^[0-9a-f._]{1,64}$`)
	dayPattern    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	hourPattern   = regexp.MustCompile(`^([01]\d|2[0-3])$`)
)

// DeviceName turns a source address into a safe directory name.
func DeviceName(a netip.Addr) string {
	return strings.ReplaceAll(a.Unmap().String(), ":", "_")
}

// ValidDevice reports whether s is a safe device directory name.
func ValidDevice(s string) bool { return devicePattern.MatchString(s) }

// ValidDay reports whether s is a YYYY-MM-DD day directory name.
func ValidDay(s string) bool {
	if !dayPattern.MatchString(s) {
		return false
	}
	_, err := time.Parse(DayLayout, s)
	return err == nil
}

// ValidHour reports whether s is a two digit hour.
func ValidHour(s string) bool { return hourPattern.MatchString(s) }

// DayDir returns <root>/<tenant>/<day>.
func DayDir(root, tenant, day string) string { return filepath.Join(root, tenant, day) }

// HourPath returns the raw (ext RawExt) or sealed (ext SealedExt) path of an hour.
func HourPath(root, tenant, day, device, hour, ext string) string {
	return filepath.Join(root, tenant, day, device, hour+ext)
}

// SafeJoin joins untrusted path elements under root and refuses anything that
// escapes it. Every element must be a single, non-special name.
func SafeJoin(root string, elems ...string) (string, error) {
	p := root
	for _, e := range elems {
		if e == "" || e == "." || e == ".." || strings.ContainsAny(e, `/\`+"\x00") {
			return "", errors.New("invalid path element")
		}
		p = filepath.Join(p, e)
	}
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes data dir")
	}
	return p, nil
}
