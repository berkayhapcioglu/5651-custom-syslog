package store

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// HourEntry describes one sealed hourly file.
type HourEntry struct {
	Device     string `json:"device"`
	Hour       string `json:"hour"`
	File       string `json:"file"` // relative to the day dir
	Lines      int64  `json:"lines"`
	RawBytes   int64  `json:"raw_bytes"`
	RawSHA256  string `json:"raw_sha256"`
	FileBytes  int64  `json:"file_bytes"`
	FileSHA256 string `json:"file_sha256"`
	Codec      string `json:"codec"`
	SealedAt   string `json:"sealed_at"`
	// Prev is the previous entry's Chain in this day (empty for the first);
	// Chain = sha256(Prev || canonical JSON of the entry without Chain).
	Prev  string `json:"prev"`
	Chain string `json:"chain,omitempty"`
}

// chainOf computes the chain hash of e (whose Chain must be empty).
func chainOf(e HourEntry) (string, error) {
	e.Chain = ""
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(e.Prev))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}

var hoursMu sync.Mutex

// AppendHour appends e to the day's hours.jsonl, linking it into the chain.
func AppendHour(dayDir string, e HourEntry) (HourEntry, error) {
	hoursMu.Lock()
	defer hoursMu.Unlock()
	entries, err := ReadHours(dayDir)
	if err != nil {
		return e, err
	}
	e.Prev = ""
	if len(entries) > 0 {
		e.Prev = entries[len(entries)-1].Chain
	}
	e.Chain = ""
	if e.Chain, err = chainOf(e); err != nil {
		return e, err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return e, err
	}
	f, err := os.OpenFile(filepath.Join(dayDir, HoursFile), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) // #nosec G304 -- path built from validated components
	if err != nil {
		return e, err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return e, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return e, err
	}
	return e, f.Close()
}

// ReadHours reads and chain-verifies a day's hours.jsonl. A missing file is empty.
func ReadHours(dayDir string) ([]HourEntry, error) {
	f, err := os.Open(filepath.Join(dayDir, HoursFile)) // #nosec G304 -- path built from validated components
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []HourEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	prev := ""
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e HourEntry
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", HoursFile, n, err)
		}
		if e.Prev != prev {
			return nil, fmt.Errorf("%s line %d: chain broken", HoursFile, n)
		}
		want, err := chainOf(e)
		if err != nil {
			return nil, err
		}
		if want != e.Chain {
			return nil, fmt.Errorf("%s line %d: chain hash mismatch", HoursFile, n)
		}
		prev = e.Chain
		out = append(out, e)
	}
	return out, sc.Err()
}

// HasHour reports whether the day already lists device/hour.
func HasHour(dayDir, device, hour string) (bool, error) {
	es, err := ReadHours(dayDir)
	if err != nil {
		return false, err
	}
	for _, e := range es {
		if e.Device == device && e.Hour == hour {
			return true, nil
		}
	}
	return false, nil
}
