package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/colz"
)

// Sealer compresses closed hourly raw files and records them in the manifest.
type Sealer struct {
	Root  string
	Codec colz.Codec
	Log   *slog.Logger
	// Now is overridable in tests.
	Now func() time.Time
}

// SealHour seals one raw file at <root>/<tenant>/<day>/<device>/<HH>.log.
// It is safe to call again after a crash at any point.
func (s *Sealer) SealHour(rawPath string) error {
	device := filepath.Base(filepath.Dir(rawPath))
	dayDir := filepath.Dir(filepath.Dir(rawPath))
	hour := strings.TrimSuffix(filepath.Base(rawPath), RawExt)
	if !ValidDevice(device) || !ValidHour(hour) || !ValidDay(filepath.Base(dayDir)) {
		return fmt.Errorf("seal: unexpected path %s", rawPath)
	}
	sealedPath := filepath.Join(filepath.Dir(rawPath), hour+SealedExt)
	// The writer, start-up recovery and the day sealer may all ask for the
	// same hour; only one may work on it at a time.
	unlock := lockPath(rawPath)
	defer unlock()
	if _, err := os.Stat(rawPath); errors.Is(err, os.ErrNotExist) {
		if listed, _ := HasHour(dayDir, device, hour); listed {
			return nil // sealed by another caller meanwhile
		}
	}

	// Crash recovery: sealed and listed already, only the raw delete was lost.
	// A listed hour is never written again.
	listed, err := HasHour(dayDir, device, hour)
	if err != nil {
		return err
	}
	if listed {
		if _, err := os.Stat(sealedPath); err != nil {
			return fmt.Errorf("seal %s: hour is listed but its sealed file is missing; raw kept", rawPath)
		}
		s.writeIndex(dayDir, device, hour, rawPath)
		return os.Remove(rawPath)
	}

	rawSum, rawBytes, lines, err := hashFile(rawPath)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := s.encode(&buf, rawPath, false); err != nil {
		return err
	}
	if !s.roundTrips(buf.Bytes(), rawSum) {
		s.Log.Warn("columnar round trip failed, storing plain", "file", rawPath)
		buf.Reset()
		if err := s.encode(&buf, rawPath, true); err != nil {
			return err
		}
		if !s.roundTrips(buf.Bytes(), rawSum) {
			return fmt.Errorf("seal %s: compressed file does not decode to the original; raw kept", rawPath)
		}
	}

	if err := writeFileSync(sealedPath, buf.Bytes(), 0o400); err != nil {
		return err
	}
	fileSum := sha256.Sum256(buf.Bytes())
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	_, err = AppendHour(dayDir, HourEntry{
		Device:     device,
		Hour:       hour,
		File:       filepath.Join(device, hour+SealedExt),
		Lines:      lines,
		RawBytes:   rawBytes,
		RawSHA256:  hex.EncodeToString(rawSum[:]),
		FileBytes:  int64(buf.Len()),
		FileSHA256: hex.EncodeToString(fileSum[:]),
		Codec:      s.Codec.Name(),
		SealedAt:   now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	s.writeIndex(dayDir, device, hour, rawPath)
	s.Log.Info("sealed hour", "file", sealedPath, "raw_bytes", rawBytes, "sealed_bytes", buf.Len(),
		"ratio", fmt.Sprintf("%.1f", float64(rawBytes)/float64(max(buf.Len(), 1))))
	return os.Remove(rawPath)
}

var (
	pathLocksMu sync.Mutex
	pathLocks   = map[string]*pathLock{}
)

type pathLock struct {
	mu   sync.Mutex
	refs int
}

// lockPath serializes work on one file path and returns the unlock function.
func lockPath(p string) func() {
	pathLocksMu.Lock()
	l := pathLocks[p]
	if l == nil {
		l = &pathLock{}
		pathLocks[p] = l
	}
	l.refs++
	pathLocksMu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		pathLocksMu.Lock()
		if l.refs--; l.refs == 0 {
			delete(pathLocks, p)
		}
		pathLocksMu.Unlock()
	}
}

// writeIndex builds the search index from the raw file. Failure is only
// logged: the index is optional and never part of the seal.
func (s *Sealer) writeIndex(dayDir, device, hour, rawPath string) {
	if _, err := os.Stat(IndexPath(dayDir, device, hour)); err == nil {
		return
	}
	f, err := os.Open(rawPath) // #nosec G304 -- validated path under data dir
	if err != nil {
		s.Log.Warn("search index", "file", rawPath, "err", err)
		return
	}
	defer f.Close()
	if _, err := WriteIndex(dayDir, device, hour, f); err != nil {
		s.Log.Warn("search index", "file", rawPath, "err", err)
	}
}

func (s *Sealer) encode(w io.Writer, rawPath string, plain bool) error {
	f, err := os.Open(rawPath) // #nosec G304 -- validated path under data dir
	if err != nil {
		return err
	}
	defer f.Close()
	return colz.EncodeStream(w, f, s.Codec, plain)
}

func (s *Sealer) roundTrips(container []byte, want [32]byte) bool {
	h := sha256.New()
	if err := colz.DecodeTo(h, container, colz.Codecs()); err != nil {
		return false
	}
	return bytes.Equal(h.Sum(nil), want[:])
}

func hashFile(p string) (sum [32]byte, size, lines int64, err error) {
	f, err := os.Open(p) // #nosec G304 -- validated path under data dir
	if err != nil {
		return sum, 0, 0, err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<20)
	for {
		n, rerr := f.Read(buf)
		h.Write(buf[:n])
		size += int64(n)
		lines += int64(bytes.Count(buf[:n], []byte{'\n'}))
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return sum, 0, 0, rerr
		}
	}
	copy(sum[:], h.Sum(nil))
	return sum, size, lines, nil
}

// writeFileSync writes atomically: temp file, fsync, rename, fsync dir.
func writeFileSync(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(dir)
}

// WriteFileSync is the exported atomic write used by other packages.
func WriteFileSync(path string, data []byte, perm os.FileMode) error {
	return writeFileSync(path, data, perm)
}

func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- directory under data dir
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

// ReadSealed decodes a sealed file and checks it against its manifest entry.
// It holds the whole hour in memory; prefer StreamSealed for large hours.
func ReadSealed(dayDir string, e HourEntry) ([]byte, error) {
	var out bytes.Buffer
	if err := StreamSealed(dayDir, e, &out); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// ErrSealedMismatch reports a sealed file that differs from its manifest entry.
var ErrSealedMismatch = errors.New("sealed file hash mismatch")

// StreamSealed decodes a sealed file into w chunk by chunk. The file's own
// SHA-256 is checked before anything is written; the decoded content's
// SHA-256 can only be checked at the end, so on ErrSealedMismatch the caller
// must discard what w received.
func StreamSealed(dayDir string, e HourEntry, w io.Writer) error {
	if !ValidDevice(e.Device) || !ValidHour(e.Hour) {
		return fmt.Errorf("invalid manifest entry %q/%q", e.Device, e.Hour)
	}
	// OpenInRoot refuses symlinks or ".." that would leave the day directory.
	f, err := os.OpenInRoot(dayDir, filepath.Join(e.Device, e.Hour+SealedExt))
	if err != nil {
		return err
	}
	defer f.Close()
	fh := sha256.New()
	n, err := io.Copy(fh, io.LimitReader(f, e.FileBytes+1))
	if err != nil {
		return err
	}
	if n != e.FileBytes || hex.EncodeToString(fh.Sum(nil)) != e.FileSHA256 {
		return fmt.Errorf("%s: %w", e.File, ErrSealedMismatch)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	// Hash the file again while decoding, so a change between the two
	// reads is caught too.
	fh.Reset()
	rh := sha256.New()
	cw := &countWriter{w: io.MultiWriter(w, rh)}
	if err := colz.DecodeReader(cw, io.TeeReader(io.LimitReader(f, e.FileBytes), fh), colz.Codecs()); err != nil {
		return err
	}
	if hex.EncodeToString(fh.Sum(nil)) != e.FileSHA256 {
		return fmt.Errorf("%s: %w", e.File, ErrSealedMismatch)
	}
	if hex.EncodeToString(rh.Sum(nil)) != e.RawSHA256 || (e.RawBytes > 0 && cw.n != e.RawBytes) {
		return fmt.Errorf("%s: decoded content: %w", e.File, ErrSealedMismatch)
	}
	return nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
