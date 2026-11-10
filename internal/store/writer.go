package store

import (
	"bufio"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Record is one received syslog message.
type Record struct {
	Received time.Time
	Source   netip.Addr
	Tenant   string
	Message  []byte
}

// Stats are exported counters.
type Stats struct {
	Records atomic.Int64
	Bytes   atomic.Int64
	Errors  atomic.Int64
}

type openFile struct {
	f    *os.File
	bw   *bufio.Writer
	path string
	hour string // "YYYY-MM-DD/HH" in local time
}

// Writer owns all open raw files. Records go through In; only the Run
// goroutine touches files, so no locking is needed.
type Writer struct {
	Root     string
	Loc      *time.Location
	Log      *slog.Logger
	In       chan Record
	Seal     func(path string) // called (asynchronously) for every closed hour
	Stats    *Stats
	LastSeen func(tenant, device string, t time.Time)

	files   map[string]*openFile
	scratch []byte
}

// NewWriter creates a writer with a buffered input channel.
func NewWriter(root string, loc *time.Location, log *slog.Logger, seal func(string)) *Writer {
	return &Writer{
		Root:  root,
		Loc:   loc,
		Log:   log,
		In:    make(chan Record, 65536),
		Seal:  seal,
		Stats: &Stats{},
		files: map[string]*openFile{},
	}
}

// Run processes records until stop is closed, then flushes and closes files
// (current-hour files stay as raw and are resumed on restart).
func (w *Writer) Run(stop <-chan struct{}) {
	flush := time.NewTicker(time.Second)
	defer flush.Stop()
	syncT := time.NewTicker(10 * time.Second)
	defer syncT.Stop()
	for {
		select {
		case r := <-w.In:
			w.write(r)
		case now := <-flush.C:
			w.flushAll(false)
			w.rotateIdle(now)
		case <-syncT.C:
			w.flushAll(true)
		case <-stop:
		drain:
			for {
				select {
				case r := <-w.In:
					w.write(r)
				default:
					break drain
				}
			}
			w.flushAll(true)
			for k, of := range w.files {
				of.f.Close()
				delete(w.files, k)
			}
			return
		}
	}
}

func (w *Writer) write(r Record) {
	device := DeviceName(r.Source)
	local := r.Received.In(w.Loc)
	hour := local.Format("2006-01-02/15")
	key := r.Tenant + "/" + device
	of := w.files[key]
	if of != nil && of.hour != hour {
		w.close(key, of)
		of = nil
	}
	if of == nil {
		var err error
		of, err = w.open(r.Tenant, device, local)
		if err != nil {
			w.Stats.Errors.Add(1)
			w.Log.Error("open raw file", "err", err)
			return
		}
		w.files[key] = of
	}
	b := w.scratch[:0]
	b = r.Received.UTC().AppendFormat(b, RecordTime)
	b = append(b, '\t')
	b = append(b, r.Source.Unmap().String()...)
	b = append(b, '\t')
	b = appendEscaped(b, r.Message)
	b = append(b, '\n')
	w.scratch = b
	if _, err := of.bw.Write(b); err != nil {
		w.Stats.Errors.Add(1)
		w.Log.Error("write raw file", "file", of.path, "err", err)
		return
	}
	w.Stats.Records.Add(1)
	w.Stats.Bytes.Add(int64(len(b)))
	if w.LastSeen != nil {
		w.LastSeen(r.Tenant, device, r.Received)
	}
}

// appendEscaped keeps each record on one line: CR, LF and NUL are escaped and
// trailing line terminators are dropped.
func appendEscaped(dst, msg []byte) []byte {
	for len(msg) > 0 && (msg[len(msg)-1] == '\n' || msg[len(msg)-1] == '\r' || msg[len(msg)-1] == 0) {
		msg = msg[:len(msg)-1]
	}
	for _, c := range msg {
		switch c {
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case 0:
			dst = append(dst, '\\', '0')
		default:
			dst = append(dst, c)
		}
	}
	return dst
}

func (w *Writer) open(tenant, device string, local time.Time) (*openFile, error) {
	day := local.Format(DayLayout)
	hh := local.Format("15")
	dir := filepath.Join(w.Root, tenant, day, device)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, hh+RawExt)
	f, err := os.OpenFile(p, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600) // #nosec G304 -- tenant/device validated
	if err != nil {
		return nil, err
	}
	// A crash may have left a torn last line; terminate it so records stay aligned.
	if st, err := f.Stat(); err == nil && st.Size() > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, st.Size()-1); err == nil && last[0] != '\n' {
			f.Write([]byte{'\n'})
		}
	}
	return &openFile{f: f, bw: bufio.NewWriterSize(f, 256*1024), path: p, hour: day + "/" + hh}, nil
}

func (w *Writer) close(key string, of *openFile) {
	if err := of.bw.Flush(); err != nil {
		w.Log.Error("flush raw file", "file", of.path, "err", err)
	}
	of.f.Sync()
	of.f.Close()
	delete(w.files, key)
	if w.Seal != nil {
		w.Seal(of.path)
	}
}

func (w *Writer) flushAll(sync bool) {
	for _, of := range w.files {
		if err := of.bw.Flush(); err != nil {
			w.Stats.Errors.Add(1)
			w.Log.Error("flush raw file", "file", of.path, "err", err)
		}
		if sync {
			of.f.Sync()
		}
	}
}

// rotateIdle closes files whose hour has passed even if no new record came.
func (w *Writer) rotateIdle(now time.Time) {
	cur := now.In(w.Loc).Format("2006-01-02/15")
	for k, of := range w.files {
		if of.hour != cur {
			w.close(k, of)
		}
	}
}

// PendingRaw lists raw files that are not the current hour; they are left over
// from a previous run and must be sealed.
func PendingRaw(root string, now time.Time, loc *time.Location) ([]string, error) {
	cur := now.In(loc)
	curDay, curHour := cur.Format(DayLayout), cur.Format("15")
	var out []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, RawExt) {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) != 4 {
			return nil
		}
		if parts[1] == curDay && strings.TrimSuffix(parts[3], RawExt) == curHour {
			return nil
		}
		out = append(out, p)
		return nil
	})
	if os.IsNotExist(err) {
		return nil, nil
	}
	return out, err
}
