package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/config"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/store"
)

type hit struct {
	Time   time.Time
	Device string
	Label  string
	Line   string
}

const (
	maxQuery      = 200
	maxHits       = 500
	maxCSVHits    = 100000
	maxSearchDays = 366
	searchTimeout = 60 * time.Second
)

type searchReq struct {
	Tenant       *config.Tenant
	From, To     string
	HFrom, HTo   int
	Device       string
	Q            string
	Text         bool // substring mode
	Asc          bool
	qLower       []byte
	tokens       [][]byte
	labels       map[string]string
	loc          *time.Location
	stats        searchStats
	hits         []hit
	truncated    bool
	timedOut     bool
	indexSkipped int
	limit        int
}

type searchStats struct {
	Hours   int // hours looked at
	Skipped int // hours ruled out by the index
	Read    int // hours decompressed
	Elapsed time.Duration
}

func (s *Server) search(w http.ResponseWriter, r *http.Request, ss *session) {
	s.doSearch(w, r, ss, false)
}

// searchCSV downloads the hits of a search (up to maxCSVHits) as CSV.
func (s *Server) searchCSV(w http.ResponseWriter, r *http.Request, ss *session) {
	s.doSearch(w, r, ss, true)
}

func (s *Server) doSearch(w http.ResponseWriter, r *http.Request, ss *session, csvOut bool) {
	q := r.URL.Query()
	id := r.PathValue("tenant")
	if id == "" {
		id = q.Get("tenant")
	}
	tenants := s.visibleTenants(ss.user)
	data := map[string]any{"Tenants": tenants}
	var t *config.Tenant
	if id != "" {
		x, ok := s.Cfg.Tenant(id)
		if !config.IDPattern.MatchString(id) || !ok || !s.canSee(ss.user, id) {
			http.NotFound(w, r)
			return
		}
		t = x
	} else if len(tenants) == 1 {
		t = &tenants[0]
	}
	loc := s.Cfg.Location()
	today := time.Now().In(loc).Format(store.DayLayout)
	req := &searchReq{Tenant: t, From: q.Get("from"), To: q.Get("to"), Device: q.Get("device"),
		Q: strings.TrimSpace(q.Get("q")), Text: q.Get("mode") == "text", Asc: q.Get("order") == "asc", loc: loc,
		HFrom: 0, HTo: 23}
	if q.Get("day") != "" && req.From == "" { // old links
		req.From, req.To = q.Get("day"), q.Get("day")
	}
	if req.From == "" {
		req.From = today
	}
	if req.To == "" {
		req.To = req.From
		if req.From < today {
			req.To = today
		}
	}
	if v, err := strconv.Atoi(q.Get("hfrom")); err == nil && v >= 0 && v <= 23 {
		req.HFrom = v
	}
	if v, err := strconv.Atoi(q.Get("hto")); err == nil && v >= 0 && v <= 23 {
		req.HTo = v
	}
	data["Req"] = req
	data["Hours"] = hoursList()
	if t != nil {
		data["T"] = t
		data["DeviceList"] = s.deviceList(t)
	}
	render := func() { s.render(w, "search.html", s.page(r, ss, "search", data)) }
	if csvOut {
		render = func() {
			msg, _ := data["Error"].(string)
			if msg == "" {
				msg = "Arama metni girin"
			}
			http.Error(w, msg, http.StatusConflict)
		}
	}
	req.limit = maxHits
	if csvOut {
		req.limit = maxCSVHits
	}
	if req.Q == "" || t == nil {
		render()
		return
	}
	fromT, err1 := time.ParseInLocation(store.DayLayout, req.From, loc)
	toT, err2 := time.ParseInLocation(store.DayLayout, req.To, loc)
	switch {
	case len(req.Q) > maxQuery, !store.ValidDay(req.From), !store.ValidDay(req.To), err1 != nil, err2 != nil:
		data["Error"] = "Geçersiz arama"
		render()
		return
	case req.Device != "" && !store.ValidDevice(req.Device):
		data["Error"] = "Geçersiz cihaz"
		render()
		return
	case toT.Before(fromT):
		data["Error"] = "Bitiş tarihi başlangıçtan önce olamaz"
		render()
		return
	case toT.Sub(fromT) > maxSearchDays*24*time.Hour:
		data["Error"] = fmt.Sprintf("En fazla %d günlük aralıkta arama yapılabilir", maxSearchDays)
		render()
		return
	case req.HFrom > req.HTo:
		data["Error"] = "Başlangıç saati bitiş saatinden büyük olamaz"
		render()
		return
	}
	req.qLower = bytes.ToLower([]byte(req.Q))
	if !req.Text {
		req.tokens = store.QueryTokens(req.qLower)
	}
	req.labels = map[string]string{}
	s.audit(r, ss.user.Username, "search", "tenant", t.ID, "from", req.From, "to", req.To, "hours", fmt.Sprintf("%02d-%02d", req.HFrom, req.HTo),
		"device", req.Device, "mode", map[bool]string{true: "text", false: "word"}[req.Text], "query", req.Q, "csv", csvOut)
	release, ok := s.acquireHeavy(w, r, ss.user.Username)
	if !ok {
		return
	}
	defer release()
	ctx, cancel := context.WithTimeout(r.Context(), searchTimeout)
	defer cancel()
	start := time.Now()
	err := s.runSearch(ctx, req, fromT, toT)
	req.stats.Elapsed = time.Since(start).Round(time.Millisecond)
	if err != nil {
		data["Error"] = err.Error()
	}
	if req.timedOut {
		data["Error"] = "Arama zaman aşımına uğradı; bulunanlar gösteriliyor. Tarih aralığını ya da saatleri daraltın."
	}
	if csvOut {
		s.writeCSV(w, req)
		return
	}
	data["Hits"] = req.hits
	data["CSVURL"] = "/t/" + t.ID + "/search.csv?" + r.URL.RawQuery
	data["Truncated"] = req.truncated
	data["Stats"] = req.stats
	data["Searched"] = true
	render()
}

func hoursList() []string {
	out := make([]string, 24)
	for i := range out {
		out[i] = fmt.Sprintf("%02d", i)
	}
	return out
}

// deviceList returns the devices that sent logs recently or are listed in
// the last days, for the device filter.
func (s *Server) deviceList(t *config.Tenant) []devRow {
	set := map[string]bool{}
	for k := range s.Seen.get(t.ID) {
		set[k] = true
	}
	days, _ := store.ListDays(s.Cfg.DataDir, t.ID)
	for i := len(days) - 1; i >= 0 && i >= len(days)-7; i-- {
		hours, _ := store.ReadHours(store.DayDir(s.Cfg.DataDir, t.ID, days[i]))
		for _, h := range hours {
			set[h.Device] = true
		}
	}
	var out []devRow
	for k := range set {
		out = append(out, devRow{Name: k, Label: labelFor(t, k)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

type hourFile struct {
	entry  *store.HourEntry // nil for an open (not sealed) hour
	device string
	hour   string
	path   string
}

func (s *Server) runSearch(ctx context.Context, req *searchReq, fromT, toT time.Time) error {
	var days []string
	for d := fromT; !d.After(toT); d = d.AddDate(0, 0, 1) {
		days = append(days, d.Format(store.DayLayout))
	}
	if !req.Asc {
		for i, j := 0, len(days)-1; i < j; i, j = i+1, j-1 {
			days[i], days[j] = days[j], days[i]
		}
	}
	for _, day := range days {
		dir, err := store.SafeJoin(s.Cfg.DataDir, req.Tenant.ID, day)
		if err != nil {
			return err
		}
		if _, err := os.Stat(dir); err != nil { // #nosec G703 -- validated, SafeJoin
			continue
		}
		files := s.dayFiles(dir, req)
		for _, f := range files {
			if ctx.Err() != nil {
				req.timedOut = true
				return nil
			}
			if done := s.searchHour(ctx, dir, f, req); done {
				req.truncated = true
				return nil
			}
		}
	}
	return nil
}

func (s *Server) dayFiles(dir string, req *searchReq) []hourFile {
	var files []hourFile
	hours, _ := store.ReadHours(dir)
	sealed := map[string]bool{}
	for i := range hours {
		h := &hours[i]
		sealed[h.Device+"/"+h.Hour] = true
		files = append(files, hourFile{entry: h, device: h.Device, hour: h.Hour})
	}
	raws, _ := filepath.Glob(filepath.Join(dir, "*", "*"+store.RawExt))
	for _, p := range raws {
		dev := filepath.Base(filepath.Dir(p))
		hh := strings.TrimSuffix(filepath.Base(p), store.RawExt)
		if store.ValidDevice(dev) && store.ValidHour(hh) && !sealed[dev+"/"+hh] {
			files = append(files, hourFile{device: dev, hour: hh, path: filepath.Join(dev, hh+store.RawExt)})
		}
	}
	out := files[:0]
	for _, f := range files {
		h, _ := strconv.Atoi(f.hour)
		if h < req.HFrom || h > req.HTo || (req.Device != "" && f.device != req.Device) {
			continue
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].hour != out[j].hour {
			if req.Asc {
				return out[i].hour < out[j].hour
			}
			return out[i].hour > out[j].hour
		}
		return out[i].device < out[j].device
	})
	return out
}

// searchHour scans one hour; it returns true when the hit limit is reached.
// The hour is streamed (sealed hours chunk by chunk), so memory does not
// grow with the size of the hour, and at most the hits still wanted are kept.
func (s *Server) searchHour(ctx context.Context, dir string, f hourFile, req *searchReq) bool {
	req.stats.Hours++
	var src io.Reader
	var wait func() error
	if f.entry != nil {
		ix, ierr := store.ReadIndex(dir, *f.entry)
		if ierr == nil && len(req.tokens) > 0 {
			for _, tok := range req.tokens {
				if !ix.MayContain(tok) {
					req.stats.Skipped++
					return false
				}
			}
		}
		pr, pw := io.Pipe()
		done := make(chan error, 1)
		go func() {
			err := store.StreamSealed(dir, *f.entry, pw)
			pw.CloseWithError(err)
			done <- err
		}()
		defer pr.Close()
		src = pr
		wait = func() error { pr.Close(); return <-done }
	} else {
		fh, err := os.OpenInRoot(dir, f.path)
		if err != nil {
			return false
		}
		defer fh.Close()
		src = fh
	}
	req.stats.Read++
	label, ok := req.labels[f.device]
	if !ok {
		label = labelFor(req.Tenant, f.device)
		req.labels[f.device] = label
	}
	want := req.limit - len(req.hits)
	if want <= 0 {
		return true
	}
	// Ascending: the first `want` hits. Descending: the last `want` hits of
	// the hour, kept in a ring.
	ring := make([]hit, 0, min(want, 1024))
	start, total := 0, 0
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	var low []byte
	var wq *store.WordQuery
	if !req.Text {
		wq = store.NewWordQuery(req.qLower)
	}
	full := false
	for n := 0; sc.Scan(); n++ {
		if n&0xffff == 0 && ctx.Err() != nil {
			req.timedOut = true
			break
		}
		line := sc.Bytes()
		low = append(low[:0], line...)
		for i, c := range low {
			if c >= 'A' && c <= 'Z' {
				low[i] = c + 32
			}
		}
		var match bool
		if req.Text {
			match = bytes.Contains(low, req.qLower)
		} else {
			match = wq.Match(low)
		}
		if !match {
			continue
		}
		h := hit{Device: f.device, Label: label}
		ts, rest, _ := bytes.Cut(line, []byte("\t"))
		if t, err := time.Parse(store.RecordTime, string(ts)); err == nil {
			h.Time = t
		}
		if _, msg, ok := bytes.Cut(rest, []byte("\t")); ok {
			rest = msg
		}
		h.Line = string(rest)
		total++
		if len(ring) < want {
			ring = append(ring, h)
		} else if req.Asc {
			full = true
			break
		} else {
			ring[start] = h
			start = (start + 1) % want
		}
	}
	scanErr := sc.Err()
	if wait != nil {
		if err := wait(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			req.hits = append(req.hits, hit{Device: f.device, Line: "HATA: " + err.Error()})
			return false
		}
	}
	if scanErr != nil {
		req.hits = append(req.hits, hit{Device: f.device, Line: "HATA: " + scanErr.Error()})
	}
	found := append(ring[start:len(ring):len(ring)], ring[:start]...)
	if !req.Asc {
		for i, j := 0, len(found)-1; i < j; i, j = i+1, j-1 {
			found[i], found[j] = found[j], found[i]
		}
	}
	req.hits = append(req.hits, found...)
	return full || total > want || len(req.hits) >= req.limit
}

func (s *Server) writeCSV(w http.ResponseWriter, req *searchReq) {
	name := fmt.Sprintf("arama-%s-%s-%s.csv", req.Tenant.ID, req.From, req.To)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Write([]byte("\xef\xbb\xbf")) // BOM so Excel reads UTF-8
	cw := csv.NewWriter(w)
	cw.Comma = ';' // Excel in Turkish locale
	_ = cw.Write([]string{"Zaman", "Cihaz", "Cihaz adı", "Kayıt"})
	loc := s.Cfg.Location()
	for _, h := range req.hits {
		ts := ""
		if !h.Time.IsZero() {
			ts = h.Time.In(loc).Format("02.01.2006 15:04:05")
		}
		_ = cw.Write([]string{ts, csvSafe(h.Device), csvSafe(h.Label), csvSafe(h.Line)})
	}
	if req.truncated {
		_ = cw.Write([]string{"", "", "", fmt.Sprintf("(ilk %d sonuç; aramayı daraltın)", req.limit)})
	}
	cw.Flush()
}

// csvSafe keeps spreadsheet programs from running a cell as a formula.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}
