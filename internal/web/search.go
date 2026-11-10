package web

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
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
}

type searchStats struct {
	Hours   int // hours looked at
	Skipped int // hours ruled out by the index
	Read    int // hours decompressed
	Elapsed time.Duration
}

func (s *Server) search(w http.ResponseWriter, r *http.Request, ss *session) {
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
		"device", req.Device, "mode", map[bool]string{true: "text", false: "word"}[req.Text], "query", req.Q)
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
	data["Hits"] = req.hits
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
			if done := s.searchHour(dir, f, req); done {
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
func (s *Server) searchHour(dir string, f hourFile, req *searchReq) bool {
	req.stats.Hours++
	var raw []byte
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
		b, err := store.ReadSealed(dir, *f.entry)
		if err != nil {
			req.hits = append(req.hits, hit{Device: f.device, Line: "HATA: " + err.Error()})
			return false
		}
		raw = b
		if ierr != nil { // build a missing index on the way
			_, _ = store.WriteIndex(dir, f.device, f.hour, bytes.NewReader(raw))
			s.sums.forget(dir)
		}
	} else {
		b, err := readLimited(dir, f.path, 2<<30)
		if err != nil {
			return false
		}
		raw = b
	}
	req.stats.Read++
	label, ok := req.labels[f.device]
	if !ok {
		label = labelFor(req.Tenant, f.device)
		req.labels[f.device] = label
	}
	var found []hit
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	var low []byte
	var wq *store.WordQuery
	if !req.Text {
		wq = store.NewWordQuery(req.qLower)
	}
	for sc.Scan() {
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
		found = append(found, h)
	}
	if !req.Asc {
		for i, j := 0, len(found)-1; i < j; i, j = i+1, j-1 {
			found[i], found[j] = found[j], found[i]
		}
	}
	for _, h := range found {
		req.hits = append(req.hits, h)
		if len(req.hits) >= maxHits {
			return true
		}
	}
	return false
}
