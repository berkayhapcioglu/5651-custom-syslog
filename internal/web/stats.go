package web

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/config"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/store"
)

// LastSeen tracks the latest record per tenant/device and counts records per
// hour for the charts of the current, not yet sealed hours.
type LastSeen struct {
	mu     sync.Mutex
	m      map[string]map[string]time.Time
	counts map[string]map[int64]int64 // tenant -> hour start (unix) -> records
}

// NewLastSeen creates an empty tracker.
func NewLastSeen() *LastSeen {
	return &LastSeen{m: map[string]map[string]time.Time{}, counts: map[string]map[int64]int64{}}
}

// Mark records t for tenant/device.
func (l *LastSeen) Mark(tenant, device string, t time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	d := l.m[tenant]
	if d == nil {
		d = map[string]time.Time{}
		l.m[tenant] = d
	}
	d[device] = t
	c := l.counts[tenant]
	if c == nil {
		c = map[int64]int64{}
		l.counts[tenant] = c
	}
	h := t.Truncate(time.Hour).Unix()
	if _, ok := c[h]; !ok {
		for k := range c {
			if k < h-48*3600 {
				delete(c, k)
			}
		}
	}
	c[h]++
}

// Seed fills the tracker from disk after a restart: the latest record time
// per device from today's and yesterday's files, and record counts of the
// hours that are not sealed yet.
func (l *LastSeen) Seed(root string, tenants []string, loc *time.Location, now time.Time) {
	for _, t := range tenants {
		for _, day := range []time.Time{now.AddDate(0, 0, -1), now} {
			dir, err := store.SafeJoin(root, t, day.In(loc).Format(store.DayLayout))
			if err != nil {
				continue
			}
			hours, _ := store.ReadHours(dir)
			for _, h := range hours {
				if start, err := time.ParseInLocation(store.DayLayout+" 15", filepath.Base(dir)+" "+h.Hour, loc); err == nil {
					end := start.Add(time.Hour - time.Second)
					if end.After(now) {
						end = now
					}
					l.seen(t, h.Device, end)
				}
			}
			raws, _ := filepath.Glob(filepath.Join(dir, "*", "*"+store.RawExt))
			for _, p := range raws {
				dev, hh := filepath.Base(filepath.Dir(p)), strings.TrimSuffix(filepath.Base(p), store.RawExt)
				st, err := os.Stat(p) // #nosec G703 -- under data_dir, names from Glob
				if err != nil || !store.ValidDevice(dev) || !store.ValidHour(hh) {
					continue
				}
				l.seen(t, dev, st.ModTime())
				start, err := time.ParseInLocation(store.DayLayout+" 15", filepath.Base(dir)+" "+hh, loc)
				if err != nil {
					continue
				}
				if n := countLines(p); n > 0 {
					l.mu.Lock()
					c := l.counts[t]
					if c == nil {
						c = map[int64]int64{}
						l.counts[t] = c
					}
					c[start.Truncate(time.Hour).Unix()] += n
					l.mu.Unlock()
				}
			}
		}
	}
}

// seen sets the time for tenant/device if it is later than the known one.
func (l *LastSeen) seen(tenant, device string, t time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	d := l.m[tenant]
	if d == nil {
		d = map[string]time.Time{}
		l.m[tenant] = d
	}
	if t.After(d[device]) {
		d[device] = t
	}
}

func countLines(p string) int64 {
	f, err := os.Open(p) // #nosec G304 -- under data_dir, names from Glob
	if err != nil {
		return 0
	}
	defer f.Close()
	var n int64
	buf := make([]byte, 256*1024)
	for {
		k, err := f.Read(buf)
		n += int64(bytes.Count(buf[:k], []byte{'\n'}))
		if err != nil {
			return n
		}
	}
}

func (l *LastSeen) get(tenant string) map[string]time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]time.Time{}
	for k, v := range l.m[tenant] {
		out[k] = v
	}
	return out
}

func (l *LastSeen) count(tenant string, hourStart time.Time) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.counts[tenant][hourStart.Truncate(time.Hour).Unix()]
}

// ---- per day summaries ----

// daySum summarizes one tenant day. Sealed days never change, so their
// summaries are cached.
type daySum struct {
	Day       string
	Sealed    bool
	StampTime string
	Files     int
	Lines     int64
	Raw       int64
	Stored    int64 // sealed files
	Index     int64 // search index files
	Open      int64 // raw files of hours not sealed yet
	Hours     map[string]int64
}

// Disk is everything the day occupies.
func (d daySum) Disk() int64 { return d.Stored + d.Index + d.Open }

type sumCache struct {
	mu sync.Mutex
	m  map[string]daySum
}

func newSumCache() *sumCache { return &sumCache{m: map[string]daySum{}} }

func (c *sumCache) forget(dir string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, dir)
}

func (s *Server) daySummary(tenant, day string) daySum {
	dir := store.DayDir(s.Cfg.DataDir, tenant, day)
	s.sums.mu.Lock()
	if v, ok := s.sums.m[dir]; ok {
		s.sums.mu.Unlock()
		return v
	}
	s.sums.mu.Unlock()
	d := daySum{Day: day, Sealed: store.IsSealed(dir), Hours: map[string]int64{}}
	if info, err := store.ReadSealedInfo(dir); err == nil {
		d.StampTime = info.StampTime
	}
	hours, _ := store.ReadHours(dir)
	for _, h := range hours {
		d.Files++
		d.Lines += h.Lines
		d.Raw += h.RawBytes
		d.Stored += h.FileBytes
		d.Hours[h.Hour] += h.Lines
		if st, err := os.Stat(store.IndexPath(dir, h.Device, h.Hour)); err == nil { // #nosec G703 -- validated entry
			d.Index += st.Size()
		}
	}
	if !d.Sealed {
		raws, _ := filepath.Glob(filepath.Join(dir, "*", "*"+store.RawExt))
		for _, p := range raws {
			if st, err := os.Stat(p); err == nil {
				d.Open += st.Size()
				d.Raw += st.Size()
			}
		}
	}
	if d.Sealed {
		s.sums.mu.Lock()
		if len(s.sums.m) > 200000 {
			s.sums.m = map[string]daySum{}
		}
		s.sums.m[dir] = d
		s.sums.mu.Unlock()
	}
	return d
}

// tenantUsage sums all days of a tenant.
type tenantUsage struct {
	Days       int
	Raw, Disk  int64
	Lines      int64
	LastSealed string
	StampTime  string
	OldestOpen string // a finished day that is still not sealed
}

func (s *Server) usage(t string, today string) tenantUsage {
	days, _ := store.ListDays(s.Cfg.DataDir, t)
	var u tenantUsage
	for _, day := range days {
		d := s.daySummary(t, day)
		u.Days++
		u.Raw += d.Raw
		u.Disk += d.Disk()
		u.Lines += d.Lines
		if d.Sealed {
			u.LastSealed, u.StampTime = day, d.StampTime
		} else if day < today && u.OldestOpen == "" {
			u.OldestOpen = day
		}
	}
	return u
}

// hourly returns record counts for the last n hours (oldest first) of the
// given tenants: sealed hours from hours.jsonl, open hours from live counts.
func (s *Server) hourly(tenants []string, now time.Time, n int) ([]int64, []time.Time) {
	loc := s.Cfg.Location()
	end := now.In(loc).Truncate(time.Hour)
	vals := make([]int64, n)
	slots := make([]time.Time, n)
	for i := 0; i < n; i++ {
		slots[i] = end.Add(-time.Duration(n-1-i) * time.Hour)
	}
	for _, t := range tenants {
		cache := map[string]daySum{}
		for i, sl := range slots {
			day := sl.Format(store.DayLayout)
			d, ok := cache[day]
			if !ok {
				d = s.daySummary(t, day)
				cache[day] = d
			}
			vals[i] += max(d.Hours[sl.Format("15")], s.Seen.count(t, sl))
		}
	}
	return vals, slots
}

// daily returns record counts for the last n days (oldest first).
func (s *Server) daily(tenants []string, now time.Time, n int) ([]int64, []time.Time) {
	loc := s.Cfg.Location()
	y, m, d := now.In(loc).Date()
	today := time.Date(y, m, d, 0, 0, 0, 0, loc)
	vals := make([]int64, n)
	days := make([]time.Time, n)
	for i := 0; i < n; i++ {
		days[i] = today.AddDate(0, 0, -(n - 1 - i))
	}
	hv, hs := s.hourly(tenants, now, 24)
	for _, t := range tenants {
		for i, day := range days[:n-1] {
			vals[i] += s.daySummary(t, day.Format(store.DayLayout)).Lines
		}
	}
	for i, h := range hs { // today: sealed + live
		if h.Format(store.DayLayout) == today.Format(store.DayLayout) {
			vals[n-1] += hv[i]
		}
	}
	return vals, days
}

// ---- charts: server rendered SVG, no JavaScript ----

type chartBar struct {
	X, Y, W, H float64
	Title      string
}

type chartLabel struct {
	X    float64
	Text string
}

type chart struct {
	W, H   float64
	Bars   []chartBar
	Labels []chartLabel
	Grid   []float64
	Max    int64
	Total  int64
	Aria   string
}

func barChart(vals []int64, label func(i int) string, title func(i int, v int64) string, every int, aria string) chart {
	const width, plotH, top = 600.0, 130.0, 20.0
	step := width / float64(max(len(vals), 1))
	c := chart{W: width, H: 172, Aria: aria}
	for _, v := range vals {
		c.Max = max(c.Max, v)
		c.Total += v
	}
	scale := 0.0
	if c.Max > 0 {
		scale = plotH / float64(c.Max)
	}
	c.Grid = []float64{top, top + plotH/3, top + 2*plotH/3}
	for i, v := range vals {
		h := float64(v) * scale
		if v > 0 && h < 2 {
			h = 2
		}
		gap := step * 0.2
		c.Bars = append(c.Bars, chartBar{X: float64(i)*step + gap/2, Y: top + plotH - h, W: step - gap, H: h, Title: title(i, v)})
		if i%every == 0 {
			c.Labels = append(c.Labels, chartLabel{X: float64(i)*step + step/2, Text: label(i)})
		}
	}
	return c
}

func hourChart(vals []int64, slots []time.Time, aria string) chart {
	return barChart(vals, func(i int) string { return slots[i].Format("15") },
		func(i int, v int64) string { return slots[i].Format("02.01 15:00") + " · " + thousands(v) + " kayıt" }, 3, aria)
}

func dayChart(vals []int64, days []time.Time, aria string) chart {
	return barChart(vals, func(i int) string { return days[i].Format("02.01") },
		func(i int, v int64) string { return days[i].Format("02.01.2006") + " · " + thousands(v) + " kayıt" }, 5, aria)
}

// ---- formatting ----

func thousands(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte('.')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func agoTR(t time.Time) string {
	if t.IsZero() {
		return "hiç"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "az önce"
	case d < time.Hour:
		return fmt.Sprintf("%d dk önce", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d sa önce", int(d.Hours()))
	default:
		return fmt.Sprintf("%d gün önce", int(d.Hours()/24))
	}
}

func durTR(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d dk", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d sa", int(d.Hours()))
	default:
		return fmt.Sprintf("%d gün", int(d.Hours()/24))
	}
}

func (s *Server) funcs() template.FuncMap {
	loc := s.Cfg.Location()
	return template.FuncMap{
		"ratio": func(raw, file int64) string {
			if file == 0 {
				return "-"
			}
			return strings.Replace(fmt.Sprintf("%.1fx", float64(raw)/float64(file)), ".", ",", 1)
		},
		"bytes":     humanBytes,
		"thousands": thousands,
		"ago":       agoTR,
		"localtime": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.In(loc).Format("02.01.2006 15:04:05")
		},
		"stamp": func(s string) string { // RFC 3339 -> local
			t, err := time.Parse(time.RFC3339Nano, s)
			if err != nil {
				return s
			}
			return t.In(loc).Format("02.01.2006 15:04")
		},
		"daytr": func(s string) string {
			t, err := time.Parse(store.DayLayout, s)
			if err != nil {
				return s
			}
			return t.Format("02.01.2006")
		},
		"initial": func(s string) string {
			if s == "" {
				return "?"
			}
			return strings.ToUpper(s[:1])
		},
		"rolename": func(r string) string {
			if r == RoleAdmin {
				return "Yönetici"
			}
			return "Müşteri kullanıcısı"
		},
		"has": func(list []string, v string) bool {
			for _, x := range list {
				if x == v {
					return true
				}
			}
			return false
		},
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
		"mclass": func(p float64) string { // meter width class, 5% steps
			n := int(p/5+0.5) * 5
			return fmt.Sprintf("m%d", min(max(n, 0), 100))
		},
		"join":  strings.Join,
		"level": level,
		"pct":   func(f float64) string { return fmt.Sprintf("%.0f", f) },
		"dec2":  func(f float64) string { return strings.Replace(fmt.Sprintf("%.2f", f), ".", ",", 1) },
		"dur":   durTR,
		"since": func(t time.Time) string { return durTR(time.Since(t)) },
		"days":  func(d time.Duration) int { return int(d.Hours() / 24) },
		"sortlink": func(cur, key string) string {
			if cur == key {
				return "-" + key
			}
			return key
		},
		"ariasort": func(cur, key string) string {
			switch cur {
			case key:
				return "ascending"
			case "-" + key:
				return "descending"
			}
			return ""
		},
	}
}

// ---- license ----

type license struct {
	Set   bool
	Until string
	Days  int // days left; negative when expired
	Class string
	Text  string
}

func (s *Server) licenseOf(t config.Tenant, now time.Time) license {
	if t.LicenseUntil == "" {
		return license{Text: "Tanımsız", Class: ""}
	}
	loc := s.Cfg.Location()
	until, err := time.ParseInLocation(store.DayLayout, t.LicenseUntil, loc)
	if err != nil {
		return license{Text: "Hatalı tarih", Class: "err"}
	}
	y, m, d := now.In(loc).Date()
	today := time.Date(y, m, d, 0, 0, 0, 0, loc)
	days := int(until.Sub(today).Hours()/24 + 0.5)
	l := license{Set: true, Until: t.LicenseUntil, Days: days}
	switch {
	case days < 0:
		l.Class, l.Text = "err", fmt.Sprintf("%d gün önce bitti", -days)
	case days <= s.Cfg.LicenseWarnDays():
		l.Class, l.Text = "warn", fmt.Sprintf("%d gün", days)
	default:
		l.Class, l.Text = "ok", fmt.Sprintf("%d gün", days)
	}
	return l
}

// ---- dashboard and tenant pages ----

type tenantRow struct {
	T          config.Tenant
	Devices    int
	LastSeen   time.Time
	Usage      tenantUsage
	License    license
	Problem    string
	Level      string // ok, warn, err
	Today      int64
	Spark      chart
	levelOrder int
}

func (s *Server) tenantRows(u User, now time.Time) []tenantRow {
	today := now.In(s.Cfg.Location()).Format(store.DayLayout)
	var rows []tenantRow
	for _, t := range s.visibleTenants(u) {
		row := tenantRow{T: t, License: s.licenseOf(t, now), Level: "ok"}
		seen := s.Seen.get(t.ID)
		row.Devices = len(seen)
		for _, v := range seen {
			if v.After(row.LastSeen) {
				row.LastSeen = v
			}
		}
		row.Usage = s.usage(t.ID, today)
		var problems []string
		lvl := 0
		raise := func(l int, msg string) {
			problems = append(problems, msg)
			lvl = max(lvl, l)
		}
		if row.Usage.OldestOpen != "" && s.dayOverdue(row.Usage.OldestOpen, now) {
			raise(2, "Mühür bekliyor: "+row.Usage.OldestOpen)
		}
		switch {
		case row.LastSeen.IsZero():
			raise(1, "Servis açıldığından beri log yok")
		case now.Sub(row.LastSeen) > time.Hour:
			raise(1, durTR(now.Sub(row.LastSeen))+"dir log yok")
		}
		if row.License.Class == "err" {
			raise(2, "Lisans bitti")
		} else if row.License.Class == "warn" {
			raise(1, "Lisans bitiyor")
		}
		row.levelOrder = lvl
		row.Level = []string{"ok", "warn", "err"}[lvl]
		if len(problems) == 0 {
			row.Problem = "Normal"
		} else {
			row.Problem = strings.Join(problems, " · ")
		}
		hv, hs := s.hourly([]string{t.ID}, now, 24)
		for i, h := range hs {
			if h.Format(store.DayLayout) == today {
				row.Today += hv[i]
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// dayOverdue reports whether day should have been sealed by now (day end +
// grace + one hour of retries).
func (s *Server) dayOverdue(day string, now time.Time) bool {
	t, err := time.ParseInLocation(store.DayLayout, day, s.Cfg.Location())
	if err != nil {
		return false
	}
	return now.After(t.AddDate(0, 0, 1).Add(s.Cfg.DayGrace.Duration + time.Hour))
}

func sortRows(rows []tenantRow, key string) {
	desc := strings.HasPrefix(key, "-")
	key = strings.TrimPrefix(key, "-")
	less := func(a, b tenantRow) bool {
		switch key {
		case "name":
			return strings.ToLower(a.T.Name) < strings.ToLower(b.T.Name)
		case "last":
			return a.LastSeen.Before(b.LastSeen)
		case "disk":
			return a.Usage.Disk < b.Usage.Disk
		case "today":
			return a.Today < b.Today
		case "license":
			ad, bd := a.License.Days, b.License.Days
			if !a.License.Set {
				ad = 1 << 30
			}
			if !b.License.Set {
				bd = 1 << 30
			}
			return ad < bd
		default: // status: problems first
			if a.levelOrder != b.levelOrder {
				return a.levelOrder > b.levelOrder
			}
			return a.T.ID < b.T.ID
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if desc {
			return less(rows[j], rows[i])
		}
		return less(rows[i], rows[j])
	})
}

var sortKeys = map[string]bool{"name": true, "last": true, "disk": true, "today": true, "license": true, "status": true}

func sortParam(r *http.Request, def string) string {
	v := r.URL.Query().Get("sort")
	if sortKeys[strings.TrimPrefix(v, "-")] {
		return v
	}
	return def
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, ss *session) {
	now := time.Now()
	rows := s.tenantRows(ss.user, now)
	sortKey := sortParam(r, "status")
	sortRows(rows, sortKey)
	var ids []string
	var disk, raw, today int64
	devices, sealedYesterday, withYesterday, problems := 0, 0, 0, 0
	yesterday := now.In(s.Cfg.Location()).AddDate(0, 0, -1).Format(store.DayLayout)
	lastSealed, lastStamp := "", ""
	var alerts []string
	for _, row := range rows {
		ids = append(ids, row.T.ID)
		disk += row.Usage.Disk
		raw += row.Usage.Raw
		today += row.Today
		devices += row.Devices
		if dir, err := store.SafeJoin(s.Cfg.DataDir, row.T.ID, yesterday); err == nil {
			if _, err := os.Stat(dir); err == nil { // #nosec G703 -- validated, SafeJoin
				withYesterday++
				if row.Usage.LastSealed >= yesterday {
					sealedYesterday++
				}
			}
		}
		if row.Usage.LastSealed > lastSealed {
			lastSealed, lastStamp = row.Usage.LastSealed, row.Usage.StampTime
		}
		if row.Level != "ok" {
			problems++
			alerts = append(alerts, row.T.Name+": "+row.Problem)
		}
	}
	hv, hs := s.hourly(ids, now, 24)
	dv, ds := s.daily(ids, now, 30)
	data := map[string]any{
		"Rows": rows, "Sort": sortKey, "Now": now,
		"Today": today, "Disk": disk, "Raw": raw, "Devices": devices,
		"LastSealed": lastSealed, "LastStamp": lastStamp, "SealedYesterday": sealedYesterday, "WithYesterday": withYesterday,
		"Problems": problems, "Alerts": alerts,
		"Hourly": hourChart(hv, hs, "Son 24 saatte saatlik kayıt sayısı"),
		"Daily":  dayChart(dv, ds, "Son 30 günde günlük kayıt sayısı"),
	}
	if ss.user.Role == RoleAdmin {
		data["Status"] = s.status(now)
	}
	s.render(w, "dashboard.html", s.page(r, ss, "home", data))
}

func (s *Server) tenantsPage(w http.ResponseWriter, r *http.Request, ss *session) {
	now := time.Now()
	rows := s.tenantRows(ss.user, now)
	sortKey := sortParam(r, "name")
	sortRows(rows, sortKey)
	s.render(w, "tenants.html", s.page(r, ss, "tenants", map[string]any{"Rows": rows, "Sort": sortKey}))
}

// deviceLabels maps device directory names to the labels of their sources.
func deviceLabels(t *config.Tenant, hours []store.HourEntry) map[string]string {
	out := map[string]string{}
	for _, h := range hours {
		if _, ok := out[h.Device]; !ok {
			out[h.Device] = labelFor(t, h.Device)
		}
	}
	return out
}

func labelFor(t *config.Tenant, device string) string {
	a, err := netip.ParseAddr(strings.ReplaceAll(device, "_", ":"))
	if err != nil {
		return ""
	}
	for _, si := range t.SourceList {
		if si.Prefix.Contains(a) && si.Label != "" {
			return si.Label
		}
	}
	return ""
}

type devRow struct {
	Name, Label string
	Last        time.Time
	Active      bool
}

const daysPerPage = 31

func (s *Server) tenantPage(w http.ResponseWriter, r *http.Request, ss *session) {
	t, ok := s.tenantParam(w, r, ss)
	if !ok {
		return
	}
	now := time.Now()
	q := r.URL.Query()
	from, to, status := q.Get("from"), q.Get("to"), q.Get("status")
	if status != "sealed" && status != "open" {
		status = ""
	}
	if from != "" && !store.ValidDay(from) {
		from = ""
	}
	if to != "" && !store.ValidDay(to) {
		to = ""
	}
	order := "desc"
	if q.Get("order") == "asc" {
		order = "asc"
	}
	pageNo, _ := strconv.Atoi(q.Get("page"))
	pageNo = max(pageNo, 1)

	days, _ := store.ListDays(s.Cfg.DataDir, t.ID)
	var rows []daySum
	for _, d := range days {
		if (from != "" && d < from) || (to != "" && d > to) {
			continue
		}
		sum := s.daySummary(t.ID, d)
		if (status == "sealed" && !sum.Sealed) || (status == "open" && sum.Sealed) {
			continue
		}
		rows = append(rows, sum)
	}
	if order == "desc" {
		for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
			rows[i], rows[j] = rows[j], rows[i]
		}
	}
	total := len(rows)
	pages := max((total+daysPerPage-1)/daysPerPage, 1)
	pageNo = min(pageNo, pages)
	rows = rows[min((pageNo-1)*daysPerPage, total):min(pageNo*daysPerPage, total)]

	var devs []devRow
	for k, v := range s.Seen.get(t.ID) {
		devs = append(devs, devRow{Name: k, Label: labelFor(t, k), Last: v, Active: now.Sub(v) < time.Hour})
	}
	sort.Slice(devs, func(i, j int) bool { return devs[i].Name < devs[j].Name })

	today := now.In(s.Cfg.Location()).Format(store.DayLayout)
	hv, hs := s.hourly([]string{t.ID}, now, 24)
	dv, ds := s.daily([]string{t.ID}, now, 30)
	var todayLines int64
	for i, h := range hs {
		if h.Format(store.DayLayout) == today {
			todayLines += hv[i]
		}
	}
	base := fmt.Sprintf("/t/%s?from=%s&to=%s&status=%s&order=%s", t.ID, from, to, status, order)
	flip := "asc"
	if order == "asc" {
		flip = "desc"
	}
	s.render(w, "tenant.html", s.page(r, ss, "tenants", map[string]any{
		"T": t, "Days": rows, "Devices": devs, "Usage": s.usage(t.ID, today), "License": s.licenseOf(*t, now),
		"From": from, "To": to, "Status": status, "Order": order, "Page": pageNo, "Pages": pages, "TotalDays": total,
		"PrevURL": fmt.Sprintf("%s&page=%d", base, pageNo-1), "NextURL": fmt.Sprintf("%s&page=%d", base, pageNo+1),
		"FlipURL":    fmt.Sprintf("/t/%s?from=%s&to=%s&status=%s&order=%s", t.ID, from, to, status, flip),
		"TodayLines": todayLines,
		"Hourly":     hourChart(hv, hs, "Son 24 saatte saatlik kayıt sayısı"),
		"Daily":      dayChart(dv, ds, "Son 30 günde günlük kayıt sayısı"),
	}))
}
