package web

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/store"
)

// The monthly report is a printable statement for the customer: which days
// were stored, how much, and that each day is sealed with a time stamp.

type reportDay struct {
	daySum
	Exists   bool
	Manifest string
	TSA      string
	Future   bool
}

func (s *Server) reportPage(w http.ResponseWriter, r *http.Request, ss *session) {
	t, ok := s.tenantParam(w, r, ss)
	if !ok {
		return
	}
	loc := s.Cfg.Location()
	now := time.Now().In(loc)
	month := r.URL.Query().Get("month")
	first, err := time.ParseInLocation("2006-01", month, loc)
	if month == "" || err != nil || first.After(now) || first.Year() < 2000 {
		first = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, loc)
		if now.Day() <= 5 { // early in the month the previous one is wanted
			first = first.AddDate(0, -1, 0)
		}
	}
	today := now.Format(store.DayLayout)
	var days []reportDay
	var tot daySum
	sealed, withLogs, missing, open := 0, 0, 0, 0
	devices := map[string]bool{}
	tsa := map[string]bool{}
	for d := first; d.Month() == first.Month(); d = d.AddDate(0, 0, 1) {
		day := d.Format(store.DayLayout)
		rd := reportDay{daySum: daySum{Day: day}, Future: day > today}
		if dir, err := store.SafeJoin(s.Cfg.DataDir, t.ID, day); err == nil && !rd.Future {
			if _, err := os.Stat(dir); err == nil { // #nosec G703 -- validated, SafeJoin
				rd.Exists = true
				rd.daySum = s.daySummary(t.ID, day)
				if !rd.Sealed { // records of hours not sealed yet
					raws, _ := filepath.Glob(filepath.Join(dir, "*", "*"+store.RawExt))
					for _, p := range raws {
						rd.Lines += countLines(p)
					}
				}
				if info, err := store.ReadSealedInfo(dir); err == nil {
					rd.Manifest, rd.TSA = info.ManifestSHA256, info.TSA
					if info.TSA != "" {
						tsa[info.TSA] = true
					}
				}
				hours, _ := store.ReadHours(dir)
				for _, h := range hours {
					devices[h.Device] = true
				}
			}
		}
		switch {
		case rd.Future:
		case !rd.Exists:
			missing++
		default:
			withLogs++
			if rd.Sealed {
				sealed++
			} else {
				open++
			}
		}
		tot.Lines += rd.Lines
		tot.Raw += rd.Raw
		tot.Stored += rd.Stored + rd.Index
		days = append(days, rd)
	}
	var devs []devRow
	for d := range devices {
		devs = append(devs, devRow{Name: d, Label: labelFor(t, d)})
	}
	sort.Slice(devs, func(i, j int) bool { return devs[i].Name < devs[j].Name })
	var tsas []string
	for k := range tsa {
		tsas = append(tsas, k)
	}
	sort.Strings(tsas)
	host, _ := os.Hostname()
	s.audit(r, ss.user.Username, "report", "tenant", t.ID, "month", first.Format("2006-01"))
	s.render(w, "report.html", s.page(r, ss, "tenants", map[string]any{
		"T": t, "Month": first.Format("2006-01"), "MonthName": monthTR(first), "Days": days, "Total": tot,
		"Sealed": sealed, "WithLogs": withLogs, "Missing": missing, "OpenDays": open, "Devices": devs, "TSAs": tsas,
		"Generated": now, "Host": host, "StampMode": s.Cfg.Timestamp.Mode,
		"Prev": first.AddDate(0, -1, 0).Format("2006-01"), "Next": first.AddDate(0, 1, 0).Format("2006-01"),
		"HasNext": !first.AddDate(0, 1, 0).After(now),
	}))
}

func monthTR(t time.Time) string {
	names := [...]string{"Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran", "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık"}
	return names[t.Month()-1] + " " + t.Format("2006")
}
