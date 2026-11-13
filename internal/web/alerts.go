package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/config"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/notify"
)

// Alerts watch the service and mail the panel's alert recipients when a
// problem starts, as a reminder while it lasts, and when it is resolved.

// alert is one active problem.
type alert struct {
	Key      string    `json:"key"`
	Level    string    `json:"level"` // warn or err
	Title    string    `json:"title"`
	Since    time.Time `json:"since"`
	Seen     int       `json:"seen"` // consecutive checks it was present
	LastSent time.Time `json:"last_sent,omitzero"`
	LastTry  time.Time `json:"last_try,omitzero"`
	remind   time.Duration
}

type alertEvent struct {
	Time   time.Time
	Kind   string // Yeni, Sürüyor, Düzeldi, Test
	Title  string
	Result string
}

type alerter struct {
	mu      sync.Mutex
	active  map[string]*alert
	history []alertEvent
	prevErr int64
	errAt   time.Time
}

func (s *Server) alertsPath() string {
	return filepath.Join(s.Cfg.DataDir, config.PanelDir, "alerts.json")
}

// loadAlerts restores active alerts so a restart does not mail them again.
func (s *Server) loadAlerts() {
	s.alerts.active = map[string]*alert{}
	b, err := os.ReadFile(s.alertsPath())
	if err != nil {
		return
	}
	var list []*alert
	if json.Unmarshal(b, &list) == nil {
		for _, a := range list {
			if a != nil && a.Key != "" {
				s.alerts.active[a.Key] = a
			}
		}
	}
}

func (s *Server) saveAlerts() {
	list := make([]*alert, 0, len(s.alerts.active))
	for _, a := range s.alerts.active {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Key < list[j].Key })
	b, _ := json.MarshalIndent(list, "", "  ")
	_ = os.MkdirAll(filepath.Dir(s.alertsPath()), 0o700)
	tmp := s.alertsPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil { // #nosec G306 G703 -- under data_dir
		_ = os.Rename(tmp, s.alertsPath())
	}
}

// conditions returns the problems present now. keep lists keys whose state
// cannot be judged now (for example no data after a restart) and must not be
// resolved.
func (s *Server) conditions(now time.Time) (cur map[string]*alert, keep map[string]bool) {
	cur, keep = map[string]*alert{}, map[string]bool{}
	add := func(key, level, title string, remind time.Duration) {
		cur[key] = &alert{Key: key, Level: level, Title: title, remind: remind}
	}
	silent := time.Duration(s.Cfg.SilentHours()) * time.Hour
	for _, row := range s.tenantRows(User{Role: RoleAdmin}, now) {
		t := row.T
		switch {
		case row.LastSeen.IsZero():
			keep["silent:"+t.ID] = true
		case now.Sub(row.LastSeen) > silent:
			add("silent:"+t.ID, "err", fmt.Sprintf("%s: %s boyunca log gelmedi (son log %s)", t.Name, durTR(now.Sub(row.LastSeen)),
				row.LastSeen.In(s.Cfg.Location()).Format("02.01.2006 15:04")), 24*time.Hour)
		}
		if row.Usage.OldestOpen != "" && s.dayOverdue(row.Usage.OldestOpen, now) {
			add("seal:"+t.ID, "err", fmt.Sprintf("%s: %s günü mühürlenemedi (zaman damgası alınamıyor olabilir)", t.Name, dayTR(row.Usage.OldestOpen)), 24*time.Hour)
		}
		if l := row.License; l.Set && l.Class != "ok" {
			title := fmt.Sprintf("%s: lisans %d gün sonra bitiyor (%s)", t.Name, l.Days, dayTR(l.Until))
			if l.Days < 0 {
				title = fmt.Sprintf("%s: lisans %d gün önce bitti (%s); loglar saklanmaya devam ediyor", t.Name, -l.Days, dayTR(l.Until))
			}
			add("license:"+t.ID, "warn", title, 7*24*time.Hour)
		}
	}
	st := s.status(now)
	if st.DiskTotal > 0 && float64(st.DiskFree)/float64(st.DiskTotal) < 0.1 {
		add("disk", "err", fmt.Sprintf("Veri diskinde yer azaldı: %s boş (%%%.0f dolu)", humanBytes(st.DiskFree), st.DiskUsedPercent()), 24*time.Hour)
	}
	certs := append([]certStatus(nil), st.Certs...)
	if st.StampCert != nil {
		certs = append(certs, *st.StampCert)
	}
	for _, c := range certs {
		end := c.NotAfter.In(s.Cfg.Location()).Format("02.01.2006")
		switch {
		case c.Err != "":
		case c.NotAfter.Before(now):
			add("cert:"+c.Name, "err", fmt.Sprintf("%s sertifikasının süresi doldu (%s)", c.Name, end), 24*time.Hour)
		case c.Days < 30:
			add("cert:"+c.Name, "warn", fmt.Sprintf("%s sertifikası %d gün içinde bitiyor (%s)", c.Name, c.Days, end), 7*24*time.Hour)
		}
	}
	if st.Stats != nil {
		e := st.Stats["Yazma hatası"]
		s.alerts.mu.Lock()
		if e > s.alerts.prevErr {
			s.alerts.errAt = now
		}
		s.alerts.prevErr = e
		recent := !s.alerts.errAt.IsZero() && now.Sub(s.alerts.errAt) < 15*time.Minute
		s.alerts.mu.Unlock()
		if recent {
			add("write", "err", "Log dosyalarına yazılamıyor (disk dolu ya da izin sorunu olabilir); servis kayıtlarına bakın", 24*time.Hour)
		}
	}
	return cur, keep
}

// checkAlerts compares the problems with the active ones and mails changes.
// A problem must be present in two checks in a row before it is mailed.
func (s *Server) checkAlerts(ctx context.Context, now time.Time) {
	cur, keep := s.conditions(now)
	var started, ongoing, resolved []*alert
	s.alerts.mu.Lock()
	for k, c := range cur {
		a := s.alerts.active[k]
		if a == nil {
			c.Since, c.Seen = now, 1
			s.alerts.active[k] = c
			continue
		}
		a.Title, a.Level, a.remind = c.Title, c.Level, c.remind
		a.Seen++
		switch {
		case a.LastSent.IsZero() && a.Seen >= 2 && now.Sub(a.LastTry) >= 15*time.Minute:
			started = append(started, a)
		case !a.LastSent.IsZero() && a.remind > 0 && now.Sub(a.LastSent) >= a.remind && now.Sub(a.LastTry) >= 15*time.Minute:
			ongoing = append(ongoing, a)
		}
	}
	for k, a := range s.alerts.active {
		if cur[k] == nil && !keep[k] {
			delete(s.alerts.active, k)
			if !a.LastSent.IsZero() {
				resolved = append(resolved, a)
			}
		}
	}
	s.alerts.mu.Unlock()

	if len(started)+len(ongoing)+len(resolved) > 0 {
		subject, body := s.alertMail(started, ongoing, resolved, now)
		err := s.sendAlertMail(ctx, subject, body)
		res := "gönderildi"
		if err != nil {
			res = "gönderilemedi: " + err.Error()
			s.Log.Warn("alert mail", "err", err)
		}
		s.alerts.mu.Lock()
		for _, a := range append(started, ongoing...) {
			a.LastTry = now
			if err == nil || !s.mailReady() {
				a.LastSent = now // without a mail server the panel still shows it once
			}
		}
		for _, x := range []struct {
			kind string
			l    []*alert
		}{{"Yeni", started}, {"Sürüyor", ongoing}, {"Düzeldi", resolved}} {
			for _, a := range x.l {
				s.alerts.history = append(s.alerts.history, alertEvent{Time: now, Kind: x.kind, Title: a.Title, Result: res})
			}
		}
		if n := len(s.alerts.history); n > 100 {
			s.alerts.history = s.alerts.history[n-100:]
		}
		s.alerts.mu.Unlock()
		s.auditSystem("alert", "new", len(started), "ongoing", len(ongoing), "resolved", len(resolved), "mail", res)
	}
	s.alerts.mu.Lock()
	s.saveAlerts()
	s.alerts.mu.Unlock()
}

func (s *Server) mailReady() bool {
	return s.Mailer.Enabled() && len(s.Cfg.PanelCopy().Settings.AlertEmails) > 0
}

func (s *Server) sendAlertMail(ctx context.Context, subject, body string) error {
	if !s.mailReady() {
		return fmt.Errorf("e-posta ayarlı değil")
	}
	return s.Mailer.Send(ctx, s.Cfg.PanelCopy().Settings.AlertEmails, subject, body)
}

func (s *Server) alertMail(started, ongoing, resolved []*alert, now time.Time) (string, string) {
	host, _ := os.Hostname()
	var b strings.Builder
	section := func(head string, l []*alert, since bool) {
		if len(l) == 0 {
			return
		}
		b.WriteString(head + "\n")
		for _, a := range l {
			b.WriteString("  - " + a.Title)
			if since {
				b.WriteString(" (başlangıç " + a.Since.In(s.Cfg.Location()).Format("02.01.2006 15:04") + ")")
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	section("YENİ SORUNLAR:", started, false)
	section("DEVAM EDEN SORUNLAR:", ongoing, true)
	section("DÜZELENLER:", resolved, false)
	fmt.Fprintf(&b, "Sunucu: %s\nZaman: %s\n\nBu e-posta 5651 Log servisi tarafından otomatik gönderildi. Alıcılar panelde Ayarlar sayfasından değiştirilir.\n",
		host, now.In(s.Cfg.Location()).Format("02.01.2006 15:04"))
	var subject string
	switch {
	case len(started) > 0:
		subject = fmt.Sprintf("[5651 Log] %d yeni sorun: %s", len(started), started[0].Title)
	case len(ongoing) > 0:
		subject = fmt.Sprintf("[5651 Log] %d sorun devam ediyor", len(ongoing))
	default:
		subject = fmt.Sprintf("[5651 Log] %d sorun düzeldi", len(resolved))
	}
	if len([]rune(subject)) > 150 {
		subject = string([]rune(subject)[:150]) + "…"
	}
	return subject, b.String()
}

func (s *Server) alertLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			func() {
				defer func() {
					if v := recover(); v != nil {
						s.Log.Error("alert check", "err", v)
					}
				}()
				s.checkAlerts(ctx, now)
			}()
		}
	}
}

// activeAlerts lists the current problems for the panel, worst first.
func (s *Server) activeAlerts() ([]alert, []alertEvent) {
	s.alerts.mu.Lock()
	defer s.alerts.mu.Unlock()
	var out []alert
	for _, a := range s.alerts.active {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Level != out[j].Level {
			return out[i].Level == "err"
		}
		return out[i].Since.Before(out[j].Since)
	})
	h := make([]alertEvent, len(s.alerts.history))
	for i, e := range s.alerts.history {
		h[len(h)-1-i] = e
	}
	if len(h) > 20 {
		h = h[:20]
	}
	return out, h
}

// ---- settings: recipients, threshold, test mail ----

func (s *Server) alertSettingsSave(w http.ResponseWriter, r *http.Request, ss *session) {
	var emails []string
	for _, f := range strings.FieldsFunc(r.PostFormValue("emails"), func(c rune) bool { return c == ',' || c == ';' || c == '\n' || c == '\r' || c == ' ' }) {
		if !notify.ValidAddress(f) {
			s.flash(w, r, "/admin/settings#uyarilar", "", "Geçersiz e-posta adresi: "+f)
			return
		}
		emails = append(emails, f)
	}
	if len(emails) > 10 {
		s.flash(w, r, "/admin/settings#uyarilar", "", "En fazla 10 alıcı girilebilir")
		return
	}
	hours, err := strconv.Atoi(r.PostFormValue("silent_hours"))
	if err != nil || hours < 1 || hours > 72 {
		s.flash(w, r, "/admin/settings#uyarilar", "", "Log kesintisi süresi 1-72 saat olmalı")
		return
	}
	if err := s.Cfg.UpdatePanel(func(p *config.Panel) error {
		p.Settings.AlertEmails, p.Settings.SilentHours = emails, hours
		return nil
	}); err != nil {
		s.flash(w, r, "/admin/settings#uyarilar", "", err.Error())
		return
	}
	s.audit(r, ss.user.Username, "alert_settings", "emails", strings.Join(emails, ","), "silent_hours", hours)
	s.flash(w, r, "/admin/settings#uyarilar", "Uyarı ayarları kaydedildi", "")
}

func (s *Server) alertTest(w http.ResponseWriter, r *http.Request, ss *session) {
	body := "Bu bir deneme e-postasıdır. 5651 Log uyarıları bu adrese gelecek.\n\nGönderen: " + ss.user.Username + "\n"
	err := s.sendAlertMail(r.Context(), "[5651 Log] Deneme e-postası", body)
	res := "gönderildi"
	if err != nil {
		res = "gönderilemedi: " + err.Error()
	}
	s.alerts.mu.Lock()
	s.alerts.history = append(s.alerts.history, alertEvent{Time: time.Now(), Kind: "Deneme", Title: "Deneme e-postası", Result: res})
	s.alerts.mu.Unlock()
	s.audit(r, ss.user.Username, "alert_test", "result", res)
	if err != nil {
		s.flash(w, r, "/admin/settings#uyarilar", "", "Deneme e-postası gönderilemedi: "+err.Error())
		return
	}
	s.flash(w, r, "/admin/settings#uyarilar", "Deneme e-postası gönderildi", "")
}

// healthz is for monitoring tools: 200 when no error-level problem is
// active, 503 otherwise. It needs no login and tells nothing about tenants.
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	s.alerts.mu.Lock()
	errs, warns := 0, 0
	for _, a := range s.alerts.active {
		if a.Seen < 2 {
			continue
		}
		if a.Level == "err" {
			errs++
		} else {
			warns++
		}
	}
	s.alerts.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	status := "ok"
	if errs > 0 {
		status = "degraded"
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	fmt.Fprintf(w, `{"status":%q,"errors":%d,"warnings":%d,"uptime_seconds":%d}`+"\n", status, errs, warns, int64(time.Since(s.Started).Seconds()))
}

func dayTR(day string) string {
	t, err := time.Parse("2006-01-02", day)
	if err != nil {
		return day
	}
	return t.Format("02.01.2006")
}
