package web

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/config"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/store"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/tsa"
)

// certStatus describes a certificate file.
type certStatus struct {
	Name     string
	Path     string
	Subject  string
	NotAfter time.Time
	Days     int
	Class    string
	Err      string
	SelfSign bool
}

func readCert(name, path string, now time.Time) certStatus {
	cs := certStatus{Name: name, Path: path}
	if path == "" {
		cs.Err, cs.Class = "Tanımlı değil", ""
		return cs
	}
	b, err := os.ReadFile(path) // #nosec G304 -- operator-configured certificate path
	if err != nil {
		cs.Err, cs.Class = "Okunamadı", "err"
		return cs
	}
	blk, _ := pem.Decode(b)
	der := b
	if blk != nil {
		der = blk.Bytes
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		cs.Err, cs.Class = "Geçersiz sertifika", "err"
		return cs
	}
	return certFrom(cs, c.Subject.String(), c.NotAfter, c.Subject.String() == c.Issuer.String(), now)
}

func certFrom(cs certStatus, subject string, notAfter time.Time, self bool, now time.Time) certStatus {
	cs.Subject, cs.NotAfter, cs.SelfSign = subject, notAfter, self
	cs.Days = int(notAfter.Sub(now).Hours() / 24)
	switch {
	case cs.Days < 0:
		cs.Class = "err"
	case cs.Days < 30:
		cs.Class = "warn"
	default:
		cs.Class = "ok"
	}
	return cs
}

// serviceStatus is shown on the dashboard and the settings page.
type serviceStatus struct {
	Uptime       time.Duration
	SystemUptime time.Duration
	Started      time.Time
	Version      string
	Certs        []certStatus
	StampMode    string
	StampTSA     string
	StampLast    string
	StampDay     string
	StampCert    *certStatus
	DiskFree     int64
	DiskTotal    int64
	DiskClass    string
	Stats        map[string]int64
	Sys          sysInfo
}

func systemUptime() time.Duration {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	sec, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0
	}
	return time.Duration(sec * float64(time.Second))
}

func (s *Server) status(now time.Time) serviceStatus {
	st := serviceStatus{
		Uptime: now.Sub(s.Started), SystemUptime: systemUptime(), Started: s.Started, Version: s.Version,
		StampMode: s.Cfg.Timestamp.Mode,
	}
	if s.Cfg.Web.TLSCert != "" && !s.Insecure {
		st.Certs = append(st.Certs, readCert("Web arayüzü (HTTPS)", s.Cfg.Web.TLSCert, now))
	}
	if s.Cfg.Listen.TLS != "" {
		st.Certs = append(st.Certs, readCert("Syslog TLS (6514)", s.Cfg.Listen.TLSCert, now))
	}
	// Latest time stamp over all tenants.
	for _, t := range s.Cfg.TenantList() {
		days, _ := store.ListDays(s.Cfg.DataDir, t.ID)
		for i := len(days) - 1; i >= 0; i-- {
			dir := store.DayDir(s.Cfg.DataDir, t.ID, days[i])
			info, err := store.ReadSealedInfo(dir)
			if err != nil {
				continue
			}
			if info.StampTime > st.StampLast {
				st.StampLast, st.StampDay, st.StampTSA = info.StampTime, days[i], info.TSA
				if f, err := os.OpenInRoot(dir, store.StampFile); err == nil {
					b, _ := io.ReadAll(io.LimitReader(f, 1<<20))
					f.Close()
					if in, err := tsa.Describe(b); err == nil && !in.NotAfter.IsZero() {
						cs := certFrom(certStatus{Name: "Zaman damgası (TSA)"}, in.Subject, in.NotAfter, false, now)
						st.StampCert = &cs
					}
				}
			}
			break
		}
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(s.Cfg.DataDir, &fs); err == nil {
		bs := int64(fs.Bsize)                // #nosec G115 -- block size fits
		st.DiskFree = int64(fs.Bavail) * bs  // #nosec G115 -- disk sizes fit in int64
		st.DiskTotal = int64(fs.Blocks) * bs // #nosec G115 -- disk sizes fit in int64
		st.DiskClass = "ok"
		if st.DiskTotal > 0 && float64(st.DiskFree)/float64(st.DiskTotal) < 0.1 {
			st.DiskClass = "err"
		} else if st.DiskTotal > 0 && float64(st.DiskFree)/float64(st.DiskTotal) < 0.2 {
			st.DiskClass = "warn"
		}
	}
	if s.Stats != nil {
		st.Stats = s.Stats()
	}
	st.Sys = s.sysInfo()
	return st
}

// DiskUsedPercent is the used share of the data disk.
func (st serviceStatus) DiskUsedPercent() float64 {
	if st.DiskTotal == 0 {
		return 0
	}
	return 100 * float64(st.DiskTotal-st.DiskFree) / float64(st.DiskTotal)
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request, ss *session) {
	c := s.Cfg
	cfg := [][2]string{
		{"Veri klasörü", c.DataDir},
		{"Saat dilimi", c.Timezone},
		{"Syslog UDP", orDash(c.Listen.UDP)},
		{"Syslog TCP", orDash(c.Listen.TCP)},
		{"Syslog TLS", orDash(c.Listen.TLS)},
		{"TLS istemci sertifikası", orDash(c.Listen.TLSClientCA)},
		{"Web arayüzü", c.Web.Listen},
		{"Oturum süresi", c.Web.SessionTTL.String()},
		{"Sıkıştırma", c.Compression.Codec + fmt.Sprintf(" (%d işçi)", c.Compression.Workers)},
		{"Zaman damgası modu", c.Timestamp.Mode},
		{"Zaman damgası adresi", orDash(c.Timestamp.URL)},
		{"TSA kök sertifikası", orDash(c.Timestamp.CAFile)},
		{"Mühür bekleme süresi", c.DayGrace.String()},
		{"En büyük mesaj", humanBytes(int64(c.MaxMessageBytes))},
		{"Kullanıcı dosyası", c.Web.UsersFile},
		{"config.yaml varsayılan saklama", fmt.Sprintf("%d gün", c.RetentionDays)},
	}
	p := c.PanelCopy()
	active, history := s.activeAlerts()
	mail := "Tanımlı değil (config.yaml: alerts)"
	if s.Mailer.Enabled() {
		mail = fmt.Sprintf("%s:%d (%s), gönderen %s", c.Alerts.SMTPHost, c.Alerts.SMTPPort, c.Alerts.SMTPTLS, c.Alerts.From)
	}
	s.render(w, "settings.html", s.page(r, ss, "settings", map[string]any{
		"Alerts": active, "AlertHistory": history, "MailServer": mail, "MailOn": s.Mailer.Enabled(),
		"AlertEmails": strings.Join(p.Settings.AlertEmails, "\n"), "SilentHours": c.SilentHours(),
		"Status": s.status(time.Now()), "Config": cfg,
		"DefaultRetention": c.DefaultRetention(), "LicenseWarnDays": c.LicenseWarnDays(),
		"PanelSettings": p.Settings,
	}))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Retention limits for changes made in the panel. Law 5651 asks for at least
// one and at most two years; we allow up to ten for contracts that need more.
const (
	minRetention = 365
	maxRetention = 3650
)

func (s *Server) settingsSave(w http.ResponseWriter, r *http.Request, ss *session) {
	ret, err1 := strconv.Atoi(r.PostFormValue("default_retention_days"))
	warn, err2 := strconv.Atoi(r.PostFormValue("license_warn_days"))
	if err1 != nil || err2 != nil || ret < minRetention || ret > maxRetention || warn < 1 || warn > 365 {
		s.flash(w, r, "/admin/settings", "", fmt.Sprintf("Saklama süresi %d-%d gün, lisans uyarısı 1-365 gün olmalı", minRetention, maxRetention))
		return
	}
	old := s.Cfg.PanelCopy().Settings
	err := s.Cfg.UpdatePanel(func(p *config.Panel) error {
		p.Settings.DefaultRetentionDays = ret
		p.Settings.LicenseWarnDays = warn
		return nil
	})
	if err != nil {
		s.flash(w, r, "/admin/settings", "", err.Error())
		return
	}
	s.audit(r, ss.user.Username, "settings_update", "default_retention_days", ret, "old_default_retention_days", old.DefaultRetentionDays,
		"license_warn_days", warn)
	s.flash(w, r, "/admin/settings", "Ayarlar kaydedildi", "")
}

// ---- audit log ----

type auditRow struct {
	Time  string
	Event string
	User  string
	IP    string
	Rest  string
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request, ss *session) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if len(q) > 100 {
		q = q[:100]
	}
	rows, err := readAudit(s.Cfg.DataDir, q, 300)
	data := map[string]any{"Rows": rows, "Q": q}
	if err != nil {
		data["Error"] = err.Error()
	}
	s.render(w, "audit.html", s.page(r, ss, "audit", data))
}

// readAudit returns the newest n matching entries of the audit log. It reads
// at most the last 8 MiB of the file.
func readAudit(root, q string, n int) ([]auditRow, error) {
	f, err := os.OpenInRoot(root, filepath.Join(store.AuditDir, "audit.jsonl"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	const window = 8 << 20
	if st, err := f.Stat(); err == nil && st.Size() > window {
		if _, err := f.Seek(st.Size()-window, io.SeekStart); err != nil {
			return nil, err
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, window))
	if err != nil {
		return nil, err
	}
	var lines [][]byte
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		lines = append(lines, append([]byte(nil), sc.Bytes()...))
	}
	var out []auditRow
	for i := len(lines) - 1; i >= 0 && len(out) < n; i-- {
		if q != "" && !bytes.Contains(bytes.ToLower(lines[i]), []byte(q)) {
			continue
		}
		var m map[string]any
		if json.Unmarshal(lines[i], &m) != nil {
			continue
		}
		row := auditRow{}
		pop := func(k string) string {
			v, ok := m[k]
			delete(m, k)
			if !ok {
				return ""
			}
			return fmt.Sprint(v)
		}
		row.Time, row.Event, row.User, row.IP = pop("time"), pop("event"), pop("user"), pop("ip")
		if row.Event == "" { // retention entries use "action"
			row.Event = pop("action")
		}
		rest, _ := json.Marshal(m)
		if string(rest) != "{}" {
			row.Rest = string(rest)
		}
		out = append(out, row)
	}
	return out, nil
}
