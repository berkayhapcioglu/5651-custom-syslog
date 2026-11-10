// Package web serves the management interface.
//
// Security model:
//   - HTTPS only (TLS 1.2+), HSTS, strict CSP with no JavaScript at all.
//   - argon2id password hashes, constant-time checks, dummy hash for unknown
//     users, exponential lockout per IP and per username.
//   - Server-side sessions with random 256-bit ids in __Host- cookies
//     (Secure, HttpOnly, SameSite=Strict); CSRF tokens on every POST.
//   - Tenant users can only reach their own tenants; every path element is
//     validated and joined with SafeJoin.
//   - Every login, search and download is written to the audit log.
package web

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/config"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

// LastSeen tracks the latest record per tenant/device.
type LastSeen struct {
	mu sync.Mutex
	m  map[string]map[string]time.Time
}

// NewLastSeen creates an empty tracker.
func NewLastSeen() *LastSeen { return &LastSeen{m: map[string]map[string]time.Time{}} }

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

// Server is the web UI.
type Server struct {
	Cfg      *config.Config
	Users    map[string]User
	Log      *slog.Logger
	Seen     *LastSeen
	Roots    *x509.CertPool
	Stats    func() map[string]int64
	Insecure bool

	sess   *sessions
	limIP  *limiter
	limUsr *limiter
	tpl    *template.Template
}

// New builds the server.
func New(cfg *config.Config, users map[string]User, log *slog.Logger, seen *LastSeen) (*Server, error) {
	s := &Server{
		Cfg: cfg, Users: users, Log: log, Seen: seen,
		Insecure: cfg.Web.AllowInsecureHTTP,
		sess:     newSessions(cfg.Web.SessionTTL.Duration),
		limIP:    newLimiter(),
		limUsr:   newLimiter(),
	}
	funcs := template.FuncMap{
		"ratio": func(raw, file int64) string {
			if file == 0 {
				return "-"
			}
			return fmt.Sprintf("%.1fx", float64(raw)/float64(file))
		},
		"bytes": humanBytes,
		"ago": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return time.Since(t).Round(time.Second).String()
		},
		"localtime": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.In(cfg.Location()).Format("2006-01-02 15:04:05")
		},
	}
	t, err := template.New("").Funcs(funcs).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s.tpl = t
	return s, nil
}

// Handler returns the HTTP handler with security middleware applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fsSub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("POST /logout", s.auth(s.logout))
	mux.HandleFunc("GET /{$}", s.auth(s.dashboard))
	mux.HandleFunc("GET /t/{tenant}", s.auth(s.tenantPage))
	mux.HandleFunc("GET /t/{tenant}/d/{day}", s.auth(s.dayPage))
	mux.HandleFunc("POST /t/{tenant}/d/{day}/verify", s.auth(s.verifyDay))
	mux.HandleFunc("GET /t/{tenant}/d/{day}/package.zip", s.auth(s.packageZip))
	mux.HandleFunc("GET /t/{tenant}/d/{day}/raw/{device}/{hour}", s.auth(s.rawHour))
	mux.HandleFunc("GET /t/{tenant}/search", s.auth(s.search))
	return s.secure(mux)
}

// ListenAndServe runs the server until ctx ends.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.Cfg.Web.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      10 * time.Minute, // large package downloads
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(s.Log.Handler(), slog.LevelWarn),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		},
	}
	// #nosec G118 -- shutdown needs a fresh context; ctx is already done here
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(c)
	}()
	s.Log.Info("web listening", "addr", s.Cfg.Web.Listen, "tls", !s.Insecure)
	var err error
	if s.Insecure {
		err = srv.ListenAndServe()
	} else {
		err = srv.ListenAndServeTLS(s.Cfg.Web.TLSCert, s.Cfg.Web.TLSKey)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) cookieName() string {
	if s.Insecure {
		return "s5651"
	}
	return "__Host-s5651"
}

func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		h.Set("Cache-Control", "no-store")
		if !s.Insecure {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
			// Reject cross-site POSTs even before the CSRF token check.
			if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		defer func() {
			if v := recover(); v != nil {
				s.Log.Error("panic in handler", "err", v, "path", r.URL.Path)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next func(http.ResponseWriter, *http.Request, *session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(s.cookieName())
		var ss *session
		if err == nil {
			ss = s.sess.get(c.Value, time.Now())
		}
		if ss == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(ss.csrf)) != 1 {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		next(w, r, ss)
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) render(w http.ResponseWriter, name string, data map[string]any) {
	var buf bytes.Buffer
	if err := s.tpl.ExecuteTemplate(&buf, name, data); err != nil {
		s.Log.Error("template", "name", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

func (s *Server) audit(r *http.Request, user, event string, kv ...any) {
	ev := map[string]any{
		"time":  time.Now().UTC().Format(time.RFC3339),
		"event": event,
		"user":  user,
		"ip":    clientIP(r),
	}
	for i := 0; i+1 < len(kv); i += 2 {
		ev[fmt.Sprint(kv[i])] = kv[i+1]
	}
	if err := store.AppendAudit(s.Cfg.DataDir, ev); err != nil {
		s.Log.Error("audit", "err", err)
	}
}

// ---- login ----

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	tok := randToken()
	// #nosec G124 -- Secure is false only in the explicit allow_insecure_http test mode
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName() + "-login", Value: tok, Path: "/", MaxAge: 600,
		Secure: !s.Insecure, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	s.render(w, "login.html", map[string]any{"CSRF": tok, "Error": r.URL.Query().Get("e") == "1"})
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(s.cookieName() + "-login")
	if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostFormValue("csrf"))) != 1 {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	now := time.Now()
	ip := clientIP(r)
	name := r.PostFormValue("username")
	pw := r.PostFormValue("password")
	if b, _ := s.limIP.blocked("ip:"+ip, now); b {
		s.audit(r, name, "login_blocked")
		http.Error(w, "too many failed attempts, try again later", http.StatusTooManyRequests)
		return
	}
	if b, _ := s.limUsr.blocked("u:"+name, now); b {
		s.audit(r, name, "login_blocked")
		http.Error(w, "too many failed attempts, try again later", http.StatusTooManyRequests)
		return
	}
	u, ok := s.Users[name]
	hash := dummyHash
	if ok {
		hash = u.PasswordHash
	}
	if !CheckPassword(hash, pw) || !ok {
		s.limIP.failure("ip:"+ip, now)
		s.limUsr.failure("u:"+name, now)
		if !ValidUsername(name) {
			name = "(invalid)"
		}
		s.audit(r, name, "login_failed")
		http.Redirect(w, r, "/login?e=1", http.StatusSeeOther)
		return
	}
	s.limIP.success("ip:" + ip)
	s.limUsr.success("u:" + name)
	id, _ := s.sess.create(u, now)
	// #nosec G124 -- Secure is false only in the explicit allow_insecure_http test mode
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(), Value: id, Path: "/", MaxAge: int(s.Cfg.Web.SessionTTL.Seconds()),
		Secure: !s.Insecure, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	// #nosec G124 -- Secure is false only in the explicit allow_insecure_http test mode
	http.SetCookie(w, &http.Cookie{Name: s.cookieName() + "-login", Value: "", Path: "/", MaxAge: -1, Secure: !s.Insecure, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	s.audit(r, name, "login_ok")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, ss *session) {
	if c, err := r.Cookie(s.cookieName()); err == nil {
		s.sess.delete(c.Value)
	}
	// #nosec G124 -- Secure is false only in the explicit allow_insecure_http test mode
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1, Secure: !s.Insecure, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	s.audit(r, ss.user.Username, "logout")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- authorization helpers ----

func (s *Server) visibleTenants(u User) []config.Tenant {
	var out []config.Tenant
	for _, t := range s.Cfg.Tenants {
		if s.canSee(u, t.ID) {
			out = append(out, t)
		}
	}
	return out
}

func (s *Server) canSee(u User, tenant string) bool {
	if u.Role == RoleAdmin {
		return true
	}
	for _, t := range u.Tenants {
		if t == tenant {
			return true
		}
	}
	return false
}

// tenantParam validates the {tenant} path value and the user's access.
// Unknown and forbidden tenants both answer 404 so ids cannot be probed.
func (s *Server) tenantParam(w http.ResponseWriter, r *http.Request, ss *session) (*config.Tenant, bool) {
	id := r.PathValue("tenant")
	t, ok := s.Cfg.Tenant(id)
	if !config.IDPattern.MatchString(id) || !ok || !s.canSee(ss.user, id) {
		http.NotFound(w, r)
		return nil, false
	}
	return t, true
}

func (s *Server) dayParam(w http.ResponseWriter, r *http.Request, tenant string) (string, string, bool) {
	day := r.PathValue("day")
	if !store.ValidDay(day) {
		http.NotFound(w, r)
		return "", "", false
	}
	dir, err := store.SafeJoin(s.Cfg.DataDir, tenant, day)
	if err != nil {
		http.NotFound(w, r)
		return "", "", false
	}
	if st, err := os.Lstat(dir); err != nil || !st.IsDir() { // #nosec G703 -- tenant and day validated, SafeJoin above
		http.NotFound(w, r)
		return "", "", false
	}
	return day, dir, true
}

// ---- pages ----

type tenantRow struct {
	T          config.Tenant
	Devices    int
	LastSeen   time.Time
	LastSealed string
	StampTime  string
	Days       int
	Problem    string
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, ss *session) {
	var rows []tenantRow
	for _, t := range s.visibleTenants(ss.user) {
		row := tenantRow{T: t}
		seen := s.Seen.get(t.ID)
		row.Devices = len(seen)
		for _, v := range seen {
			if v.After(row.LastSeen) {
				row.LastSeen = v
			}
		}
		days, _ := store.ListDays(s.Cfg.DataDir, t.ID)
		row.Days = len(days)
		for i := len(days) - 1; i >= 0; i-- {
			dir := store.DayDir(s.Cfg.DataDir, t.ID, days[i])
			if info, err := store.ReadSealedInfo(dir); err == nil {
				row.LastSealed = days[i]
				row.StampTime = info.StampTime
				break
			}
		}
		if row.LastSeen.IsZero() || time.Since(row.LastSeen) > time.Hour {
			row.Problem = "Son 1 saatte log gelmedi"
		}
		rows = append(rows, row)
	}
	data := map[string]any{"User": ss.user, "CSRF": ss.csrf, "Rows": rows}
	if ss.user.Role == RoleAdmin && s.Stats != nil {
		data["Stats"] = s.Stats()
	}
	s.render(w, "dashboard.html", data)
}

type dayRow struct {
	Day       string
	Sealed    bool
	StampTime string
	Files     int
	Lines     int64
	Raw       int64
	Stored    int64
}

func (s *Server) tenantPage(w http.ResponseWriter, r *http.Request, ss *session) {
	t, ok := s.tenantParam(w, r, ss)
	if !ok {
		return
	}
	days, _ := store.ListDays(s.Cfg.DataDir, t.ID)
	var rows []dayRow
	for i := len(days) - 1; i >= 0; i-- {
		dir := store.DayDir(s.Cfg.DataDir, t.ID, days[i])
		row := dayRow{Day: days[i], Sealed: store.IsSealed(dir)}
		if info, err := store.ReadSealedInfo(dir); err == nil {
			row.StampTime = info.StampTime
		}
		hours, _ := store.ReadHours(dir)
		for _, h := range hours {
			row.Files++
			row.Lines += h.Lines
			row.Raw += h.RawBytes
			row.Stored += h.FileBytes
		}
		rows = append(rows, row)
	}
	seen := s.Seen.get(t.ID)
	type dev struct {
		Name string
		Last time.Time
	}
	var devs []dev
	for k, v := range seen {
		devs = append(devs, dev{k, v})
	}
	sort.Slice(devs, func(i, j int) bool { return devs[i].Name < devs[j].Name })
	s.render(w, "tenant.html", map[string]any{"User": ss.user, "CSRF": ss.csrf, "T": t, "Days": rows, "Devices": devs})
}

func (s *Server) dayPage(w http.ResponseWriter, r *http.Request, ss *session) {
	t, ok := s.tenantParam(w, r, ss)
	if !ok {
		return
	}
	day, dir, ok := s.dayParam(w, r, t.ID)
	if !ok {
		return
	}
	hours, err := store.ReadHours(dir)
	data := map[string]any{"User": ss.user, "CSRF": ss.csrf, "T": t, "Day": day, "Hours": hours, "Sealed": store.IsSealed(dir)}
	if err != nil {
		data["Error"] = err.Error()
	}
	if info, err := store.ReadSealedInfo(dir); err == nil {
		data["Info"] = info
	}
	s.render(w, "day.html", data)
}

func (s *Server) verifyDay(w http.ResponseWriter, r *http.Request, ss *session) {
	t, ok := s.tenantParam(w, r, ss)
	if !ok {
		return
	}
	day, _, ok := s.dayParam(w, r, t.ID)
	if !ok {
		return
	}
	rep, err := store.VerifyDay(s.Cfg.DataDir, t.ID, day, s.Roots, s.Cfg.Timestamp.Mode != "none")
	s.audit(r, ss.user.Username, "verify", "tenant", t.ID, "day", day, "ok", err == nil)
	data := map[string]any{"User": ss.user, "CSRF": ss.csrf, "T": t, "Day": day, "Report": rep}
	if err != nil {
		data["Error"] = err.Error()
	}
	s.render(w, "verify.html", data)
}

func (s *Server) packageZip(w http.ResponseWriter, r *http.Request, ss *session) {
	t, ok := s.tenantParam(w, r, ss)
	if !ok {
		return
	}
	day, dir, ok := s.dayParam(w, r, t.ID)
	if !ok {
		return
	}
	if !store.IsSealed(dir) {
		http.Error(w, "gün henüz mühürlenmedi", http.StatusConflict)
		return
	}
	hours, err := store.ReadHours(dir)
	if err != nil {
		http.Error(w, "manifest okunamadı", http.StatusInternalServerError)
		return
	}
	s.audit(r, ss.user.Username, "download_package", "tenant", t.ID, "day", day)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s_%s_5651.zip"`, t.ID, day))
	zw := zip.NewWriter(w)
	files := []string{store.ManifestFile, store.StampFile, store.HoursFile, store.SealedMarker}
	for _, h := range hours {
		files = append(files, filepath.Join(h.Device, h.Hour+store.SealedExt))
	}
	for _, f := range files {
		src, err := os.OpenInRoot(dir, f)
		if err != nil {
			continue
		}
		dst, err := zw.CreateHeader(&zip.FileHeader{Name: filepath.ToSlash(f), Method: zip.Store, Modified: time.Now()})
		if err == nil {
			_, err = io.Copy(dst, src)
		}
		src.Close()
		if err != nil {
			s.Log.Error("package zip", "err", err)
			return
		}
	}
	zw.Close()
}

func (s *Server) rawHour(w http.ResponseWriter, r *http.Request, ss *session) {
	t, ok := s.tenantParam(w, r, ss)
	if !ok {
		return
	}
	day, dir, ok := s.dayParam(w, r, t.ID)
	if !ok {
		return
	}
	device, hour := r.PathValue("device"), r.PathValue("hour")
	if !store.ValidDevice(device) || !store.ValidHour(hour) {
		http.NotFound(w, r)
		return
	}
	hours, err := store.ReadHours(dir)
	if err != nil {
		http.Error(w, "manifest okunamadı", http.StatusInternalServerError)
		return
	}
	for _, h := range hours {
		if h.Device == device && h.Hour == hour {
			raw, err := store.ReadSealed(dir, h)
			if err != nil {
				s.audit(r, ss.user.Username, "download_raw_failed", "tenant", t.ID, "day", day, "file", h.File, "err", err.Error())
				http.Error(w, "dosya doğrulanamadı: "+err.Error(), http.StatusInternalServerError)
				return
			}
			s.audit(r, ss.user.Username, "download_raw", "tenant", t.ID, "day", day, "file", h.File)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s_%s_%s_%s.log"`, t.ID, day, device, hour))
			w.Write(raw) // #nosec G705 -- served as an attachment with text/plain and nosniff
			return
		}
	}
	http.NotFound(w, r)
}

type hit struct {
	Device string
	Hour   string
	Line   string
}

const (
	maxQuery = 200
	maxHits  = 500
)

func (s *Server) search(w http.ResponseWriter, r *http.Request, ss *session) {
	t, ok := s.tenantParam(w, r, ss)
	if !ok {
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	day := r.URL.Query().Get("day")
	device := r.URL.Query().Get("device")
	data := map[string]any{"User": ss.user, "CSRF": ss.csrf, "T": t, "Q": q, "Day": day, "Device": device}
	if day == "" {
		day = time.Now().In(s.Cfg.Location()).Format(store.DayLayout)
		data["Day"] = day
	}
	if q == "" {
		s.render(w, "search.html", data)
		return
	}
	if len(q) > maxQuery || !store.ValidDay(day) || (device != "" && !store.ValidDevice(device)) {
		data["Error"] = "Geçersiz arama"
		s.render(w, "search.html", data)
		return
	}
	dir, err := store.SafeJoin(s.Cfg.DataDir, t.ID, day)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.audit(r, ss.user.Username, "search", "tenant", t.ID, "day", day, "device", device, "query", q)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	hits, truncated, err := searchDay(ctx, dir, device, []byte(q))
	if err != nil {
		data["Error"] = err.Error()
	}
	data["Hits"] = hits
	data["Truncated"] = truncated
	s.render(w, "search.html", data)
}

// searchDay scans sealed hours and current raw files of one day.
func searchDay(ctx context.Context, dir, device string, q []byte) ([]hit, bool, error) {
	var hits []hit
	add := func(dev, hour string, data []byte) bool {
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 64*1024), 2<<20)
		for sc.Scan() {
			if bytes.Contains(sc.Bytes(), q) {
				hits = append(hits, hit{dev, hour, sc.Text()})
				if len(hits) >= maxHits {
					return false
				}
			}
		}
		return true
	}
	hours, err := store.ReadHours(dir)
	if err != nil {
		return nil, false, err
	}
	for _, h := range hours {
		if ctx.Err() != nil {
			return hits, true, errors.New("arama zaman aşımına uğradı, aramayı daraltın")
		}
		if device != "" && h.Device != device {
			continue
		}
		raw, err := store.ReadSealed(dir, h)
		if err != nil {
			return hits, false, err
		}
		if !add(h.Device, h.Hour, raw) {
			return hits, true, nil
		}
	}
	// Hours that are still open (not sealed yet).
	raws, _ := filepath.Glob(filepath.Join(dir, "*", "*"+store.RawExt))
	for _, p := range raws {
		dev := filepath.Base(filepath.Dir(p))
		if !store.ValidDevice(dev) || (device != "" && dev != device) {
			continue
		}
		b, err := readLimited(dir, filepath.Join(dev, filepath.Base(p)), 2<<30)
		if err != nil {
			continue
		}
		if !add(dev, strings.TrimSuffix(filepath.Base(p), store.RawExt)+" (açık)", b) {
			return hits, true, nil
		}
	}
	return hits, false, nil
}

func readLimited(dir, rel string, n int64) ([]byte, error) {
	f, err := os.OpenInRoot(dir, rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, n))
}

func humanBytes(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(u), 0
	for m := n / u; m >= u; m /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
