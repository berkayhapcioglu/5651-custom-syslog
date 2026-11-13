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
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/config"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/ingest"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/notify"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Server is the web UI.
type Server struct {
	Cfg      *config.Config
	Log      *slog.Logger
	Seen     *LastSeen
	Roots    *x509.CertPool
	Stats    func() map[string]int64
	Unknown  *ingest.Unknown
	Started  time.Time
	Version  string
	Insecure bool

	users  *userStore
	sess   *sessions
	limIP  *limiter
	limUsr *limiter
	tpl    *template.Template
	sums   *sumCache
	cpu    cpuSampler
	steps  usedSteps
	pend   pendingLogins
	// heavy is a semaphore for work that reads whole hours (search, raw
	// download, reindex), so many requests at once cannot exhaust CPU/RAM.
	heavy   chan struct{}
	heavyMu sync.Mutex
	heavyBy map[string]bool
	alerts  alerter

	// Mailer sends alert e-mails; nil or unconfigured means none are sent.
	Mailer *notify.Mailer
}

// New builds the server. Users are read from cfg.Web.UsersFile and reloaded
// when the file changes.
func New(cfg *config.Config, log *slog.Logger, seen *LastSeen) (*Server, error) {
	us, err := newUserStore(cfg.Web.UsersFile)
	if err != nil {
		return nil, err
	}
	s := &Server{
		Cfg: cfg, Log: log, Seen: seen, Started: time.Now(), Version: "dev",
		Insecure: cfg.Web.AllowInsecureHTTP,
		users:    us,
		sess:     newSessions(cfg.Web.SessionTTL.Duration),
		limIP:    newLimiter(),
		limUsr:   newLimiter(),
		sums:     newSumCache(),
		heavy:    make(chan struct{}, max(2, runtime.NumCPU()/2)),
	}
	t, err := template.New("").Funcs(s.funcs()).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s.tpl = t
	s.loadAlerts()
	return s, nil
}

// Handler returns the HTTP handler with security middleware applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fsSub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("GET /login/2fa", s.login2faPage)
	mux.HandleFunc("POST /login/2fa", s.login2faPost)
	mux.HandleFunc("POST /logout", s.auth(s.logout))
	mux.HandleFunc("GET /{$}", s.auth(s.dashboard))
	mux.HandleFunc("GET /t", s.auth(s.tenantsPage))
	mux.HandleFunc("GET /t/{tenant}", s.auth(s.tenantPage))
	mux.HandleFunc("GET /t/{tenant}/d/{day}", s.auth(s.dayPage))
	mux.HandleFunc("POST /t/{tenant}/d/{day}/verify", s.auth(s.verifyDay))
	mux.HandleFunc("POST /t/{tenant}/d/{day}/reindex", s.admin(s.reindexDay))
	mux.HandleFunc("GET /t/{tenant}/d/{day}/package.zip", s.auth(s.packageZip))
	mux.HandleFunc("GET /t/{tenant}/d/{day}/raw/{device}/{hour}", s.auth(s.rawHour))
	mux.HandleFunc("GET /t/{tenant}/search", s.auth(s.search))
	mux.HandleFunc("GET /t/{tenant}/search.csv", s.auth(s.searchCSV))
	mux.HandleFunc("GET /t/{tenant}/report", s.auth(s.reportPage))
	mux.HandleFunc("GET /search", s.auth(s.search))
	mux.HandleFunc("GET /account", s.auth(s.accountPage))
	mux.HandleFunc("POST /account/password", s.auth(s.accountPassword))
	mux.HandleFunc("POST /account/2fa/start", s.auth(s.account2faStart))
	mux.HandleFunc("POST /account/2fa/enable", s.auth(s.account2faEnable))
	mux.HandleFunc("POST /account/2fa/disable", s.auth(s.account2faDisable))
	mux.HandleFunc("GET /admin/sources", s.admin(s.sourcesPage))
	mux.HandleFunc("POST /admin/sources/tenant", s.admin(s.tenantSave))
	mux.HandleFunc("POST /admin/sources/tenant/delete", s.admin(s.tenantDelete))
	mux.HandleFunc("POST /admin/sources/add", s.admin(s.sourceAdd))
	mux.HandleFunc("POST /admin/sources/remove", s.admin(s.sourceRemove))
	mux.HandleFunc("GET /admin/users", s.admin(s.usersPage))
	mux.HandleFunc("POST /admin/users/save", s.admin(s.userSave))
	mux.HandleFunc("POST /admin/users/delete", s.admin(s.userDelete))
	mux.HandleFunc("POST /admin/users/reset2fa", s.admin(s.userReset2fa))
	mux.HandleFunc("GET /admin/settings", s.admin(s.settingsPage))
	mux.HandleFunc("POST /admin/settings", s.admin(s.settingsSave))
	mux.HandleFunc("POST /admin/settings/alerts", s.admin(s.alertSettingsSave))
	mux.HandleFunc("POST /admin/settings/alerts/test", s.admin(s.alertTest))
	mux.HandleFunc("GET /admin/audit", s.admin(s.auditPage))
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
	go s.cpu.run(ctx)
	go s.alertLoop(ctx)
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
	return http.HandlerFunc(func(w0 http.ResponseWriter, r *http.Request) {
		w := &errorWriter{ResponseWriter: w0, s: s}
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
				if v == http.ErrAbortHandler { //nolint:errorlint // sentinel compared as the panic value
					panic(v) // aborts the response on purpose (see rawHour)
				}
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
		if ss != nil {
			// The user may have been deleted, changed or given a new password.
			u, ok := s.users.get(ss.user.Username)
			if !ok || u.PasswordHash != ss.hash {
				s.sess.delete(c.Value)
				ss = nil
			} else {
				ss.user = u
			}
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

// acquireHeavy waits for a heavy-work slot; it answers 503 itself and
// returns false when none frees up in time. One user runs one heavy job at
// a time, so a single user cannot hold every slot.
func (s *Server) acquireHeavy(w http.ResponseWriter, r *http.Request, user string) (func(), bool) {
	s.heavyMu.Lock()
	if s.heavyBy == nil {
		s.heavyBy = map[string]bool{}
	}
	busy := s.heavyBy[user]
	if !busy {
		s.heavyBy[user] = true
	}
	s.heavyMu.Unlock()
	if busy {
		http.Error(w, "Önceki aramanız ya da indirmeniz hâlâ sürüyor; bitmesini bekleyin.", http.StatusTooManyRequests)
		return nil, false
	}
	done := func() {
		s.heavyMu.Lock()
		delete(s.heavyBy, user)
		s.heavyMu.Unlock()
	}
	t := time.NewTimer(20 * time.Second)
	defer t.Stop()
	select {
	case s.heavy <- struct{}{}:
		return func() { <-s.heavy; done() }, true
	case <-t.C:
	case <-r.Context().Done():
	}
	done()
	w.Header().Set("Retry-After", "10")
	http.Error(w, "Sunucu şu an başka aramaları işliyor; birkaç saniye sonra tekrar deneyin.", http.StatusServiceUnavailable)
	return nil, false
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

// auditSystem records an event of the service itself (no request).
func (s *Server) auditSystem(event string, kv ...any) {
	ev := map[string]any{"time": time.Now().UTC().Format(time.RFC3339), "event": event, "user": "system"}
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
	s.render(w, "login.html", map[string]any{"CSRF": tok, "Error": r.URL.Query().Get("e") == "1", "Version": s.Version})
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
	u, ok := s.users.get(name)
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
	if u.TOTPSecret != "" {
		// Password is right; the code is asked on the next page. The failure
		// counters are only reset once the code is right too.
		tok := s.pend.add(u.Username, now)
		// #nosec G124 -- Secure is false only in the explicit allow_insecure_http test mode
		http.SetCookie(w, &http.Cookie{Name: s.cookieName() + "-2fa", Value: tok, Path: "/", MaxAge: int(pendingTTL.Seconds()),
			Secure: !s.Insecure, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		s.audit(r, name, "login_password_ok")
		http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
		return
	}
	s.finishLogin(w, r, u, now)
}

// finishLogin creates the session after every login step succeeded.
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, u User, now time.Time) {
	name := u.Username
	s.limIP.success("ip:" + clientIP(r))
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
	for _, t := range s.Cfg.TenantList() {
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

type hourRow struct {
	store.HourEntry
	Indexed bool
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
	var rows []hourRow
	var sum daySum
	for _, h := range hours {
		_, ierr := os.Stat(store.IndexPath(dir, h.Device, h.Hour)) // #nosec G703 -- validated entry under day dir
		rows = append(rows, hourRow{h, ierr == nil})
		sum.Lines += h.Lines
		sum.Raw += h.RawBytes
		sum.Stored += h.FileBytes
	}
	data := map[string]any{"T": t, "Day": day, "Hours": rows, "Sum": sum, "Sealed": store.IsSealed(dir), "Labels": deviceLabels(t, hours)}
	if err != nil {
		data["Error"] = err.Error()
	}
	if info, err := store.ReadSealedInfo(dir); err == nil {
		data["Info"] = info
	}
	s.render(w, "day.html", s.page(r, ss, "tenants", data))
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
	data := map[string]any{"T": t, "Day": day, "Report": rep}
	if err != nil {
		data["Error"] = err.Error()
	}
	s.render(w, "verify.html", s.page(r, ss, "tenants", data))
}

// reindexDay rebuilds the search index of a day from its sealed files.
func (s *Server) reindexDay(w http.ResponseWriter, r *http.Request, ss *session) {
	t, ok := s.tenantParam(w, r, ss)
	if !ok {
		return
	}
	day, dir, ok := s.dayParam(w, r, t.ID)
	if !ok {
		return
	}
	release, ok := s.acquireHeavy(w, r, ss.user.Username)
	if !ok {
		return
	}
	defer release()
	hours, err := store.ReadHours(dir)
	n := 0
	for _, h := range hours {
		if err != nil {
			break
		}
		if err = s.reindexHour(dir, h); err == nil {
			n++
		}
	}
	s.sums.forget(dir)
	s.audit(r, ss.user.Username, "reindex", "tenant", t.ID, "day", day, "hours", n, "ok", err == nil)
	path := "/t/" + t.ID + "/d/" + day
	if err != nil {
		s.flash(w, r, path, "", "Dizin oluşturulamadı: "+err.Error())
		return
	}
	s.flash(w, r, path, fmt.Sprintf("%d saatin arama dizini yeniden oluşturuldu", n), "")
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
			release, ok := s.acquireHeavy(w, r, ss.user.Username)
			if !ok {
				return
			}
			defer release()
			// The file is streamed: nothing is sent until its SHA-256 matched
			// the manifest, and if the decoded content does not match at the
			// end the connection is cut, so a bad file is never delivered whole.
			aw := &lazyAttachment{w: w, name: fmt.Sprintf("%s_%s_%s_%s.log", t.ID, day, device, hour), size: h.RawBytes}
			err := store.StreamSealed(dir, h, aw)
			if err != nil {
				s.audit(r, ss.user.Username, "download_raw_failed", "tenant", t.ID, "day", day, "file", h.File, "err", err.Error())
				if aw.started {
					panic(http.ErrAbortHandler)
				}
				http.Error(w, "dosya doğrulanamadı: "+err.Error(), http.StatusInternalServerError)
				return
			}
			s.audit(r, ss.user.Username, "download_raw", "tenant", t.ID, "day", day, "file", h.File)
			return
		}
	}
	http.NotFound(w, r)
}

// reindexHour rebuilds one hour's index, streaming the sealed file. The
// index is written only if the whole file decoded and matched its hashes.
func (s *Server) reindexHour(dir string, h store.HourEntry) error {
	pr, pw := io.Pipe()
	type res struct {
		b   []byte
		err error
	}
	done := make(chan res, 1)
	go func() {
		b, err := store.BuildIndex(pr)
		pr.CloseWithError(err)
		done <- res{b, err}
	}()
	err := store.StreamSealed(dir, h, pw)
	pw.CloseWithError(err)
	out := <-done
	if err != nil {
		return err
	}
	if out.err != nil {
		return out.err
	}
	return store.SaveIndex(dir, h.Device, h.Hour, out.b)
}

// lazyAttachment sets the download headers on the first write, so an error
// before any data can still be answered with an error page.
type lazyAttachment struct {
	w       http.ResponseWriter
	name    string
	size    int64
	started bool
}

func (a *lazyAttachment) Write(p []byte) (int, error) {
	if !a.started {
		a.started = true
		h := a.w.Header()
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("Content-Disposition", `attachment; filename="`+a.name+`"`)
		if a.size > 0 {
			h.Set("Content-Length", strconv.FormatInt(a.size, 10))
		}
	}
	return a.w.Write(p) // #nosec G705 -- served as an attachment with text/plain and nosniff
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
	return strings.Replace(fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp]), ".", ",", 1)
}

// page fills the common template data: user, CSRF token, active menu item
// and the flash message of the previous POST.
func (s *Server) page(r *http.Request, ss *session, active string, data map[string]any) map[string]any {
	if data == nil {
		data = map[string]any{}
	}
	data["User"] = ss.user
	data["CSRF"] = ss.csrf
	data["Active"] = active
	data["IsAdmin"] = ss.user.Role == RoleAdmin
	data["Version"] = s.Version
	ok, er := s.sess.popFlash(sessionIDOf(r, s))
	data["FlashOK"], data["FlashErr"] = ok, er
	return data
}

// flash stores a one-time message in the session and redirects (POST/redirect/GET).
func (s *Server) flash(w http.ResponseWriter, r *http.Request, path, ok, er string) {
	s.sess.setFlash(sessionIDOf(r, s), ok, er)
	// Only local paths; a fragment is kept only when it is a plain anchor.
	base, frag, _ := strings.Cut(path, "#")
	if !strings.HasPrefix(base, "/") || strings.HasPrefix(base, "//") || strings.ContainsAny(base, "\\?") {
		base = "/"
	}
	if frag != "" && anchorRe.MatchString(frag) {
		base += "#" + frag
	}
	http.Redirect(w, r, base, http.StatusSeeOther) // #nosec G710 -- local path checked above
}

var anchorRe = regexp.MustCompile(`^[a-z0-9_-]{1,80}$`)
