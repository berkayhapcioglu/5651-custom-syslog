package web

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// csrfOf logs nothing; it reads a page and returns its CSRF token.
func csrfOf(t *testing.T, c *http.Client, u string) string {
	t.Helper()
	_, body, _ := get(t, c, u)
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf on %s", u)
	}
	return m[1]
}

func post(t *testing.T, c *http.Client, u string, v url.Values) *http.Response {
	t.Helper()
	r, err := c.PostForm(u, v)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	return r
}

func TestAdminPagesRender(t *testing.T) {
	ts, _ := testServer(t)
	c := client(ts)
	login(t, ts, c, "admin", testPassword)
	for _, p := range []string{"/", "/t", "/t/musteri-a", "/t/musteri-a/d/2026-11-09", "/search", "/t/musteri-a/search?q=x&from=2026-11-01&to=2026-11-09",
		"/admin/sources", "/admin/users", "/admin/settings", "/admin/audit", "/account", "/?sort=-disk", "/t/musteri-a?from=2026-11-01&order=asc"} {
		code, body, _ := get(t, c, ts.URL+p)
		if code != 200 || strings.Contains(body, "internal error") {
			t.Errorf("%s: %d", p, code)
		}
	}
}

func TestTenantUserCannotAdmin(t *testing.T) {
	ts, _ := testServer(t)
	c := client(ts)
	login(t, ts, c, "ali", testPassword)
	for _, p := range []string{"/admin/sources", "/admin/users", "/admin/settings", "/admin/audit"} {
		if code, _, _ := get(t, c, ts.URL+p); code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", p, code)
		}
	}
	tok := csrfOf(t, c, ts.URL+"/account")
	for _, p := range []string{"/admin/sources/add", "/admin/users/save", "/admin/settings", "/admin/sources/tenant"} {
		r := post(t, c, ts.URL+p, url.Values{"csrf": {tok}, "tenant": {"musteri-a"}, "source": {"8.8.8.8"}, "username": {"ali"}, "role": {"admin"}})
		if r.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s: got %d, want 404", p, r.StatusCode)
		}
	}
	if code, body, _ := get(t, c, ts.URL+"/search"); code != 200 || strings.Contains(body, "musteri-b") {
		t.Error("search page leaks other tenants")
	}
	if code, _, _ := get(t, c, ts.URL+"/search?tenant=musteri-b&q=x"); code != http.StatusNotFound {
		t.Errorf("search other tenant via query: %d", code)
	}
}

func newServerT(t *testing.T) (*httptest.Server, *Server, string) {
	t.Helper()
	ts, dir := testServer(t)
	return ts, lastServer, dir
}

func TestSourcesLive(t *testing.T) {
	ts, s, dir := newServerT(t)
	c := client(ts)
	login(t, ts, c, "admin", testPassword)
	tok := csrfOf(t, c, ts.URL+"/admin/sources")
	// New tenant, then a source; logs from it resolve at once.
	post(t, c, ts.URL+"/admin/sources/tenant", url.Values{"csrf": {tok}, "new": {"1"}, "id": {"yeni-musteri"}, "name": {"Yeni A.Ş."}, "license_until": {"2027-01-31"}})
	post(t, c, ts.URL+"/admin/sources/add", url.Values{"csrf": {tok}, "tenant": {"yeni-musteri"}, "source": {"203.0.113.10"}, "label": {"Merkez FortiGate"}})
	if id, ok := s.Cfg.Resolve(netip.MustParseAddr("203.0.113.10")); !ok || id != "yeni-musteri" {
		t.Fatalf("panel source not live: %q %v", id, ok)
	}
	// Overlap with another tenant is refused.
	post(t, c, ts.URL+"/admin/sources/add", url.Values{"csrf": {tok}, "tenant": {"yeni-musteri"}, "source": {"10.0.0.0/25"}})
	if id, _ := s.Cfg.Resolve(netip.MustParseAddr("10.0.0.5")); id != "musteri-a" {
		t.Fatal("overlapping source accepted")
	}
	// Too wide networks are refused.
	post(t, c, ts.URL+"/admin/sources/add", url.Values{"csrf": {tok}, "tenant": {"yeni-musteri"}, "source": {"0.0.0.0/0"}})
	if _, ok := s.Cfg.Resolve(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("0.0.0.0/0 accepted")
	}
	// Retention below the legal minimum is refused.
	post(t, c, ts.URL+"/admin/sources/tenant", url.Values{"csrf": {tok}, "id": {"musteri-a"}, "name": {"A"}, "retention_days": {"7"}})
	if tn, _ := s.Cfg.Tenant("musteri-a"); tn.RetentionDays != 730 {
		t.Fatalf("retention changed to %d", tn.RetentionDays)
	}
	// State survives a restart and every change is audited.
	if b, err := os.ReadFile(filepath.Join(dir, "_panel", "panel.json")); err != nil || !strings.Contains(string(b), "203.0.113.10") {
		t.Fatalf("panel state not saved: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "_audit", "audit.jsonl"))
	for _, ev := range []string{"tenant_create", "source_add"} {
		if !strings.Contains(string(b), ev) {
			t.Errorf("audit lacks %s", ev)
		}
	}
	// Remove the source again.
	post(t, c, ts.URL+"/admin/sources/remove", url.Values{"csrf": {tok}, "tenant": {"yeni-musteri"}, "source": {"203.0.113.10/32"}})
	if _, ok := s.Cfg.Resolve(netip.MustParseAddr("203.0.113.10")); ok {
		t.Fatal("source not removed")
	}
}

func TestUserManagement(t *testing.T) {
	ts, _, _ := newServerT(t)
	admin := client(ts)
	login(t, ts, admin, "admin", testPassword)
	tok := csrfOf(t, admin, ts.URL+"/admin/users")
	post(t, admin, ts.URL+"/admin/users/save", url.Values{"csrf": {tok}, "new": {"1"}, "username": {"veli"}, "role": {"tenant"}, "tenants": {"musteri-b"}, "password": {"veli-icin-uzun-sifre"}})
	veli := client(ts)
	if r := login(t, ts, veli, "veli", "veli-icin-uzun-sifre"); r.Header.Get("Location") != "/" {
		t.Fatal("new user cannot log in")
	}
	if code, _, _ := get(t, veli, ts.URL+"/t/musteri-b"); code != 200 {
		t.Fatal("new user cannot see own tenant")
	}
	if code, _, _ := get(t, veli, ts.URL+"/t/musteri-a"); code != http.StatusNotFound {
		t.Fatal("new user sees other tenant")
	}
	// A password change by the admin ends veli's session.
	post(t, admin, ts.URL+"/admin/users/save", url.Values{"csrf": {tok}, "username": {"veli"}, "role": {"tenant"}, "tenants": {"musteri-b"}, "password": {"baska-uzun-sifre-123"}})
	if code, _, h := get(t, veli, ts.URL+"/t/musteri-b"); code != http.StatusSeeOther || h.Get("Location") != "/login" {
		t.Fatalf("session survived password change: %d", code)
	}
	// Deleting yourself and the last admin is refused.
	post(t, admin, ts.URL+"/admin/users/delete", url.Values{"csrf": {tok}, "username": {"admin"}})
	if code, _, _ := get(t, admin, ts.URL+"/admin/users"); code != 200 {
		t.Fatal("admin deleted itself")
	}
	post(t, admin, ts.URL+"/admin/users/save", url.Values{"csrf": {tok}, "username": {"admin"}, "role": {"tenant"}, "tenants": {"musteri-a"}})
	if code, _, _ := get(t, admin, ts.URL+"/admin/users"); code != 200 {
		t.Fatal("last admin demoted")
	}
	post(t, admin, ts.URL+"/admin/users/delete", url.Values{"csrf": {tok}, "username": {"veli"}})
	if r := login(t, ts, client(ts), "veli", "baska-uzun-sifre-123"); r.Header.Get("Location") == "/" {
		t.Fatal("deleted user can log in")
	}
}

func TestAccountPassword(t *testing.T) {
	ts, _, _ := newServerT(t)
	c := client(ts)
	login(t, ts, c, "ali", testPassword)
	tok := csrfOf(t, c, ts.URL+"/account")
	post(t, c, ts.URL+"/account/password", url.Values{"csrf": {tok}, "current": {"yanlis"}, "new": {"yeni-uzun-sifre-42"}, "repeat": {"yeni-uzun-sifre-42"}})
	if r := login(t, ts, client(ts), "ali", "yeni-uzun-sifre-42"); r.Header.Get("Location") == "/" {
		t.Fatal("password changed without the current password")
	}
	post(t, c, ts.URL+"/account/password", url.Values{"csrf": {tok}, "current": {testPassword}, "new": {"yeni-uzun-sifre-42"}, "repeat": {"yeni-uzun-sifre-42"}})
	if code, _, _ := get(t, c, ts.URL+"/account"); code != 200 {
		t.Fatal("own session ended after own password change")
	}
	if r := login(t, ts, client(ts), "ali", "yeni-uzun-sifre-42"); r.Header.Get("Location") != "/" {
		t.Fatal("new password does not work")
	}
}

func TestErrorPages(t *testing.T) {
	ts, _ := testServer(t)
	c := client(ts)
	login(t, ts, c, "admin", testPassword)
	code, body, h := get(t, c, ts.URL+"/t/yok-boyle")
	if code != http.StatusNotFound || !strings.Contains(body, "Sayfa bulunamadı") || !strings.HasPrefix(h.Get("Content-Type"), "text/html") {
		t.Fatalf("404 page: %d %s", code, h.Get("Content-Type"))
	}
	if h.Get("Content-Security-Policy") == "" {
		t.Fatal("error page lost security headers")
	}
	if code, body, _ := get(t, c, ts.URL+"/admin/sources/add"); code != http.StatusMethodNotAllowed || !strings.Contains(body, "böyle açılmaz") {
		t.Fatalf("405 page: %d", code)
	}
}
