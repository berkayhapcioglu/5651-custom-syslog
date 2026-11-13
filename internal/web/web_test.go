package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/config"
)

const testPassword = "dogru-at-pil-zimba-42"

var lastServer *Server

func testServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	for _, p := range []string{"musteri-a/2026-11-09", "musteri-b/2026-11-09"} {
		os.MkdirAll(filepath.Join(dir, p), 0o750)
	}
	h, _ := HashPassword(testPassword)
	if err := SaveUsers(filepath.Join(dir, "users.yaml"), &UsersFile{Users: []User{
		{Username: "admin", PasswordHash: h, Role: RoleAdmin},
		{Username: "ali", PasswordHash: h, Role: RoleTenant, Tenants: []string{"musteri-a"}},
	}}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(`
data_dir: ` + dir + `
listen: {udp: ":0"}
timestamp: {mode: none}
web: {listen: ":0", users_file: ` + filepath.Join(dir, "users.yaml") + `, tls_cert: x, tls_key: y}
tenants:
  - {id: musteri-a, name: A, sources: [10.0.0.0/24]}
  - {id: musteri-b, name: B, sources: [10.0.1.0/24]}
`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), NewLastSeen())
	if err != nil {
		t.Fatal(err)
	}
	lastServer = s
	ts := httptest.NewTLSServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, dir
}

func client(ts *httptest.Server) *http.Client {
	c := *ts.Client() // a copy: each client gets its own cookie jar
	c.Jar, _ = cookiejar.New(nil)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func login(t *testing.T, ts *httptest.Server, c *http.Client, user, pw string) *http.Response {
	t.Helper()
	r, err := c.Get(ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	m := csrfRe.FindSubmatch(b)
	if m == nil {
		t.Fatal("no csrf on login page")
	}
	resp, err := c.PostForm(ts.URL+"/login", url.Values{"csrf": {string(m[1])}, "username": {user}, "password": {pw}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func get(t *testing.T, c *http.Client, u string) (int, string, http.Header) {
	t.Helper()
	r, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r.StatusCode, string(b), r.Header
}

func TestRequiresLogin(t *testing.T) {
	ts, _ := testServer(t)
	c := client(ts)
	for _, p := range []string{"/", "/t/musteri-a", "/t/musteri-a/d/2026-11-09", "/t/musteri-a/search?q=x"} {
		code, _, h := get(t, c, ts.URL+p)
		if code != http.StatusSeeOther || h.Get("Location") != "/login" {
			t.Fatalf("%s: got %d, want redirect to login", p, code)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	ts, _ := testServer(t)
	_, _, h := get(t, client(ts), ts.URL+"/login")
	for k, want := range map[string]string{
		"Content-Security-Policy":   "default-src 'none'",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Strict-Transport-Security": "max-age=",
		"Cache-Control":             "no-store",
	} {
		if !strings.Contains(h.Get(k), want) {
			t.Errorf("%s = %q", k, h.Get(k))
		}
	}
	if c := h.Get("Set-Cookie"); !strings.Contains(c, "__Host-") || !strings.Contains(c, "Secure") || !strings.Contains(c, "HttpOnly") || !strings.Contains(c, "SameSite=Strict") {
		t.Errorf("login cookie flags: %s", c)
	}
}

func TestLoginAndTenantIsolation(t *testing.T) {
	ts, _ := testServer(t)
	c := client(ts)
	if r := login(t, ts, c, "ali", testPassword); r.Header.Get("Location") != "/" {
		t.Fatalf("login failed: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	code, body, _ := get(t, c, ts.URL+"/")
	if code != 200 || !strings.Contains(body, "musteri-a") || strings.Contains(body, "musteri-b") {
		t.Fatalf("dashboard shows wrong tenants: %d", code)
	}
	if code, _, _ := get(t, c, ts.URL+"/t/musteri-a/d/2026-11-09"); code != 200 {
		t.Fatalf("own tenant: %d", code)
	}
	for _, p := range []string{
		"/t/musteri-b", "/t/musteri-b/d/2026-11-09", "/t/musteri-b/search?q=x",
		"/t/musteri-b/d/2026-11-09/package.zip", "/t/musteri-a/d/..%2f..%2fetc",
		"/t/musteri-a/d/2026-11-09/raw/..%2f..%2f/00", "/t/..%2fmusteri-b",
	} {
		if code, _, _ := get(t, c, ts.URL+p); code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", p, code)
		}
	}
}

func TestWrongPasswordAndLockout(t *testing.T) {
	ts, _ := testServer(t)
	c := client(ts)
	for i := 0; i < 5; i++ {
		if r := login(t, ts, c, "admin", "wrong-password-xx"); r.Header.Get("Location") != "/login?e=1" {
			t.Fatalf("attempt %d: %d %s", i, r.StatusCode, r.Header.Get("Location"))
		}
	}
	if r := login(t, ts, c, "admin", testPassword); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected lockout, got %d", r.StatusCode)
	}
}

func TestCSRF(t *testing.T) {
	ts, _ := testServer(t)
	c := client(ts)
	// Login without the login CSRF token.
	r, _ := c.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {testPassword}})
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("login without csrf: %d", r.StatusCode)
	}
	login(t, ts, c, "admin", testPassword)
	r, _ = c.PostForm(ts.URL+"/logout", url.Values{"csrf": {"forged"}})
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("logout with bad csrf: %d", r.StatusCode)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/logout", strings.NewReader("csrf=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	r, _ = c.Do(req)
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site post: %d", r.StatusCode)
	}
}

func TestPasswordPolicy(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
	h, _ := HashPassword(testPassword)
	if !CheckPassword(h, testPassword) || CheckPassword(h, testPassword+"x") {
		t.Fatal("password check wrong")
	}
	if CheckPassword("$argon2id$v=19$m=8,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "x") {
		t.Fatal("weak parameters accepted")
	}
}
