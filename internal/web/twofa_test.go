package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestTOTPVector(t *testing.T) {
	// RFC 6238 appendix B, SHA-1, T=59 -> 94287082 (last 6 digits).
	sec := b32.EncodeToString([]byte("12345678901234567890"))
	if c, _ := totpCode(sec, 59/30); c != "287082" {
		t.Fatalf("got %s", c)
	}
	if _, ok := totpMatch(sec, "287082", time.Unix(59, 0)); !ok {
		t.Fatal("match failed")
	}
	if _, ok := totpMatch(sec, "287083", time.Unix(59, 0)); ok {
		t.Fatal("wrong code matched")
	}
}

func codeNow(sec string) string {
	c, _ := totpCode(sec, uint64(time.Now().Unix())/totpStep)
	return c
}

var secretRe = regexp.MustCompile(`<code class="hash">([A-Z2-7 ]+)</code>`)

func TestTwoStepLogin(t *testing.T) {
	ts, _ := testServer(t)
	c := client(ts)
	login(t, ts, c, "ali", testPassword)
	tok := csrfOf(t, c, ts.URL+"/account")
	post(t, c, ts.URL+"/account/2fa/start", url.Values{"csrf": {tok}})
	_, body, _ := get(t, c, ts.URL+"/account")
	m := secretRe.FindStringSubmatch(body)
	if m == nil || !strings.Contains(body, "<svg class=\"qr\"") {
		t.Fatal("setup page lacks secret or QR")
	}
	sec := strings.ReplaceAll(m[1], " ", "")
	post(t, c, ts.URL+"/account/2fa/enable", url.Values{"csrf": {tok}, "code": {"000000"}})
	if u, _ := lastServer.users.get("ali"); u.TOTPSecret != "" {
		t.Fatal("enabled with a wrong code")
	}
	post(t, c, ts.URL+"/account/2fa/enable", url.Values{"csrf": {tok}, "code": {codeNow(sec)}})
	if u, _ := lastServer.users.get("ali"); u.TOTPSecret != sec {
		t.Fatal("not enabled")
	}
	// The current session stays; a new login needs the code.
	if code, _, _ := get(t, c, ts.URL+"/"); code != 200 {
		t.Fatal("own session ended")
	}
	c2 := client(ts)
	if r := login(t, ts, c2, "ali", testPassword); r.Header.Get("Location") != "/login/2fa" {
		t.Fatalf("no second step: %s", r.Header.Get("Location"))
	}
	if code, _, _ := get(t, c2, ts.URL+"/"); code != http.StatusSeeOther {
		t.Fatal("logged in without the code")
	}
	t2 := csrfOf(t, c2, ts.URL+"/login/2fa")
	if r := post(t, c2, ts.URL+"/login/2fa", url.Values{"csrf": {t2}, "code": {"123456"}}); r.Header.Get("Location") != "/login/2fa?e=1" {
		t.Fatal("wrong code accepted")
	}
	// The code used to enable is already consumed: a replay within the same step fails.
	if r := post(t, c2, ts.URL+"/login/2fa", url.Values{"csrf": {t2}, "code": {codeNow(sec)}}); r.Header.Get("Location") == "/" {
		lastServer.steps.mu.Lock()
		last := lastServer.steps.m["ali"]
		lastServer.steps.mu.Unlock()
		if last == uint64(time.Now().Unix())/totpStep-1 { // step changed meanwhile; fine
			t.Skip("time step changed during test")
		}
		t.Fatal("replayed code accepted")
	}
	// Next step's code works.
	lastServer.steps.mu.Lock()
	lastServer.steps.m["ali"] = 0
	lastServer.steps.mu.Unlock()
	if r := post(t, c2, ts.URL+"/login/2fa", url.Values{"csrf": {t2}, "code": {codeNow(sec)}}); r.Header.Get("Location") != "/" {
		t.Fatalf("right code refused: %s", r.Header.Get("Location"))
	}
	if code, _, _ := get(t, c2, ts.URL+"/"); code != 200 {
		t.Fatal("no session after second step")
	}
	// The admin resets it (lost phone); ali's sessions end.
	a := client(ts)
	login(t, ts, a, "admin", testPassword)
	at := csrfOf(t, a, ts.URL+"/admin/users")
	post(t, a, ts.URL+"/admin/users/reset2fa", url.Values{"csrf": {at}, "username": {"ali"}})
	if u, _ := lastServer.users.get("ali"); u.TOTPSecret != "" {
		t.Fatal("reset failed")
	}
	if code, _, _ := get(t, c2, ts.URL+"/"); code != http.StatusSeeOther {
		t.Fatal("session survived 2fa reset")
	}
}

func TestTwoStepPendingExpiresAfterTries(t *testing.T) {
	ts, _ := testServer(t)
	lastServer.setTOTP("ali", newTOTPSecret())
	c := client(ts)
	login(t, ts, c, "ali", testPassword)
	tok := csrfOf(t, c, ts.URL+"/login/2fa")
	for i := 0; i < 5; i++ {
		post(t, c, ts.URL+"/login/2fa", url.Values{"csrf": {tok}, "code": {"000000"}})
	}
	if code, _, h := get(t, c, ts.URL+"/login/2fa"); code != http.StatusSeeOther || h.Get("Location") != "/login" {
		t.Fatal("pending login survived 5 wrong codes")
	}
}
