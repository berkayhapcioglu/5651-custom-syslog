package web

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"sync"
	"time"
)

const pendingTTL = 5 * time.Minute

// pendingLogins holds logins whose password was right and that still need
// the one-time code.
type pendingLogins struct {
	mu sync.Mutex
	m  map[string]*pendingLogin
}

type pendingLogin struct {
	user    string
	expires time.Time
	tries   int
}

func (p *pendingLogins) add(user string, now time.Time) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[string]*pendingLogin{}
	}
	for k, v := range p.m {
		if now.After(v.expires) {
			delete(p.m, k)
		}
	}
	tok := randToken()
	p.m[tok] = &pendingLogin{user: user, expires: now.Add(pendingTTL)}
	return tok
}

func (p *pendingLogins) get(tok string, now time.Time) *pendingLogin {
	p.mu.Lock()
	defer p.mu.Unlock()
	v := p.m[tok]
	if v == nil || now.After(v.expires) {
		delete(p.m, tok)
		return nil
	}
	return v
}

// fail counts a wrong code; after 5 the pending login is dropped.
func (p *pendingLogins) fail(tok string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if v := p.m[tok]; v != nil {
		if v.tries++; v.tries >= 5 {
			delete(p.m, tok)
		}
	}
}

func (p *pendingLogins) drop(tok string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.m, tok)
}

func (s *Server) pendingOf(r *http.Request) (string, *pendingLogin) {
	c, err := r.Cookie(s.cookieName() + "-2fa")
	if err != nil {
		return "", nil
	}
	return c.Value, s.pend.get(c.Value, time.Now())
}

func (s *Server) login2faPage(w http.ResponseWriter, r *http.Request) {
	tok, p := s.pendingOf(r)
	if p == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, "login2fa.html", map[string]any{"CSRF": tok, "Error": r.URL.Query().Get("e") == "1", "Version": s.Version})
}

func (s *Server) login2faPost(w http.ResponseWriter, r *http.Request) {
	tok, p := s.pendingOf(r)
	if p == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	// The pending token doubles as the CSRF token of this form.
	if subtle.ConstantTimeCompare([]byte(tok), []byte(r.PostFormValue("csrf"))) != 1 {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	now := time.Now()
	ip := clientIP(r)
	if b, _ := s.limIP.blocked("ip:"+ip, now); b {
		http.Error(w, "too many failed attempts, try again later", http.StatusTooManyRequests)
		return
	}
	u, ok := s.users.get(p.user)
	if !ok || u.TOTPSecret == "" {
		s.pend.drop(tok)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !s.checkTOTP(u.Username, u.TOTPSecret, r.PostFormValue("code")) {
		s.pend.fail(tok)
		s.limIP.failure("ip:"+ip, now)
		s.limUsr.failure("u:"+u.Username, now)
		s.audit(r, u.Username, "login_2fa_failed")
		http.Redirect(w, r, "/login/2fa?e=1", http.StatusSeeOther)
		return
	}
	s.pend.drop(tok)
	// #nosec G124 -- Secure is false only in the explicit allow_insecure_http test mode
	http.SetCookie(w, &http.Cookie{Name: s.cookieName() + "-2fa", Value: "", Path: "/", MaxAge: -1, Secure: !s.Insecure, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	s.finishLogin(w, r, u, now)
}

// ---- turning two-step login on and off (Hesabım) ----

func (s *Server) account2faStart(w http.ResponseWriter, r *http.Request, ss *session) {
	if ss.user.TOTPSecret != "" {
		s.flash(w, r, "/account", "", "İki adımlı giriş zaten açık")
		return
	}
	s.sess.setTOTPPending(sessionIDOf(r, s), newTOTPSecret())
	http.Redirect(w, r, "/account#iki-adim", http.StatusSeeOther)
}

func (s *Server) account2faEnable(w http.ResponseWriter, r *http.Request, ss *session) {
	secret := ss.totpPending
	if secret == "" || ss.user.TOTPSecret != "" {
		s.flash(w, r, "/account", "", "Önce kurulumu başlatın")
		return
	}
	if !s.checkTOTP(ss.user.Username, secret, r.PostFormValue("code")) {
		s.flash(w, r, "/account#iki-adim", "", "Kod doğru değil. Telefonun saatinin doğru olduğundan emin olup yeni kodu girin.")
		return
	}
	if err := s.setTOTP(ss.user.Username, secret); err != nil {
		s.flash(w, r, "/account", "", err.Error())
		return
	}
	s.sess.setTOTPPending(sessionIDOf(r, s), "")
	s.audit(r, ss.user.Username, "2fa_enable")
	s.flash(w, r, "/account", "İki adımlı giriş açıldı. Bir sonraki girişte doğrulama kodu istenecek.", "")
}

func (s *Server) account2faDisable(w http.ResponseWriter, r *http.Request, ss *session) {
	u, ok := s.users.get(ss.user.Username)
	if !ok || u.TOTPSecret == "" {
		s.flash(w, r, "/account", "", "İki adımlı giriş kapalı")
		return
	}
	if !CheckPassword(u.PasswordHash, r.PostFormValue("password")) || !s.checkTOTP(u.Username, u.TOTPSecret, r.PostFormValue("code")) {
		s.audit(r, u.Username, "2fa_disable_failed")
		s.flash(w, r, "/account", "", "Şifre ya da kod yanlış")
		return
	}
	if err := s.setTOTP(u.Username, ""); err != nil {
		s.flash(w, r, "/account", "", err.Error())
		return
	}
	s.audit(r, u.Username, "2fa_disable")
	s.flash(w, r, "/account", "İki adımlı giriş kapatıldı", "")
}

// userReset2fa lets an admin turn off two-step login for a user who lost
// their phone. The user's sessions end.
func (s *Server) userReset2fa(w http.ResponseWriter, r *http.Request, ss *session) {
	name := r.PostFormValue("username")
	if err := s.setTOTP(name, ""); err != nil {
		s.flash(w, r, "/admin/users", "", err.Error())
		return
	}
	s.sess.deleteUser(name, sessionIDOf(r, s))
	s.audit(r, ss.user.Username, "2fa_reset", "target", name)
	s.flash(w, r, "/admin/users", name+" için iki adımlı giriş kapatıldı; kullanıcı yeniden kurabilir.", "")
}

func (s *Server) setTOTP(name, secret string) error {
	return s.users.update(func(us []User) ([]User, error) {
		for i := range us {
			if us[i].Username == name {
				us[i].TOTPSecret = secret
				return us, nil
			}
		}
		return nil, errors.New("kullanıcı bulunamadı")
	})
}
