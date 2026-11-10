package web

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/config"
)

// userStore keeps the users file in memory and reloads it when it changes on
// disk (for example after `syslog5651 useradd`), so no restart is needed.
type userStore struct {
	mu      sync.Mutex
	path    string
	m       map[string]User
	mtime   time.Time
	size    int64
	checked time.Time
}

func newUserStore(path string) (*userStore, error) {
	u := &userStore{path: path}
	if err := u.reload(); err != nil {
		return nil, err
	}
	return u, nil
}

func (u *userStore) reload() error {
	st, err := os.Stat(u.path)
	if err != nil {
		return err
	}
	m, err := LoadUsers(u.path)
	if err != nil {
		return err
	}
	u.m, u.mtime, u.size = m, st.ModTime(), st.Size()
	return nil
}

// refresh reloads the file at most once a second when it changed. A broken
// file keeps the last good users.
func (u *userStore) refresh() {
	if time.Since(u.checked) < time.Second {
		return
	}
	u.checked = time.Now()
	st, err := os.Stat(u.path)
	if err != nil || (st.ModTime().Equal(u.mtime) && st.Size() == u.size) {
		return
	}
	_ = u.reload()
}

func (u *userStore) get(name string) (User, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.refresh()
	x, ok := u.m[name]
	return x, ok
}

func (u *userStore) list() []User {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.refresh()
	out := make([]User, 0, len(u.m))
	for _, x := range u.m {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// update changes the users file under lock and reloads it.
func (u *userStore) update(fn func(users []User) ([]User, error)) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if err := u.reload(); err != nil {
		return err
	}
	cur := make([]User, 0, len(u.m))
	for _, x := range u.m {
		cur = append(cur, x)
	}
	sort.Slice(cur, func(i, j int) bool { return cur[i].Username < cur[j].Username })
	next, err := fn(cur)
	if err != nil {
		return err
	}
	admins := 0
	for _, x := range next {
		if x.Role == RoleAdmin {
			admins++
		}
	}
	if admins == 0 {
		return errors.New("en az bir yönetici kalmalı")
	}
	if err := SaveUsers(u.path, &UsersFile{Users: next}); err != nil {
		return fmt.Errorf("kullanıcı dosyası yazılamadı (%s): %w", u.path, err)
	}
	return u.reload()
}

// ---- pages ----

func (s *Server) admin(next func(http.ResponseWriter, *http.Request, *session)) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request, ss *session) {
		if ss.user.Role != RoleAdmin {
			http.NotFound(w, r)
			return
		}
		next(w, r, ss)
	})
}

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request, ss *session) {
	s.render(w, "users.html", s.page(r, ss, "users", map[string]any{
		"Users":   s.users.list(),
		"Me":      ss.user.Username,
		"Tenants": s.Cfg.TenantList(),
		"Path":    s.users.path,
	}))
}

func parseTenantList(r *http.Request) ([]string, error) {
	var out []string
	for _, t := range r.PostForm["tenants"] {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !config.IDPattern.MatchString(t) {
			return nil, fmt.Errorf("geçersiz müşteri %q", t)
		}
		out = append(out, t)
	}
	return out, nil
}

func (s *Server) userSave(w http.ResponseWriter, r *http.Request, ss *session) {
	name := strings.TrimSpace(r.PostFormValue("username"))
	role := r.PostFormValue("role")
	pw := r.PostFormValue("password")
	isNew := r.PostFormValue("new") == "1"
	tenants, err := parseTenantList(r)
	fail := func(msg string) { s.flash(w, r, "/admin/users", "", msg) }
	switch {
	case err != nil:
		fail(err.Error())
		return
	case !ValidUsername(name):
		fail("Kullanıcı adı 3-64 karakter olmalı: harf, rakam, . _ @ -")
		return
	case role != RoleAdmin && role != RoleTenant:
		fail("Rol yönetici ya da müşteri olmalı")
		return
	case role == RoleTenant && len(tenants) == 0:
		fail("Müşteri kullanıcısı için en az bir müşteri seçin")
		return
	}
	for _, t := range tenants {
		if _, ok := s.Cfg.Tenant(t); !ok {
			fail("Bilinmeyen müşteri: " + t)
			return
		}
	}
	if role == RoleAdmin {
		tenants = nil
	}
	var hash string
	if pw != "" || isNew {
		if hash, err = HashPassword(pw); err != nil {
			fail("Şifre en az 12 karakter olmalı")
			return
		}
	}
	err = s.users.update(func(us []User) ([]User, error) {
		for i := range us {
			if us[i].Username == name {
				if isNew {
					return nil, errors.New("bu kullanıcı adı zaten var")
				}
				us[i].Role, us[i].Tenants = role, tenants
				if hash != "" {
					us[i].PasswordHash = hash
				}
				return us, nil
			}
		}
		if !isNew {
			return nil, errors.New("kullanıcı bulunamadı")
		}
		return append(us, User{Username: name, PasswordHash: hash, Role: role, Tenants: tenants}), nil
	})
	if err != nil {
		fail(err.Error())
		return
	}
	ev := "user_update"
	if isNew {
		ev = "user_create"
	}
	s.audit(r, ss.user.Username, ev, "target", name, "role", role, "tenants", strings.Join(tenants, ","), "password_changed", hash != "")
	if hash != "" || !isNew {
		s.sess.deleteUser(name, sessionIDOf(r, s))
	}
	s.flash(w, r, "/admin/users", "Kullanıcı kaydedildi: "+name, "")
}

func (s *Server) userDelete(w http.ResponseWriter, r *http.Request, ss *session) {
	name := r.PostFormValue("username")
	if name == ss.user.Username {
		s.flash(w, r, "/admin/users", "", "Kendi hesabınızı silemezsiniz")
		return
	}
	err := s.users.update(func(us []User) ([]User, error) {
		out := us[:0]
		found := false
		for _, x := range us {
			if x.Username == name {
				found = true
				continue
			}
			out = append(out, x)
		}
		if !found {
			return nil, errors.New("kullanıcı bulunamadı")
		}
		return out, nil
	})
	if err != nil {
		s.flash(w, r, "/admin/users", "", err.Error())
		return
	}
	s.sess.deleteUser(name, "")
	s.audit(r, ss.user.Username, "user_delete", "target", name)
	s.flash(w, r, "/admin/users", "Kullanıcı silindi: "+name, "")
}

// accountPage lets every user change their own password.
func (s *Server) accountPage(w http.ResponseWriter, r *http.Request, ss *session) {
	s.render(w, "account.html", s.page(r, ss, "account", nil))
}

func (s *Server) accountPassword(w http.ResponseWriter, r *http.Request, ss *session) {
	cur, n1, n2 := r.PostFormValue("current"), r.PostFormValue("new"), r.PostFormValue("repeat")
	u, ok := s.users.get(ss.user.Username)
	if !ok || !CheckPassword(u.PasswordHash, cur) {
		s.audit(r, ss.user.Username, "password_change_failed")
		s.flash(w, r, "/account", "", "Mevcut şifre yanlış")
		return
	}
	if n1 != n2 {
		s.flash(w, r, "/account", "", "Yeni şifreler aynı değil")
		return
	}
	hash, err := HashPassword(n1)
	if err != nil {
		s.flash(w, r, "/account", "", "Şifre en az 12 karakter olmalı")
		return
	}
	err = s.users.update(func(us []User) ([]User, error) {
		for i := range us {
			if us[i].Username == u.Username {
				us[i].PasswordHash = hash
			}
		}
		return us, nil
	})
	if err != nil {
		s.flash(w, r, "/account", "", err.Error())
		return
	}
	// Other sessions of this user end; this one continues with the new hash.
	keep := sessionIDOf(r, s)
	s.sess.deleteUser(u.Username, keep)
	s.sess.setHash(keep, hash)
	s.audit(r, u.Username, "password_change")
	s.flash(w, r, "/account", "Şifreniz değiştirildi", "")
}

func sessionIDOf(r *http.Request, s *Server) string {
	if c, err := r.Cookie(s.cookieName()); err == nil {
		return c.Value
	}
	return ""
}
