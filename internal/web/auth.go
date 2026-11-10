package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"
)

// Roles.
const (
	RoleAdmin  = "admin"  // sees every tenant
	RoleTenant = "tenant" // sees only the listed tenants
)

// User is one web login.
type User struct {
	Username     string   `yaml:"username"`
	PasswordHash string   `yaml:"password_hash"`
	Role         string   `yaml:"role"`
	Tenants      []string `yaml:"tenants,omitempty"`
}

// UsersFile is the on-disk user list.
type UsersFile struct {
	Users []User `yaml:"users"`
}

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9._@-]{3,64}$`)

// ValidUsername reports whether s is an acceptable username.
func ValidUsername(s string) bool { return usernamePattern.MatchString(s) }

// LoadUsers reads and validates a users file.
func LoadUsers(path string) (map[string]User, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, err
	}
	var f UsersFile
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("users file: %w", err)
	}
	out := map[string]User{}
	for _, u := range f.Users {
		if !ValidUsername(u.Username) {
			return nil, fmt.Errorf("users file: bad username %q", u.Username)
		}
		if u.Role != RoleAdmin && u.Role != RoleTenant {
			return nil, fmt.Errorf("users file: user %s: role must be admin or tenant", u.Username)
		}
		if _, err := parseHash(u.PasswordHash); err != nil {
			return nil, fmt.Errorf("users file: user %s: %w", u.Username, err)
		}
		if _, dup := out[u.Username]; dup {
			return nil, fmt.Errorf("users file: duplicate user %s", u.Username)
		}
		out[u.Username] = u
	}
	return out, nil
}

// SaveUsers writes the users file with owner-only permissions.
func SaveUsers(path string, f *UsersFile) error {
	b, err := yaml.Marshal(f)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	// Keep the existing owner and mode (root:syslog5651 0640 after packaging)
	// so the service can still read the file after `sudo syslog5651 useradd`.
	if st, err := os.Stat(path); err == nil {
		if err := os.Chmod(tmp, st.Mode().Perm()); err != nil {
			return err
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			if err := os.Chown(tmp, int(sys.Uid), int(sys.Gid)); err != nil {
				return err
			}
		}
	}
	return os.Rename(tmp, path)
}

// Argon2id parameters (OWASP recommended minimum is m=19MiB,t=2; we use more).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	minPassword  = 12
)

// hashLimiter bounds concurrent argon2 runs so login floods cannot exhaust memory.
var hashLimiter = make(chan struct{}, 4)

// HashPassword returns a PHC-format argon2id hash.
func HashPassword(pw string) (string, error) {
	if len(pw) < minPassword {
		return "", fmt.Errorf("password must be at least %d characters", minPassword)
	}
	if len(pw) > 1024 {
		return "", errors.New("password too long")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

type phc struct {
	m, t    uint32
	p       uint8
	salt    []byte
	key     []byte
	version int
}

func parseHash(s string) (*phc, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, errors.New("password_hash is not argon2id")
	}
	h := &phc{}
	if _, err := fmt.Sscanf(parts[2], "v=%d", &h.version); err != nil || h.version != argon2.Version {
		return nil, errors.New("password_hash: bad version")
	}
	var p uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &h.m, &h.t, &p); err != nil {
		return nil, errors.New("password_hash: bad parameters")
	}
	if h.m < 19*1024 || h.m > 1024*1024 || h.t < 1 || h.t > 20 || p < 1 || p > 16 {
		return nil, errors.New("password_hash: parameters out of range")
	}
	h.p = uint8(p) // #nosec G115 -- range checked above
	var err error
	if h.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil || len(h.salt) < 16 {
		return nil, errors.New("password_hash: bad salt")
	}
	if h.key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(h.key) < 32 {
		return nil, errors.New("password_hash: bad key")
	}
	return h, nil
}

// dummyHash is checked for unknown users so timing does not reveal usernames.
var dummyHash, _ = HashPasswordForce("dummy-password-never-valid")

// HashPasswordForce hashes without the length policy (internal use).
func HashPasswordForce(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// CheckPassword verifies pw against a PHC hash in constant time.
func CheckPassword(hash, pw string) bool {
	if len(pw) > 1024 {
		return false
	}
	h, err := parseHash(hash)
	if err != nil {
		return false
	}
	hashLimiter <- struct{}{}
	defer func() { <-hashLimiter }()
	key := argon2.IDKey([]byte(pw), h.salt, h.t, h.m, h.p, uint32(len(h.key))) // #nosec G115 -- key length validated
	return subtle.ConstantTimeCompare(key, h.key) == 1
}

// limiter tracks failed logins per key (IP or username) with exponential lockout.
type limiter struct {
	mu   sync.Mutex
	fail map[string]*failState
}

type failState struct {
	count int
	until time.Time
	last  time.Time
}

const freeAttempts = 5

func newLimiter() *limiter { return &limiter{fail: map[string]*failState{}} }

// blocked reports whether key is locked out and for how long.
func (l *limiter) blocked(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.fail[key]
	if f == nil || !now.Before(f.until) {
		return false, 0
	}
	return true, f.until.Sub(now)
}

func (l *limiter) failure(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.fail[key]
	if f == nil || now.Sub(f.last) > 24*time.Hour {
		f = &failState{}
		l.fail[key] = f
	}
	f.count++
	f.last = now
	if f.count >= freeAttempts {
		d := time.Minute << min(f.count-freeAttempts, 10) // 1m, 2m, 4m ... ~17h
		f.until = now.Add(d)
	}
	if len(l.fail) > 100000 { // bound memory under a spray attack
		for k, v := range l.fail {
			if now.Sub(v.last) > time.Hour {
				delete(l.fail, k)
			}
		}
	}
}

func (l *limiter) success(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fail, key)
}

// randToken returns 32 random bytes, base64url encoded.
func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type session struct {
	user    User
	csrf    string
	expires time.Time
	created time.Time
}

type sessions struct {
	mu  sync.Mutex
	m   map[string]*session
	ttl time.Duration
}

func newSessions(ttl time.Duration) *sessions {
	return &sessions{m: map[string]*session{}, ttl: ttl}
}

func (s *sessions) create(u User, now time.Time) (string, *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if now.After(v.expires) {
			delete(s.m, k)
		}
	}
	id := randToken()
	ss := &session{user: u, csrf: randToken(), expires: now.Add(s.ttl), created: now}
	s.m[id] = ss
	return id, ss
}

func (s *sessions) get(id string, now time.Time) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	ss := s.m[id]
	if ss == nil {
		return nil
	}
	if now.After(ss.expires) {
		delete(s.m, id)
		return nil
	}
	return ss
}

func (s *sessions) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}
