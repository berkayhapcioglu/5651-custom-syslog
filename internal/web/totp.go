package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 TOTP uses HMAC-SHA1; authenticator apps expect it
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"html/template"
	"net/url"
	"strings"
	"sync"
	"time"

	"rsc.io/qr"
)

// Two-step login with a time-based one-time code (RFC 6238: 30 s steps,
// 6 digits, HMAC-SHA1), as used by Google/Microsoft Authenticator.

const (
	totpStep   = 30
	totpDigits = 6
	totpIssuer = "5651 Log"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// newTOTPSecret returns a random 160-bit secret in base32.
func newTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return b32.EncodeToString(b)
}

func validTOTPSecret(s string) bool {
	b, err := b32.DecodeString(s)
	return err == nil && len(b) >= 16
}

func totpCode(secret string, counter uint64) (string, error) {
	key, err := b32.DecodeString(secret)
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, v%1000000), nil
}

// totpMatch checks code against the steps around now and returns the
// matching step, so a code cannot be used twice.
func totpMatch(secret, code string, now time.Time) (uint64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	cur := uint64(now.Unix()) / totpStep // #nosec G115 -- time after 1970
	for _, c := range []uint64{cur, cur - 1, cur + 1} {
		want, err := totpCode(secret, c)
		if err == nil && hmac.Equal([]byte(want), []byte(code)) {
			return c, true
		}
	}
	return 0, false
}

// usedSteps remembers the last accepted step per user (replay protection).
type usedSteps struct {
	mu sync.Mutex
	m  map[string]uint64
}

// use accepts step for user only if it is newer than the last accepted one.
func (u *usedSteps) use(user string, step uint64) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.m == nil {
		u.m = map[string]uint64{}
	}
	if step <= u.m[user] {
		return false
	}
	u.m[user] = step
	return true
}

// checkTOTP verifies a code for user and consumes it.
func (s *Server) checkTOTP(user, secret, code string) bool {
	step, ok := totpMatch(secret, code, time.Now())
	return ok && s.steps.use(user, step)
}

func totpURL(user, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", totpIssuer)
	v.Set("digits", "6")
	v.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape(totpIssuer+":"+user) + "?" + v.Encode()
}

// qrSVG draws text as an inline SVG QR code (no JavaScript, CSP friendly).
func qrSVG(text string) template.HTML {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return ""
	}
	const q = 4 // quiet zone
	n := c.Size + 2*q
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="qr" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="220" height="220" role="img" aria-label="QR kodu" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n, n, n)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Black(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+q, y+q)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return template.HTML(b.String()) // #nosec G203 -- generated markup, no user text
}

// groupSecret shows the secret in groups of four for manual entry.
func groupSecret(s string) string {
	var parts []string
	for len(s) > 4 {
		parts = append(parts, s[:4])
		s = s[4:]
	}
	return strings.Join(append(parts, s), " ")
}
