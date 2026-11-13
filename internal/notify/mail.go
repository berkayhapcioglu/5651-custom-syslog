// Package notify sends alert e-mails.
package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/config"
)

// Mailer sends plain-text UTF-8 mails through the configured SMTP server.
type Mailer struct {
	Cfg config.Alerts
	// RootCAs overrides the system roots (tests).
	RootCAs *x509.CertPool
	Timeout time.Duration
}

// Enabled reports whether a mail server is configured.
func (m *Mailer) Enabled() bool { return m != nil && m.Cfg.SMTPHost != "" }

// ValidAddress reports whether s is a single plain e-mail address.
func ValidAddress(s string) bool {
	a, err := mail.ParseAddress(s)
	return err == nil && a.Name == "" && a.Address == s && len(s) <= 254 && !strings.ContainsAny(s, "\r\n")
}

// Send mails subject and body to the recipients.
func (m *Mailer) Send(ctx context.Context, to []string, subject, body string) error {
	if !m.Enabled() {
		return errors.New("e-posta sunucusu tanımlı değil (config.yaml: alerts)")
	}
	if len(to) == 0 {
		return errors.New("alıcı yok")
	}
	for _, a := range to {
		if !ValidAddress(a) {
			return fmt.Errorf("geçersiz alıcı: %q", a)
		}
	}
	from, err := mail.ParseAddress(m.Cfg.From)
	if err != nil {
		return err
	}
	msg, err := build(from, to, subject, body)
	if err != nil {
		return err
	}
	timeout := m.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addr := net.JoinHostPort(m.Cfg.SMTPHost, strconv.Itoa(m.Cfg.SMTPPort))
	tc := &tls.Config{ServerName: m.Cfg.SMTPHost, MinVersion: tls.VersionTLS12}
	tc.RootCAs = m.RootCAs
	d := &net.Dialer{}
	var conn net.Conn
	if m.Cfg.SMTPTLS == "tls" {
		conn, err = (&tls.Dialer{NetDialer: d, Config: tc}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, m.Cfg.SMTPHost)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if m.Cfg.SMTPTLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("sunucu STARTTLS desteklemiyor; şifresiz gönderim yapılmaz")
		}
		if err := c.StartTLS(tc); err != nil {
			return err
		}
	}
	if m.Cfg.Username != "" {
		pw, err := os.ReadFile(m.Cfg.PasswordFile) // #nosec G304 -- operator-configured secret file
		if err != nil {
			return fmt.Errorf("smtp şifre dosyası: %w", err)
		}
		if err := c.Auth(smtp.PlainAuth("", m.Cfg.Username, strings.TrimSpace(string(pw)), m.Cfg.SMTPHost)); err != nil {
			return err
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	for _, a := range to {
		if err := c.Rcpt(a); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func build(from *mail.Address, to []string, subject, body string) ([]byte, error) {
	var id [12]byte
	_, _ = rand.Read(id[:])
	host := "syslog5651"
	if _, d, ok := strings.Cut(from.Address, "@"); ok {
		host = d
	}
	clean := func(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", from.String())
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", clean(subject)))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", hex.EncodeToString(id[:]), host)
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\nAuto-Submitted: auto-generated\r\n\r\n")
	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n"))); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	b.WriteString("\r\n")
	return b.Bytes(), nil
}
