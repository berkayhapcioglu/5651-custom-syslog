package notify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"mime/quotedprintable"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/config"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/notify/smtptest"
)

func mailer(t *testing.T, addr, mode string) *Mailer {
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	return &Mailer{Cfg: config.Alerts{SMTPHost: host, SMTPPort: p, SMTPTLS: mode, From: "Log <log@ornek.com.tr>"}}
}

func TestSendPlainLocal(t *testing.T) {
	srv, err := smtptest.Start(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	m := mailer(t, srv.Addr, "none")
	if err := m.Send(context.Background(), []string{"noc@ornek.com.tr"}, "Müşteri: log gelmedi\r\nBcc: x@y", "Satır 1\nŞüphe ğ"); err != nil {
		t.Fatal(err)
	}
	msgs := srv.Messages()
	if len(msgs) != 1 {
		t.Fatalf("%d messages", len(msgs))
	}
	head, body, _ := strings.Cut(msgs[0], "\r\n\r\n")
	if strings.Contains(head, "\r\nBcc:") || !strings.Contains(head, "Subject: =?utf-8?q?") {
		t.Fatalf("header injection or bad subject: %s", head)
	}
	dec, _ := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
	if !strings.Contains(string(dec), "Şüphe ğ") {
		t.Fatalf("body: %q", dec)
	}
}

func TestStartTLSRequired(t *testing.T) {
	plain, _ := smtptest.Start(nil)
	defer plain.Close()
	if err := mailer(t, plain.Addr, "starttls").Send(context.Background(), []string{"a@b.co"}, "s", "b"); err == nil {
		t.Fatal("sent without TLS")
	}
	ts := httptest.NewTLSServer(nil) // borrow a certificate for 127.0.0.1
	defer ts.Close()
	cert := ts.TLS.Certificates[0]
	srv, _ := smtptest.Start(&tls.Config{Certificates: []tls.Certificate{cert}})
	defer srv.Close()
	m := mailer(t, srv.Addr, "starttls")
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	m.RootCAs = pool
	if err := m.Send(context.Background(), []string{"a@b.co"}, "s", "b"); err != nil {
		t.Fatal(err)
	}
	if len(srv.Messages()) != 1 {
		t.Fatal("not delivered over STARTTLS")
	}
}

func TestValidAddress(t *testing.T) {
	for s, want := range map[string]bool{"a@b.co": true, "Ali <a@b.co>": false, "a@b.co\r\nBcc: x": false, "x": false} {
		if ValidAddress(s) != want {
			t.Errorf("%q", s)
		}
	}
}
