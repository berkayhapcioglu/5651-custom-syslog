package web

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/config"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/notify"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/notify/smtptest"
)

func TestAlertsMailOnceAndResolve(t *testing.T) {
	ts, _ := testServer(t)
	s := lastServer
	srv, err := smtptest.Start(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Addr)
	p, _ := strconv.Atoi(port)
	s.Mailer = &notify.Mailer{Cfg: config.Alerts{SMTPHost: host, SMTPPort: p, SMTPTLS: "none", From: "log@ornek.com.tr"}}

	// Recipients are set in the panel; a bad address is refused.
	c := client(ts)
	login(t, ts, c, "admin", testPassword)
	tok := csrfOf(t, c, ts.URL+"/admin/settings")
	post(t, c, ts.URL+"/admin/settings/alerts", url.Values{"csrf": {tok}, "emails": {"noc@ornek.com.tr\nkotu adres"}, "silent_hours": {"2"}})
	if len(s.Cfg.PanelCopy().Settings.AlertEmails) != 0 {
		t.Fatal("bad address saved")
	}
	post(t, c, ts.URL+"/admin/settings/alerts", url.Values{"csrf": {tok}, "emails": {"noc@ornek.com.tr"}, "silent_hours": {"2"}})
	if got := s.Cfg.PanelCopy().Settings.AlertEmails; len(got) != 1 {
		t.Fatalf("emails %v", got)
	}

	now := time.Now()
	s.Seen.Mark("musteri-a", "10.0.0.1", now.Add(-5*time.Hour))
	ctx := context.Background()
	s.checkAlerts(ctx, now)
	if n := len(srv.Messages()); n != 0 {
		t.Fatal("mailed on the first check")
	}
	s.checkAlerts(ctx, now.Add(time.Minute))
	s.checkAlerts(ctx, now.Add(2*time.Minute))
	msgs := srv.Messages()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "log gelmedi") {
		t.Fatalf("want one mail about silence, got %d", len(msgs))
	}
	// A restart does not mail it again.
	s.loadAlerts()
	s.checkAlerts(ctx, now.Add(3*time.Minute))
	if len(srv.Messages()) != 1 {
		t.Fatal("mailed again after restart")
	}
	// Logs come back: one "resolved" mail.
	s.Seen.Mark("musteri-a", "10.0.0.1", now.Add(4*time.Minute))
	s.checkAlerts(ctx, now.Add(4*time.Minute))
	msgs = srv.Messages()
	if len(msgs) != 2 || !strings.Contains(msgs[1], "=C3=BCzeldi") && !strings.Contains(msgs[1], "zeldi") {
		t.Fatalf("no resolved mail: %d", len(msgs))
	}
	// The settings page shows the history; the test button sends a mail.
	post(t, c, ts.URL+"/admin/settings/alerts/test", url.Values{"csrf": {tok}})
	if len(srv.Messages()) != 3 {
		t.Fatal("test mail not sent")
	}
	if _, body, _ := get(t, c, ts.URL+"/admin/settings"); !strings.Contains(body, "Son bildirimler") || !strings.Contains(body, "Deneme") {
		t.Fatal("history not shown")
	}
}
