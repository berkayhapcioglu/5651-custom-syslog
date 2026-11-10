package store

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/tsa"
)

// TestDemoData fills DEMO_DIR with two sealed past days of realistic looking
// firewall logs for UI screenshots and manual trials. Skipped by default.
func TestDemoData(t *testing.T) {
	root := os.Getenv("DEMO_DIR")
	if root == "" {
		t.Skip("DEMO_DIR not set")
	}
	r := rand.New(rand.NewSource(7))
	now := time.Now().In(ist())
	for _, tenant := range []string{"musteri-a", "musteri-b"} {
		for back := 3; back >= 1; back-- {
			day := time.Date(now.Year(), now.Month(), now.Day()-back, 0, 0, 0, 0, ist())
			w := NewWriter(root, ist(), quiet, nil)
			stop, done := make(chan struct{}), make(chan struct{})
			go func() { w.Run(stop); close(done) }()
			for h := 8; h < 12; h++ {
				for i := 0; i < 4000; i++ {
					ts := day.Add(time.Duration(h)*time.Hour + time.Duration(i)*900*time.Millisecond)
					dev := "10.0.0.1"
					if tenant == "musteri-b" {
						dev = "10.0.1.1"
					}
					w.In <- Record{Received: ts, Source: netip.MustParseAddr(dev), Tenant: tenant, Message: []byte(fmt.Sprintf(
						`<189>date=%s time=%s devname="FGT60F" devid="FGT60FTK22090001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=%d srcip=192.168.1.%d srcport=%d srcintf="internal" dstip=%d.%d.%d.%d dstport=%d dstintf="wan1" proto=6 action="%s" policyid=%d service="%s" duration=%d sentbyte=%d rcvdbyte=%d`,
						ts.Format("2006-01-02"), ts.Format("15:04:05"), ts.UnixNano(), 10+r.Intn(40), 30000+r.Intn(30000),
						[]int{142, 172, 31, 104}[r.Intn(4)], 250, r.Intn(4), 1+r.Intn(20), []int{443, 443, 443, 80, 53}[r.Intn(5)],
						[]string{"accept", "accept", "close", "deny"}[r.Intn(4)], 1+r.Intn(5), []string{"HTTPS", "HTTP", "DNS"}[r.Intn(3)],
						r.Intn(120), 100+r.Intn(5000), 100+r.Intn(90000)))}
				}
			}
			close(stop)
			<-done
		}
	}
	fake, _ := tsa.NewFake()
	ds := &DaySealer{Root: root, Loc: ist(), Stamper: fake, Sealer: newSealer(root), Log: quiet,
		Tenants: func() []string { return []string{"musteri-a", "musteri-b"} }}
	ds.SealDue(context.Background())
}
