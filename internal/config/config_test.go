package config

import (
	"net/netip"
	"strings"
	"testing"
)

const base = `
data_dir: /tmp/x
listen: {udp: ":514"}
timestamp: {mode: none}
`

func TestResolve(t *testing.T) {
	c, err := Parse([]byte(base + `
tenants:
  - {id: musteri-a, name: A, sources: [10.0.0.0/24, 192.0.2.7]}
  - {id: musteri-b, name: B, sources: ["2001:db8::/32"], retention_days: 365}
`))
	if err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{"10.0.0.9": "musteri-a", "192.0.2.7": "musteri-a", "::ffff:10.0.0.1": "musteri-a", "2001:db8::1": "musteri-b"} {
		if got, ok := c.Resolve(netip.MustParseAddr(in)); !ok || got != want {
			t.Errorf("%s -> %q %v", in, got, ok)
		}
	}
	if _, ok := c.Resolve(netip.MustParseAddr("8.8.8.8")); ok {
		t.Error("unknown source resolved")
	}
	if tb, _ := c.Tenant("musteri-b"); tb.RetentionDays != 365 {
		t.Error("tenant retention not kept")
	}
	if ta, _ := c.Tenant("musteri-a"); ta.RetentionDays != 730 {
		t.Error("default retention not 730")
	}
}

func TestRejects(t *testing.T) {
	for name, doc := range map[string]string{
		"traversal id":  base + "tenants: [{id: '../x', sources: [10.0.0.1]}]",
		"upper id":      base + "tenants: [{id: 'A', sources: [10.0.0.1]}]",
		"overlap":       base + "tenants: [{id: a, sources: [10.0.0.0/8]}, {id: b, sources: [10.1.0.0/16]}]",
		"duplicate":     base + "tenants: [{id: a}, {id: a}]",
		"unknown field": base + "bogus: 1",
		"web no tls":    base + "web: {listen: ':443', users_file: u}",
		"bad default":   base + "default_tenant: nope",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte(strings.Replace(base, "timestamp: {mode: none}", "timestamp: {mode: http}", 1))); err == nil {
		t.Error("http mode without url accepted")
	}
}
