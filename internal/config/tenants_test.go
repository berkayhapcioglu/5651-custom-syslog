package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func panelCfg(t *testing.T, dir string) *Config {
	t.Helper()
	c, err := Parse([]byte(`
data_dir: ` + dir + `
listen: {udp: ":514"}
timestamp: {mode: none}
tenants:
  - {id: musteri-a, name: A, sources: [10.0.0.0/24]}
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.LoadPanel(); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPanelMergeAndPersist(t *testing.T) {
	dir := t.TempDir()
	c := panelCfg(t, dir)
	err := c.UpdatePanel(func(p *Panel) error {
		p.Tenants = append(p.Tenants, PanelTenant{ID: "yeni", Name: "Yeni", LicenseUntil: "2027-01-01"})
		p.Sources = append(p.Sources, PanelSource{Tenant: "yeni", Source: "203.0.113.0/28", Label: "FW"})
		p.TenantSettings = map[string]TenantSettings{"musteri-a": {RetentionDays: 1000}}
		p.Settings.DefaultRetentionDays = 800
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	check := func(c *Config) {
		t.Helper()
		if id, ok := c.Resolve(netip.MustParseAddr("203.0.113.5")); !ok || id != "yeni" {
			t.Fatalf("panel source not live: %q", id)
		}
		if a, _ := c.Tenant("musteri-a"); a.RetentionDays != 1000 || a.Origin != "file" {
			t.Fatalf("file tenant override: %+v", a)
		}
		if y, _ := c.Tenant("yeni"); y.RetentionDays != 800 || y.LicenseUntil != "2027-01-01" || y.Origin != "panel" {
			t.Fatalf("panel tenant: %+v", y)
		}
	}
	check(c)
	check(panelCfg(t, dir)) // after a restart
	if st, _ := os.Stat(filepath.Join(dir, PanelDir, "panel.json")); st.Mode().Perm() != 0o600 {
		t.Fatalf("panel.json mode %v", st.Mode())
	}
}

func TestPanelRejects(t *testing.T) {
	dir := t.TempDir()
	c := panelCfg(t, dir)
	for name, fn := range map[string]func(p *Panel) error{
		"overlap": func(p *Panel) error {
			p.Tenants = append(p.Tenants, PanelTenant{ID: "x", Name: "X"})
			p.Sources = append(p.Sources, PanelSource{Tenant: "x", Source: "10.0.0.7/32"})
			return nil
		},
		"duplicate id": func(p *Panel) error {
			p.Tenants = append(p.Tenants, PanelTenant{ID: "musteri-a", Name: "A"})
			return nil
		},
		"bad id": func(p *Panel) error { p.Tenants = append(p.Tenants, PanelTenant{ID: "../x", Name: "X"}); return nil },
		"unknown tenant": func(p *Panel) error {
			p.Sources = append(p.Sources, PanelSource{Tenant: "yok", Source: "198.51.100.1"})
			return nil
		},
		"bad license": func(p *Panel) error {
			p.Tenants = append(p.Tenants, PanelTenant{ID: "x", Name: "X", LicenseUntil: "31.12.2027"})
			return nil
		},
		"settings for panel tenant": func(p *Panel) error {
			p.TenantSettings = map[string]TenantSettings{"yok": {RetentionDays: 400}}
			return nil
		},
	} {
		if err := c.UpdatePanel(fn); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if len(c.TenantList()) != 1 {
		t.Fatal("rejected change leaked into the live set")
	}
	if _, err := os.Stat(filepath.Join(dir, PanelDir, "panel.json")); err == nil {
		t.Fatal("rejected change was saved")
	}
	// Unknown fields in the saved file are refused at start.
	os.MkdirAll(filepath.Join(dir, PanelDir), 0o700)
	os.WriteFile(filepath.Join(dir, PanelDir, "panel.json"), []byte(`{"tenantz":[]}`), 0o600)
	c2, _ := Parse([]byte(strings.Replace(`data_dir: D
listen: {udp: ":514"}
timestamp: {mode: none}
`, "D", dir, 1)))
	if err := c2.LoadPanel(); err == nil {
		t.Fatal("unknown panel field accepted")
	}
}
