package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// TenantSet is an immutable snapshot of all tenants. A new set replaces the
// old one atomically when an administrator changes tenants in the panel, so
// ingest and the web UI never need a restart.
type TenantSet struct {
	list   []Tenant
	byID   map[string]int
	defTen string
}

// Tenant returns a copy of the tenant with id.
func (s *TenantSet) Tenant(id string) (*Tenant, bool) {
	i, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	t := s.list[i]
	return &t, true
}

// List returns a copy of the tenants sorted by id.
func (s *TenantSet) List() []Tenant {
	out := make([]Tenant, len(s.list))
	copy(out, s.list)
	return out
}

// Resolve maps a source address to a tenant id.
func (s *TenantSet) Resolve(a netip.Addr) (string, bool) {
	a = a.Unmap()
	for i := range s.list {
		for _, p := range s.list[i].prefixes {
			if p.Contains(a) {
				return s.list[i].ID, true
			}
		}
	}
	if s.defTen != "" {
		return s.defTen, true
	}
	return "", false
}

// Panel holds everything changed from the web panel. It lives in
// <data_dir>/_panel/panel.json, because the service may only write there.
// config.yaml tenants stay read-only in the panel; the panel can add tenants,
// add sources to any tenant and override retention and license dates.
type Panel struct {
	Tenants        []PanelTenant             `json:"tenants"`
	Sources        []PanelSource             `json:"sources"`
	TenantSettings map[string]TenantSettings `json:"tenant_settings"`
	Settings       PanelSettings             `json:"settings"`
}

// PanelTenant is a tenant created in the panel.
type PanelTenant struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	RetentionDays int    `json:"retention_days,omitempty"`
	LicenseUntil  string `json:"license_until,omitempty"`
	Created       string `json:"created"`
	CreatedBy     string `json:"created_by"`
}

// PanelSource is a source network added in the panel.
type PanelSource struct {
	Tenant  string `json:"tenant"`
	Source  string `json:"source"`
	Label   string `json:"label,omitempty"`
	Added   string `json:"added"`
	AddedBy string `json:"added_by"`
}

// TenantSettings overrides values of a config.yaml tenant.
type TenantSettings struct {
	RetentionDays int    `json:"retention_days,omitempty"`
	LicenseUntil  string `json:"license_until,omitempty"`
}

// PanelSettings are service-wide settings that the panel may change.
type PanelSettings struct {
	DefaultRetentionDays int `json:"default_retention_days,omitempty"`
	LicenseWarnDays      int `json:"license_warn_days,omitempty"`
}

// PanelDir is the directory under data_dir that holds panel state.
const PanelDir = "_panel"

func (c *Config) panelPath() string { return filepath.Join(c.DataDir, PanelDir, "panel.json") }

// DefaultRetention is the retention for tenants without their own value.
func (c *Config) DefaultRetention() int {
	if p := c.PanelCopy(); p.Settings.DefaultRetentionDays > 0 {
		return p.Settings.DefaultRetentionDays
	}
	return c.RetentionDays
}

// LicenseWarnDays is how many days before expiry the panel starts warning.
func (c *Config) LicenseWarnDays() int {
	if p := c.PanelCopy(); p.Settings.LicenseWarnDays > 0 {
		return p.Settings.LicenseWarnDays
	}
	return 30
}

// LoadPanel reads panel state from data_dir and applies it. A missing file
// means no panel changes yet.
func (c *Config) LoadPanel() error {
	b, err := os.ReadFile(c.panelPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	p := &Panel{}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(p); err != nil {
		return fmt.Errorf("panel state %s: %w", c.panelPath(), err)
	}
	c.panelMu.Lock()
	defer c.panelMu.Unlock()
	ts, err := c.buildSet(p)
	if err != nil {
		return fmt.Errorf("panel state %s: %w", c.panelPath(), err)
	}
	c.set.Store(ts)
	c.panel = p
	return nil
}

// PanelCopy returns a deep copy of the current panel state.
func (c *Config) PanelCopy() *Panel {
	c.panelMu.Lock()
	defer c.panelMu.Unlock()
	return clonePanel(c.panel)
}

func clonePanel(p *Panel) *Panel {
	if p == nil {
		return &Panel{}
	}
	b, _ := json.Marshal(p)
	out := &Panel{}
	_ = json.Unmarshal(b, out)
	return out
}

// UpdatePanel applies fn to a copy of the panel state, validates the result
// together with config.yaml, saves it and swaps the live tenant set. Nothing
// changes if fn or the validation fails.
func (c *Config) UpdatePanel(fn func(p *Panel) error) error {
	c.panelMu.Lock()
	defer c.panelMu.Unlock()
	p := clonePanel(c.panel)
	if err := fn(p); err != nil {
		return err
	}
	ts, err := c.buildSet(p)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(c.panelPath())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := c.panelPath() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- under data_dir
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, c.panelPath()); err != nil {
		return err
	}
	c.set.Store(ts)
	c.panel = p
	return nil
}

// OverlapError reports two sources that would match the same address.
type OverlapError struct {
	Tenant, Other       string
	Source, OtherSource netip.Prefix
}

func (e *OverlapError) Error() string {
	return fmt.Sprintf("tenant %s: source %s overlaps tenant %s (%s)", e.Tenant, e.Source, e.Other, e.OtherSource)
}

// ValidDate reports whether s is a YYYY-MM-DD date.
func ValidDate(s string) bool {
	_, err := time.Parse("2006-01-02", s)
	return err == nil && len(s) == 10
}

// ParseSource parses an address or network as written in sources.
func ParseSource(s string) (netip.Prefix, error) { return parsePrefix(s) }

// buildSet merges config.yaml tenants with panel state and validates the
// result: ids, retention, license dates and that no two sources overlap.
func (c *Config) buildSet(p *Panel) (*TenantSet, error) {
	defRet := c.RetentionDays
	if p.Settings.DefaultRetentionDays > 0 {
		defRet = p.Settings.DefaultRetentionDays
	}
	var list []Tenant
	for _, ft := range c.Tenants {
		t := ft
		t.Origin = "file"
		t.Sources = append([]string(nil), ft.Sources...)
		t.SourceList, t.prefixes = nil, nil
		if t.RetentionDays == 0 {
			t.RetentionDays = defRet
		}
		if ov, ok := p.TenantSettings[t.ID]; ok {
			if ov.RetentionDays > 0 {
				t.RetentionDays = ov.RetentionDays
			}
			if ov.LicenseUntil != "" {
				t.LicenseUntil = ov.LicenseUntil
			}
		}
		for _, s := range ft.Sources {
			pr, err := parsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("tenant %s: source %q: %w", t.ID, s, err)
			}
			t.SourceList = append(t.SourceList, SourceInfo{Prefix: pr, Origin: "file"})
		}
		list = append(list, t)
	}
	for _, pt := range p.Tenants {
		t := Tenant{ID: pt.ID, Name: pt.Name, RetentionDays: pt.RetentionDays, LicenseUntil: pt.LicenseUntil, Origin: "panel"}
		if t.RetentionDays == 0 {
			t.RetentionDays = defRet
		}
		list = append(list, t)
	}
	idx := map[string]int{}
	for i, t := range list {
		if !IDPattern.MatchString(t.ID) {
			return nil, fmt.Errorf("tenant id %q: use lowercase letters, digits, - and _", t.ID)
		}
		if _, dup := idx[t.ID]; dup {
			return nil, fmt.Errorf("tenant id %q is duplicated", t.ID)
		}
		idx[t.ID] = i
		if t.RetentionDays < 1 {
			return nil, fmt.Errorf("tenant %s: retention_days must be >= 1", t.ID)
		}
		if t.LicenseUntil != "" && !ValidDate(t.LicenseUntil) {
			return nil, fmt.Errorf("tenant %s: license_until %q is not YYYY-MM-DD", t.ID, t.LicenseUntil)
		}
	}
	for id := range p.TenantSettings {
		if i, ok := idx[id]; !ok || list[i].Origin != "file" {
			return nil, fmt.Errorf("tenant_settings: %q is not a config.yaml tenant", id)
		}
	}
	for _, ps := range p.Sources {
		i, ok := idx[ps.Tenant]
		if !ok {
			return nil, fmt.Errorf("source %s: unknown tenant %q", ps.Source, ps.Tenant)
		}
		pr, err := parsePrefix(ps.Source)
		if err != nil {
			return nil, fmt.Errorf("tenant %s: source %q: %w", ps.Tenant, ps.Source, err)
		}
		list[i].Sources = append(list[i].Sources, pr.String())
		list[i].SourceList = append(list[i].SourceList, SourceInfo{Prefix: pr, Label: ps.Label, Origin: "panel", Added: ps.Added, AddedBy: ps.AddedBy})
	}
	type owned struct {
		p  netip.Prefix
		id string
	}
	var all []owned
	for i := range list {
		for _, si := range list[i].SourceList {
			for _, o := range all {
				if o.p.Overlaps(si.Prefix) {
					return nil, &OverlapError{Tenant: list[i].ID, Source: si.Prefix, Other: o.id, OtherSource: o.p}
				}
			}
			all = append(all, owned{si.Prefix, list[i].ID})
			list[i].prefixes = append(list[i].prefixes, si.Prefix)
		}
	}
	if c.DefaultTenant != "" {
		if _, ok := idx[c.DefaultTenant]; !ok {
			return nil, fmt.Errorf("default_tenant %q is not a configured tenant", c.DefaultTenant)
		}
	}
	sort.Slice(list, func(a, b int) bool { return list[a].ID < list[b].ID })
	byID := map[string]int{}
	for i, t := range list {
		byID[t.ID] = i
	}
	return &TenantSet{list: list, byID: byID, defTen: c.DefaultTenant}, nil
}
