package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/config"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/ingest"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/store"
)

const sourcesPath = "/admin/sources"

func (s *Server) sourcesPage(w http.ResponseWriter, r *http.Request, ss *session) {
	now := time.Now()
	type trow struct {
		T       config.Tenant
		License license
	}
	var rows []trow
	for _, t := range s.Cfg.TenantList() {
		rows = append(rows, trow{T: t, License: s.licenseOf(t, now)})
	}
	var unknown []ingest.UnknownSource
	if s.Unknown != nil {
		unknown = s.Unknown.List()
	}
	s.render(w, "sources.html", s.page(r, ss, "sources", map[string]any{
		"Rows": rows, "Unknown": unknown, "DefaultRetention": s.Cfg.DefaultRetention(),
		"Listen": s.Cfg.Listen, "Edit": r.URL.Query().Get("edit"),
	}))
}

// cleanText trims and bounds free text fields (names, labels).
func cleanText(s string, n int) (string, error) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > n || strings.ContainsAny(s, "\x00\r\n\t") {
		return "", fmt.Errorf("metin en fazla %d karakter olmalı", n)
	}
	return s, nil
}

func parseRetention(v string) (int, error) {
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < minRetention || n > maxRetention {
		return 0, fmt.Errorf("saklama süresi %d-%d gün olmalı", minRetention, maxRetention)
	}
	return n, nil
}

func parseLicense(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if !config.ValidDate(v) {
		return "", errors.New("lisans bitiş tarihi YYYY-AA-GG olmalı")
	}
	return v, nil
}

// tenantSave creates a panel tenant or edits a tenant's name (panel tenants
// only), retention and license date.
func (s *Server) tenantSave(w http.ResponseWriter, r *http.Request, ss *session) {
	id := strings.TrimSpace(r.PostFormValue("id"))
	isNew := r.PostFormValue("new") == "1"
	name, err := cleanText(r.PostFormValue("name"), 120)
	if err == nil && name == "" {
		err = errors.New("müşteri adı gerekli")
	}
	var ret int
	var lic string
	if err == nil {
		ret, err = parseRetention(r.PostFormValue("retention_days"))
	}
	if err == nil {
		lic, err = parseLicense(r.PostFormValue("license_until"))
	}
	if err == nil && !config.IDPattern.MatchString(id) {
		err = errors.New("kısa ad küçük harf, rakam, - ve _ olmalı (ör. lojistik-as)")
	}
	if err != nil {
		s.flash(w, r, sourcesPath, "", err.Error())
		return
	}
	var old *config.Tenant
	if t, ok := s.Cfg.Tenant(id); ok {
		old = t
	}
	now := time.Now().UTC().Format(time.RFC3339)
	err = s.Cfg.UpdatePanel(func(p *config.Panel) error {
		if isNew {
			if old != nil {
				return fmt.Errorf("%s kısa adı zaten kullanılıyor", id)
			}
			p.Tenants = append(p.Tenants, config.PanelTenant{ID: id, Name: name, RetentionDays: ret, LicenseUntil: lic, Created: now, CreatedBy: ss.user.Username})
			return nil
		}
		if old == nil {
			return errors.New("müşteri bulunamadı")
		}
		if old.Origin == "file" {
			if p.TenantSettings == nil {
				p.TenantSettings = map[string]config.TenantSettings{}
			}
			p.TenantSettings[id] = config.TenantSettings{RetentionDays: ret, LicenseUntil: lic}
			return nil
		}
		for i := range p.Tenants {
			if p.Tenants[i].ID == id {
				p.Tenants[i].Name, p.Tenants[i].RetentionDays, p.Tenants[i].LicenseUntil = name, ret, lic
			}
		}
		return nil
	})
	if err != nil {
		s.flash(w, r, sourcesPath, "", err.Error())
		return
	}
	kv := []any{"tenant", id, "name", name, "retention_days", ret, "license_until", lic}
	if old != nil {
		kv = append(kv, "old_retention_days", old.RetentionDays, "old_license_until", old.LicenseUntil)
	}
	if isNew {
		s.audit(r, ss.user.Username, "tenant_create", kv...)
		s.flash(w, r, sourcesPath+"#t-"+id, "Müşteri eklendi: "+name+". Şimdi firewall IP'sini ekleyin.", "")
		return
	}
	s.audit(r, ss.user.Username, "tenant_update", kv...)
	s.flash(w, r, sourcesPath+"#t-"+id, "Müşteri güncellendi: "+name, "")
}

// tenantDelete removes a panel tenant that has no stored data. Data is
// evidence: a tenant with logs cannot be deleted from the panel.
func (s *Server) tenantDelete(w http.ResponseWriter, r *http.Request, ss *session) {
	id := r.PostFormValue("id")
	t, ok := s.Cfg.Tenant(id)
	if !ok || !config.IDPattern.MatchString(id) {
		s.flash(w, r, sourcesPath, "", "Müşteri bulunamadı")
		return
	}
	if t.Origin != "panel" {
		s.flash(w, r, sourcesPath, "", "config.yaml'daki müşteri panelden silinemez")
		return
	}
	if dir, err := store.SafeJoin(s.Cfg.DataDir, id); err == nil {
		if ents, err := os.ReadDir(dir); err == nil && len(ents) > 0 { // #nosec G703 -- id validated, SafeJoin
			s.flash(w, r, sourcesPath, "", "Bu müşterinin saklanan logları var, silinemez. Yeni log gelmemesi için kaynaklarını kaldırın.")
			return
		}
	}
	err := s.Cfg.UpdatePanel(func(p *config.Panel) error {
		out := p.Tenants[:0]
		for _, x := range p.Tenants {
			if x.ID != id {
				out = append(out, x)
			}
		}
		p.Tenants = out
		src := p.Sources[:0]
		for _, x := range p.Sources {
			if x.Tenant != id {
				src = append(src, x)
			}
		}
		p.Sources = src
		return nil
	})
	if err != nil {
		s.flash(w, r, sourcesPath, "", err.Error())
		return
	}
	s.audit(r, ss.user.Username, "tenant_delete", "tenant", id)
	s.flash(w, r, sourcesPath, "Müşteri silindi: "+t.Name, "")
}

func (s *Server) sourceAdd(w http.ResponseWriter, r *http.Request, ss *session) {
	id := r.PostFormValue("tenant")
	raw := strings.TrimSpace(r.PostFormValue("source"))
	label, err := cleanText(r.PostFormValue("label"), 80)
	back := sourcesPath + "#t-" + id
	if err != nil {
		s.flash(w, r, back, "", err.Error())
		return
	}
	if _, ok := s.Cfg.Tenant(id); !ok {
		s.flash(w, r, sourcesPath, "", "Müşteri seçin")
		return
	}
	pr, err := config.ParseSource(raw)
	if err != nil || len(raw) > 64 {
		s.flash(w, r, back, "", "Geçersiz IP ya da ağ: "+raw+" (ör. 203.0.113.10 veya 198.51.100.0/28)")
		return
	}
	// A very wide network would capture other customers' firewalls.
	if (pr.Addr().Is4() && pr.Bits() < 16) || (!pr.Addr().Is4() && pr.Bits() < 32) {
		s.flash(w, r, back, "", "Ağ çok geniş: IPv4 için en az /16, IPv6 için en az /32 girin")
		return
	}
	err = s.Cfg.UpdatePanel(func(p *config.Panel) error {
		p.Sources = append(p.Sources, config.PanelSource{Tenant: id, Source: pr.String(), Label: label,
			Added: time.Now().UTC().Format(time.RFC3339), AddedBy: ss.user.Username})
		return nil
	})
	if err != nil {
		msg := err.Error()
		var oe *config.OverlapError
		if errors.As(err, &oe) {
			other := oe.Other
			if t, ok := s.Cfg.Tenant(oe.Other); ok {
				other = t.Name
			}
			msg = fmt.Sprintf("%s adresi, %s müşterisinin %s kaynağıyla çakışıyor. Bir adres yalnızca bir müşteriye ait olabilir.", oe.Source, other, oe.OtherSource)
		}
		s.flash(w, r, back, "", msg)
		return
	}
	if s.Unknown != nil {
		for _, u := range s.Unknown.List() {
			if pr.Contains(u.Addr) {
				s.Unknown.Forget(u.Addr)
			}
		}
	}
	s.audit(r, ss.user.Username, "source_add", "tenant", id, "source", pr.String(), "label", label)
	s.flash(w, r, back, "Kaynak eklendi: "+pr.String()+". Bu adresten gelen loglar hemen kabul edilir.", "")
}

func (s *Server) sourceRemove(w http.ResponseWriter, r *http.Request, ss *session) {
	id := r.PostFormValue("tenant")
	pr, err := netip.ParsePrefix(r.PostFormValue("source"))
	back := sourcesPath + "#t-" + id
	if err != nil {
		s.flash(w, r, back, "", "Geçersiz kaynak")
		return
	}
	found := false
	err = s.Cfg.UpdatePanel(func(p *config.Panel) error {
		out := p.Sources[:0]
		for _, x := range p.Sources {
			if x.Tenant == id && x.Source == pr.String() && !found {
				found = true
				continue
			}
			out = append(out, x)
		}
		p.Sources = out
		if !found {
			return errors.New("bu kaynak panelden eklenmemiş; config.yaml'daki kaynaklar orada değiştirilir")
		}
		return nil
	})
	if err != nil {
		s.flash(w, r, back, "", err.Error())
		return
	}
	s.audit(r, ss.user.Username, "source_remove", "tenant", id, "source", pr.String())
	s.flash(w, r, back, "Kaynak kaldırıldı: "+pr.String()+". Bu adresten gelen loglar artık kabul edilmez; saklanan loglar silinmez.", "")
}
