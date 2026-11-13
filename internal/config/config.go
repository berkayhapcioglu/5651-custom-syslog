// Package config loads and validates the service configuration.
package config

import (
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level service configuration.
type Config struct {
	DataDir  string `yaml:"data_dir"`
	Timezone string `yaml:"timezone"`

	Listen      Listen      `yaml:"listen"`
	Compression Compression `yaml:"compression"`
	Timestamp   Timestamp   `yaml:"timestamp"`
	Web         Web         `yaml:"web"`
	Alerts      Alerts      `yaml:"alerts"`

	// RetentionDays is the default retention for tenants that do not set one.
	RetentionDays int `yaml:"retention_days"`
	// DayGrace is how long after midnight a day is sealed, to let late files close.
	DayGrace Duration `yaml:"day_grace"`
	// MaxMessageBytes caps a single syslog message; longer messages are truncated.
	MaxMessageBytes int `yaml:"max_message_bytes"`

	// DefaultTenant receives logs from sources that match no tenant.
	// Empty means such logs are dropped (and counted).
	DefaultTenant string   `yaml:"default_tenant"`
	Tenants       []Tenant `yaml:"tenants"`

	loc *time.Location

	// set is the live tenant set: file tenants merged with panel changes.
	set     atomic.Pointer[TenantSet]
	panelMu sync.Mutex
	panel   *Panel
}

// Listen holds the syslog listener addresses. An empty address disables it.
type Listen struct {
	UDP string `yaml:"udp"`
	TCP string `yaml:"tcp"`
	TLS string `yaml:"tls"`

	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	// TLSClientCA, when set, requires and verifies client certificates.
	TLSClientCA string `yaml:"tls_client_ca"`

	// MaxTCPConns caps concurrent TCP+TLS connections.
	MaxTCPConns int `yaml:"max_tcp_conns"`
	// MaxTCPConnsPerSource caps the connections of one source address, so a
	// single device cannot use up the slots of all others.
	MaxTCPConnsPerSource int `yaml:"max_tcp_conns_per_source"`
	// TCPIdleTimeout closes TCP connections that send nothing for this long.
	TCPIdleTimeout Duration `yaml:"tcp_idle_timeout"`
}

// Compression selects how sealed hourly files are compressed.
type Compression struct {
	// Codec of each column stream: "xz" (default, best ratio) or "zstd" (faster).
	Codec string `yaml:"codec"`
	// XZCommand is the external xz binary; empty uses the built-in encoder.
	XZCommand string `yaml:"xz_command"`
	// Workers is the number of files compressed in parallel.
	Workers int `yaml:"workers"`
}

// Timestamp configures the RFC 3161 time stamp authority.
type Timestamp struct {
	// Mode: "http" (RFC 3161 over HTTP), "exec" (external client, e.g. the
	// KamuSM client) or "none" (testing only; days are sealed without a stamp).
	Mode string `yaml:"mode"`

	URL      string `yaml:"url"`
	Username string `yaml:"username"`
	// PasswordFile holds the HTTP basic-auth password (never put secrets in this file).
	PasswordFile string            `yaml:"password_file"`
	Headers      map[string]string `yaml:"headers"`
	Policy       string            `yaml:"policy"`
	Timeout      Duration          `yaml:"timeout"`

	// Command runs for exec mode. {data} is replaced with the manifest path and
	// {out} with the path the .tsr response must be written to.
	Command []string `yaml:"command"`

	// CAFile is used by `verify` to check the TSA signature with openssl.
	CAFile string `yaml:"ca_file"`
}

// Web configures the management interface.
type Web struct {
	// Listen address; empty disables the web UI.
	Listen  string `yaml:"listen"`
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	// UsersFile holds users and argon2id password hashes (see `syslog5651 useradd`).
	UsersFile string `yaml:"users_file"`
	// SessionTTL is how long a login stays valid.
	SessionTTL Duration `yaml:"session_ttl"`
	// AllowInsecureHTTP permits plain HTTP; only for local testing behind a TLS proxy.
	AllowInsecureHTTP bool `yaml:"allow_insecure_http"`
}

// Alerts configures the mail server for alert e-mails. Recipients and
// thresholds are set in the panel.
type Alerts struct {
	SMTPHost string `yaml:"smtp_host"`
	SMTPPort int    `yaml:"smtp_port"`
	// SMTPTLS: "starttls" (default, port 587), "tls" (port 465) or "none"
	// (only for a mail relay on this machine).
	SMTPTLS  string `yaml:"smtp_tls"`
	Username string `yaml:"username"`
	// PasswordFile holds the SMTP password (never put secrets in this file).
	PasswordFile string `yaml:"password_file"`
	From         string `yaml:"from"`
}

// Tenant is one customer.
type Tenant struct {
	ID            string   `yaml:"id"`
	Name          string   `yaml:"name"`
	Sources       []string `yaml:"sources"`
	RetentionDays int      `yaml:"retention_days"`
	// LicenseUntil is the last day (YYYY-MM-DD) of the customer's license.
	// It only drives warnings; logs are never refused because of it.
	LicenseUntil string `yaml:"license_until"`

	// Filled in by the tenant set; not read from YAML.
	Origin     string       `yaml:"-"` // "file" (config.yaml) or "panel"
	SourceList []SourceInfo `yaml:"-"`
	prefixes   []netip.Prefix
}

// SourceInfo is one source network of a tenant with its metadata.
type SourceInfo struct {
	Prefix  netip.Prefix
	Label   string
	Origin  string // "file" or "panel"
	Added   string
	AddedBy string
}

// Prefixes returns the parsed source networks.
func (t *Tenant) Prefixes() []netip.Prefix { return t.prefixes }

// Duration is a time.Duration that unmarshals from strings like "10m".
type Duration struct{ time.Duration }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// IDPattern is the allowed form of tenant ids; ids become directory names,
// so this is a security boundary against path traversal.
var IDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// Load reads, defaults and validates a config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path
	if err != nil {
		return nil, err
	}
	c, err := Parse(b)
	if err != nil {
		return nil, err
	}
	// Tenants and settings changed in the web panel.
	if err := c.LoadPanel(); err != nil {
		return nil, err
	}
	return c, nil
}

// Parse defaults and validates a config document.
func Parse(b []byte) (*Config, error) {
	c := &Config{}
	dec := yaml.NewDecoder(bytesReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.defaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return c, nil
}

func (c *Config) defaults() {
	if c.Timezone == "" {
		c.Timezone = "Europe/Istanbul"
	}
	if c.RetentionDays == 0 {
		c.RetentionDays = 730
	}
	if c.DayGrace.Duration == 0 {
		c.DayGrace.Duration = 10 * time.Minute
	}
	if c.MaxMessageBytes == 0 {
		c.MaxMessageBytes = 16 * 1024
	}
	if c.Listen.MaxTCPConns == 0 {
		c.Listen.MaxTCPConns = 1024
	}
	if c.Listen.MaxTCPConnsPerSource == 0 {
		c.Listen.MaxTCPConnsPerSource = 32
	}
	if c.Listen.TCPIdleTimeout.Duration == 0 {
		c.Listen.TCPIdleTimeout.Duration = 15 * time.Minute
	}
	if c.Compression.Codec == "" {
		c.Compression.Codec = "xz"
	}
	if c.Compression.Workers == 0 {
		c.Compression.Workers = 2
	}
	if c.Timestamp.Timeout.Duration == 0 {
		c.Timestamp.Timeout.Duration = 30 * time.Second
	}
	if c.Alerts.SMTPTLS == "" {
		c.Alerts.SMTPTLS = "starttls"
	}
	if c.Alerts.SMTPPort == 0 {
		c.Alerts.SMTPPort = map[string]int{"tls": 465, "none": 25}[c.Alerts.SMTPTLS]
		if c.Alerts.SMTPPort == 0 {
			c.Alerts.SMTPPort = 587
		}
	}
	if c.Web.SessionTTL.Duration == 0 {
		c.Web.SessionTTL.Duration = 8 * time.Hour
	}
}

func (c *Config) validate() error {
	if c.DataDir == "" {
		return errors.New("data_dir is required")
	}
	loc, err := time.LoadLocation(c.Timezone)
	if err != nil {
		return fmt.Errorf("timezone: %w", err)
	}
	c.loc = loc
	if c.RetentionDays < 1 {
		return errors.New("retention_days must be >= 1")
	}
	if c.MaxMessageBytes < 512 || c.MaxMessageBytes > 1<<20 {
		return errors.New("max_message_bytes must be between 512 and 1048576")
	}
	if c.Listen.UDP == "" && c.Listen.TCP == "" && c.Listen.TLS == "" {
		return errors.New("at least one of listen.udp, listen.tcp, listen.tls is required")
	}
	if c.Listen.TLS != "" && (c.Listen.TLSCert == "" || c.Listen.TLSKey == "") {
		return errors.New("listen.tls needs tls_cert and tls_key")
	}
	switch c.Compression.Codec {
	case "xz", "zstd":
	default:
		return fmt.Errorf("compression.codec %q: want xz or zstd", c.Compression.Codec)
	}
	switch c.Timestamp.Mode {
	case "http":
		if c.Timestamp.URL == "" {
			return errors.New("timestamp.url is required for http mode")
		}
	case "exec":
		if len(c.Timestamp.Command) == 0 {
			return errors.New("timestamp.command is required for exec mode")
		}
	case "none":
	default:
		return fmt.Errorf("timestamp.mode %q: want http, exec or none", c.Timestamp.Mode)
	}
	if c.Web.Listen != "" {
		if c.Web.UsersFile == "" {
			return errors.New("web.users_file is required when web.listen is set")
		}
		if !c.Web.AllowInsecureHTTP && (c.Web.TLSCert == "" || c.Web.TLSKey == "") {
			return errors.New("web needs tls_cert and tls_key (or allow_insecure_http for testing)")
		}
	}
	if a := c.Alerts; a.SMTPHost != "" {
		if _, err := mail.ParseAddress(a.From); err != nil {
			return fmt.Errorf("alerts.from: %w", err)
		}
		switch a.SMTPTLS {
		case "starttls", "tls":
		case "none":
			if h := strings.ToLower(a.SMTPHost); h != "localhost" && h != "127.0.0.1" && h != "::1" {
				return errors.New("alerts.smtp_tls none is only allowed for a mail relay on localhost")
			}
		default:
			return fmt.Errorf("alerts.smtp_tls %q: want starttls, tls or none", a.SMTPTLS)
		}
		if a.SMTPPort < 1 || a.SMTPPort > 65535 {
			return errors.New("alerts.smtp_port is out of range")
		}
		if (a.Username == "") != (a.PasswordFile == "") {
			return errors.New("alerts.username and alerts.password_file go together")
		}
	}

	ts, err := c.buildSet(&Panel{})
	if err != nil {
		return err
	}
	c.set.Store(ts)
	c.panel = &Panel{}
	return nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Location returns the configured time zone.
func (c *Config) Location() *time.Location { return c.loc }

// Tenant returns a copy of the tenant with the given id.
func (c *Config) Tenant(id string) (*Tenant, bool) { return c.set.Load().Tenant(id) }

// TenantList returns the current tenants, sorted by id.
func (c *Config) TenantList() []Tenant { return c.set.Load().List() }

// Resolve maps a source address to a tenant id; ok is false when the
// source is unknown and no default tenant is set.
func (c *Config) Resolve(a netip.Addr) (string, bool) { return c.set.Load().Resolve(a) }
