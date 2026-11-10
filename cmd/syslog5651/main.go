// Command syslog5651 collects firewall syslog, stores it compressed and
// sealed with RFC 3161 time stamps for Turkish Law 5651, and serves a web UI.
//
// Usage:
//
//	syslog5651 run       -config /etc/syslog5651/config.yaml
//	syslog5651 verify    -config ... -tenant musteri-a -day 2026-11-10
//	syslog5651 seal-day  -config ... -tenant musteri-a -day 2026-11-10
//	syslog5651 useradd   -name ali -role tenant -tenants musteri-a
//	syslog5651 version
package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/colz"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/config"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/ingest"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/store"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/tsa"
	"github.com/berkayhapcioglu/5651-custom-syslog/internal/web"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "seal-day":
		err = cmdSealDay(os.Args[2:])
	case "useradd":
		err = cmdUserAdd(os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: syslog5651 run|verify|seal-day|useradd|version [flags]")
	os.Exit(2)
}

func logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func codec(c *config.Config, log *slog.Logger) colz.Codec {
	if c.Compression.Codec == "zstd" {
		return colz.Zstd{}
	}
	cmd := c.Compression.XZCommand
	if cmd == "" {
		if p, err := exec.LookPath("xz"); err == nil {
			cmd = p
		}
	}
	if cmd == "" {
		// The pure-Go xz encoder compresses worse than zstd; prefer zstd then.
		log.Warn("xz binary not found, using built-in zstd (install xz for the best ratio)")
		return colz.Zstd{}
	}
	return colz.XZ{Command: cmd}
}

func stamper(c *config.Config) (tsa.Stamper, error) {
	switch c.Timestamp.Mode {
	case "http":
		h := &tsa.HTTP{
			URL: c.Timestamp.URL, Username: c.Timestamp.Username, Headers: c.Timestamp.Headers,
			Policy: c.Timestamp.Policy, Client: &http.Client{Timeout: c.Timestamp.Timeout.Duration},
		}
		if c.Timestamp.PasswordFile != "" {
			b, err := os.ReadFile(c.Timestamp.PasswordFile)
			if err != nil {
				return nil, err
			}
			h.Password = strings.TrimSpace(string(b))
		}
		return h, nil
	case "exec":
		return &tsa.Exec{Command: c.Timestamp.Command, Timeout: c.Timestamp.Timeout.Duration}, nil
	}
	return nil, nil
}

func roots(c *config.Config) (*x509.CertPool, error) {
	if c.Timestamp.CAFile == "" {
		return nil, nil
	}
	return tsa.LoadRoots(c.Timestamp.CAFile)
}

func tenantIDs(c *config.Config) []string {
	tl := c.TenantList()
	ids := make([]string, len(tl))
	for i, t := range tl {
		ids[i] = t.ID
	}
	return ids
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/syslog5651/config.yaml", "config file")
	fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	log := logger()
	if os.Geteuid() == 0 {
		log.Warn("running as root is not recommended; use the provided systemd unit (CAP_NET_BIND_SERVICE)")
	}
	if cfg.Timestamp.Mode == "none" {
		log.Warn("timestamp.mode is none: days are sealed WITHOUT a time stamp; not 5651 compliant")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := stamper(cfg)
	if err != nil {
		return err
	}
	rp, err := roots(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sealer := &store.Sealer{Root: cfg.DataDir, Codec: codec(cfg, log), Log: log}
	jobs := make(chan string, 4096)
	var sealWG sync.WaitGroup
	for i := 0; i < cfg.Compression.Workers; i++ {
		sealWG.Add(1)
		go func() {
			defer sealWG.Done()
			for p := range jobs {
				if err := sealer.SealHour(p); err != nil {
					log.Error("seal hour", "file", p, "err", err)
				}
			}
		}()
	}
	// Seal what a previous run left behind.
	pending, err := store.PendingRaw(cfg.DataDir, time.Now(), cfg.Location())
	if err != nil {
		return err
	}
	for _, p := range pending {
		jobs <- p
	}

	seen := web.NewLastSeen()
	seen.Seed(cfg.DataDir, tenantIDs(cfg), cfg.Location(), time.Now())
	w := store.NewWriter(cfg.DataDir, cfg.Location(), log, func(p string) { jobs <- p })
	w.LastSeen = seen.Mark
	writerStop := make(chan struct{})
	writerDone := make(chan struct{})
	go func() { w.Run(writerStop); close(writerDone) }()

	srv := &ingest.Server{
		Resolve: cfg.Resolve, Out: w.In, Log: log, MaxMsg: cfg.MaxMessageBytes,
		MaxConns: cfg.Listen.MaxTCPConns, IdleTimeout: cfg.Listen.TCPIdleTimeout.Duration,
		Unknown: ingest.NewUnknown(1000),
	}
	errc := make(chan error, 4)
	var lis sync.WaitGroup
	start := func(f func() error) {
		lis.Add(1)
		go func() {
			defer lis.Done()
			if err := f(); err != nil {
				errc <- err
			}
		}()
	}
	if cfg.Listen.UDP != "" {
		start(func() error { return srv.ServeUDP(ctx, cfg.Listen.UDP) })
	}
	if cfg.Listen.TCP != "" {
		start(func() error { return srv.ServeTCP(ctx, cfg.Listen.TCP) })
	}
	if cfg.Listen.TLS != "" {
		tc, err := ingest.TLSConfig(cfg.Listen.TLSCert, cfg.Listen.TLSKey, cfg.Listen.TLSClientCA)
		if err != nil {
			return err
		}
		start(func() error { return srv.ServeTLS(ctx, cfg.Listen.TLS, tc) })
	}

	days := &store.DaySealer{
		Root: cfg.DataDir, Loc: cfg.Location(), Grace: cfg.DayGrace.Duration, Stamper: st, Roots: rp,
		Sealer: sealer, Log: log, Tenants: func() []string { return tenantIDs(cfg) },
	}
	go days.Run(ctx)
	go retentionLoop(ctx, cfg, log)

	if cfg.Web.Listen != "" {
		ws, err := web.New(cfg, log, seen)
		if err != nil {
			return err
		}
		ws.Roots = rp
		ws.Unknown = srv.Unknown
		ws.Version = version
		ws.Stats = func() map[string]int64 {
			return map[string]int64{
				"Alınan kayıt":               w.Stats.Records.Load(),
				"Alınan bayt":                w.Stats.Bytes.Load(),
				"Yazma hatası":               w.Stats.Errors.Load(),
				"Bilinmeyen kaynak (atıldı)": srv.Dropped.Load(),
				"Reddedilen bağlantı":        srv.Rejected.Load(),
				"Kısaltılan mesaj":           srv.TooLong.Load(),
			}
		}
		start(func() error { return ws.ListenAndServe(ctx) })
	}

	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				log.Info("stats", "records", w.Stats.Records.Load(), "bytes", w.Stats.Bytes.Load(),
					"errors", w.Stats.Errors.Load(), "dropped_unknown", srv.Dropped.Load(),
					"rejected_conns", srv.Rejected.Load(), "truncated", srv.TooLong.Load())
			}
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-errc:
		log.Error("listener failed", "err", err)
		stop()
	}
	lis.Wait()
	close(writerStop)
	<-writerDone
	close(jobs)
	sealWG.Wait()
	log.Info("stopped")
	return nil
}

func retentionLoop(ctx context.Context, cfg *config.Config, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		for _, tn := range cfg.TenantList() {
			if err := store.ApplyRetention(cfg.DataDir, tn.ID, tn.RetentionDays, cfg.Location(), time.Now(), log); err != nil {
				log.Error("retention", "tenant", tn.ID, "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/syslog5651/config.yaml", "config file")
	tenant := fs.String("tenant", "", "tenant id")
	day := fs.String("day", "", "day (YYYY-MM-DD); empty = every sealed day")
	fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if _, ok := cfg.Tenant(*tenant); !ok {
		return fmt.Errorf("unknown tenant %q", *tenant)
	}
	rp, err := roots(cfg)
	if err != nil {
		return err
	}
	days := []string{*day}
	if *day == "" {
		all, err := store.ListDays(cfg.DataDir, *tenant)
		if err != nil {
			return err
		}
		days = nil
		for _, d := range all {
			if store.IsSealed(store.DayDir(cfg.DataDir, *tenant, d)) {
				days = append(days, d)
			}
		}
	}
	failed := 0
	for _, d := range days {
		rep, err := store.VerifyDay(cfg.DataDir, *tenant, d, rp, cfg.Timestamp.Mode != "none")
		if err != nil {
			failed++
			fmt.Printf("FAIL %s %s: %v\n", *tenant, d, err)
			continue
		}
		fmt.Printf("OK   %s %s files=%d lines=%d stamp=%s ca_checked=%v prev=%s\n",
			*tenant, d, rep.Files, rep.Lines, rep.StampTime, rep.ChainToCA, rep.PrevDay)
	}
	if failed > 0 {
		return fmt.Errorf("%d day(s) failed verification", failed)
	}
	return nil
}

func cmdSealDay(args []string) error {
	fs := flag.NewFlagSet("seal-day", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/syslog5651/config.yaml", "config file")
	tenant := fs.String("tenant", "", "tenant id")
	day := fs.String("day", "", "day (YYYY-MM-DD)")
	fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if _, ok := cfg.Tenant(*tenant); !ok || !store.ValidDay(*day) {
		return errors.New("valid -tenant and -day are required")
	}
	if *day >= time.Now().In(cfg.Location()).Format(store.DayLayout) {
		return errors.New("only finished days can be sealed")
	}
	log := logger()
	st, err := stamper(cfg)
	if err != nil {
		return err
	}
	rp, err := roots(cfg)
	if err != nil {
		return err
	}
	ds := &store.DaySealer{
		Root: cfg.DataDir, Loc: cfg.Location(), Stamper: st, Roots: rp, Log: log,
		Sealer: &store.Sealer{Root: cfg.DataDir, Codec: codec(cfg, log), Log: log},
	}
	return ds.SealDay(context.Background(), *tenant, *day)
}

func cmdUserAdd(args []string) error {
	fs := flag.NewFlagSet("useradd", flag.ExitOnError)
	path := fs.String("users", "", "users file (default: web.users_file from -config)")
	cfgPath := fs.String("config", "/etc/syslog5651/config.yaml", "config file")
	name := fs.String("name", "", "username")
	role := fs.String("role", web.RoleTenant, "admin or tenant")
	tenants := fs.String("tenants", "", "comma separated tenant ids (role tenant)")
	fs.Parse(args)
	if *path == "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return fmt.Errorf("%w (or pass -users)", err)
		}
		*path = cfg.Web.UsersFile
	}
	if !web.ValidUsername(*name) {
		return errors.New("username must be 3-64 characters: letters, digits, . _ @ -")
	}
	if *role != web.RoleAdmin && *role != web.RoleTenant {
		return errors.New("role must be admin or tenant")
	}
	var tl []string
	for _, t := range strings.Split(*tenants, ",") {
		if t = strings.TrimSpace(t); t != "" {
			if !config.IDPattern.MatchString(t) {
				return fmt.Errorf("bad tenant id %q", t)
			}
			tl = append(tl, t)
		}
	}
	if *role == web.RoleTenant && len(tl) == 0 {
		return errors.New("role tenant needs -tenants")
	}
	pw, err := readPassword()
	if err != nil {
		return err
	}
	hash, err := web.HashPassword(pw)
	if err != nil {
		return err
	}
	f := &web.UsersFile{}
	if _, err := os.Stat(*path); err == nil {
		if _, err := web.LoadUsers(*path); err != nil {
			return err
		}
		b, _ := os.ReadFile(*path)
		if err := yamlUnmarshal(b, f); err != nil {
			return err
		}
	}
	replaced := false
	for i := range f.Users {
		if f.Users[i].Username == *name {
			f.Users[i] = web.User{Username: *name, PasswordHash: hash, Role: *role, Tenants: tl}
			replaced = true
		}
	}
	if !replaced {
		f.Users = append(f.Users, web.User{Username: *name, PasswordHash: hash, Role: *role, Tenants: tl})
	}
	if err := web.SaveUsers(*path, f); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "user %s saved to %s (the running service picks it up within seconds)\n", *name, *path)
	return nil
}

func readPassword() (string, error) {
	fd := int(os.Stdin.Fd()) // #nosec G115 -- file descriptors fit in int
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "Password: ")
		a, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		fmt.Fprint(os.Stderr, "Repeat: ")
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(a) != string(b) {
			return "", errors.New("passwords do not match")
		}
		return string(a), nil
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
