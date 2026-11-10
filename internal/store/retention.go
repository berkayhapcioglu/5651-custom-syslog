package store

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// AuditDir holds the append-only audit log, outside any tenant directory.
const AuditDir = "_audit"

// RetentionEvent is one audit log line for a deleted day.
type RetentionEvent struct {
	Time           string `json:"time"`
	Event          string `json:"event"`
	Tenant         string `json:"tenant"`
	Day            string `json:"day"`
	RetentionDays  int    `json:"retention_days"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Files          int    `json:"files"`
	Lines          int64  `json:"lines"`
}

// ApplyRetention deletes sealed days older than days and records each
// deletion in the audit log. Unsealed days are never deleted.
func ApplyRetention(root, tenant string, days int, loc *time.Location, now time.Time, log *slog.Logger) error {
	list, err := ListDays(root, tenant)
	if err != nil {
		return err
	}
	cutoff := now.In(loc).AddDate(0, 0, -days).Format(DayLayout)
	for _, day := range list {
		if day >= cutoff {
			break
		}
		dir := DayDir(root, tenant, day)
		if !IsSealed(dir) {
			log.Warn("retention: day past retention is not sealed, keeping it", "tenant", tenant, "day", day)
			continue
		}
		ev := RetentionEvent{
			Time: now.UTC().Format(time.RFC3339), Event: "retention_delete",
			Tenant: tenant, Day: day, RetentionDays: days,
		}
		if m, b, err := ReadManifest(dir); err == nil {
			ev.ManifestSHA256 = hexSum(b)
			ev.Files = len(m.Files)
			ev.Lines = m.TotalLines
		}
		// Log first: a deletion without an audit line must never happen.
		if err := AppendAudit(root, ev); err != nil {
			return fmt.Errorf("retention audit: %w", err)
		}
		// Sealed files are read-only, but removing them only needs write
		// permission on their directories, which the service owns.
		if err := removeDay(root, tenant, day); err != nil {
			return err
		}
		log.Info("retention: deleted day", "tenant", tenant, "day", day)
	}
	return nil
}

// AppendAudit appends one JSON line to the audit log and fsyncs it.
func AppendAudit(root string, v any) error {
	dir := filepath.Join(root, AuditDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "audit.jsonl"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) // #nosec G304 -- fixed path
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
	return f.Close()
}

// removeDay deletes <root>/<tenant>/<day> through an os.Root so a symlink
// planted inside the data dir can never redirect the delete elsewhere.
func removeDay(root, tenant, day string) error {
	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer r.Close()
	return r.RemoveAll(filepath.Join(tenant, day))
}
