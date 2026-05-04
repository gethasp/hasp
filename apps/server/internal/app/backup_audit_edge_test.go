package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

func TestOpenVaultHandleBackupAndAuditHelpers(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	password := "correct horse battery staple"
	enableConvenienceUnlockForAppTests(t, homeDir, password)
	t.Setenv("HASP_BACKUP_PASSPHRASE", "backup-passphrase")
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "")

	if _, err := openVaultHandle(context.Background()); err != nil {
		t.Fatalf("open vault with convenience unlock: %v", err)
	}
	t.Setenv("HASP_MASTER_PASSWORD", "wrong password")
	if _, err := openVaultHandle(context.Background()); err == nil {
		t.Fatal("expected openVaultHandle wrong-password failure")
	}
	t.Setenv("HASP_MASTER_PASSWORD", "")

	backupPath := filepath.Join(t.TempDir(), "backup.json")
	exportErr := errors.New("export writer failure")
	if err := exportBackupCommand(context.Background(), []string{"--bad"}, io.Discard); err == nil {
		t.Fatal("expected export parse error")
	}
	if err := exportBackupCommand(context.Background(), []string{"--output", backupPath}, errWriter{err: exportErr}); !errors.Is(err, exportErr) {
		t.Fatalf("expected export writer failure, got %v", err)
	}

	restoreHome := t.TempDir()
	t.Setenv("HASP_HOME", restoreHome)
	t.Setenv("HASP_MASTER_PASSWORD", "restored-password")
	restoreErr := errors.New("restore writer failure")
	if err := restoreBackupCommand(context.Background(), []string{"--bad"}, io.Discard); err == nil {
		t.Fatal("expected restore parse error")
	}
	// HASP_BACKUP_PASSPHRASE="backup-passphrase" and HASP_MASTER_PASSWORD="restored-password" are set above.
	if err := restoreBackupCommand(context.Background(), []string{"--input", backupPath}, errWriter{err: restoreErr}); !errors.Is(err, restoreErr) {
		t.Fatalf("expected restore writer failure, got %v", err)
	}
	t.Setenv("HASP_BACKUP_PASSPHRASE", "wrong-passphrase")
	if err := restoreBackupCommand(context.Background(), []string{"--input", backupPath}, io.Discard); err == nil {
		t.Fatal("expected restore wrong-passphrase failure")
	}
	t.Setenv("HASP_BACKUP_PASSPHRASE", "backup-passphrase")

	auditHome := t.TempDir()
	t.Setenv("HASP_HOME", auditHome)
	t.Setenv("HASP_MASTER_PASSWORD", password)
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	appendAudit(audit.EventRun, "tester", map[string]any{"scope": "app"})
	data, err := os.ReadFile(filepath.Join(auditHome, "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	if !strings.Contains(string(data), "\"type\":\"run\"") {
		t.Fatalf("expected appended audit event, got %q", string(data))
	}
	auditWriterErr := errors.New("audit writer failure")
	if err := auditCommand(context.Background(), errWriter{err: auditWriterErr}); !errors.Is(err, auditWriterErr) {
		t.Fatalf("expected audit writer failure, got %v", err)
	}
	if err := os.WriteFile(filepath.Join(auditHome, "audit.jsonl"), []byte("{bad json\n"), 0o600); err != nil {
		t.Fatalf("write malformed audit log: %v", err)
	}
	if err := auditCommand(context.Background(), io.Discard); err == nil {
		t.Fatal("expected audit verify failure")
	}

	origNewAudit := newAuditLogFn
	defer func() { newAuditLogFn = origNewAudit }()
	newAuditLogFn = func() (*audit.Log, error) { return nil, errors.New("audit init failure") }
	if err := auditCommand(context.Background(), io.Discard); err == nil {
		t.Fatal("expected audit constructor failure")
	}
	appendAudit(audit.EventRun, "tester", map[string]any{"scope": "ignore-failure"})
}
