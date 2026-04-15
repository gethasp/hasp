package app

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"testing"
)

func TestRuntimeCommandUsageErrorsAndExportRestoreRoundTrip(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	t.Setenv("HASP_BACKUP_PASSPHRASE", "backup-passphrase")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run set: %v", err)
	}

	if err := exportBackupCommand(context.Background(), []string{}, io.Discard); err == nil {
		t.Fatal("expected export-backup usage error")
	}
	backupPath := filepath.Join(t.TempDir(), "hasp.backup.json")
	if err := exportBackupCommand(context.Background(), []string{"--output", backupPath}, io.Discard); err != nil {
		t.Fatalf("export-backup command: %v", err)
	}

	restoreHome := t.TempDir()
	t.Setenv("HASP_HOME", restoreHome)
	t.Setenv("HASP_MASTER_PASSWORD", "restored-password")
	if err := restoreBackupCommand(context.Background(), []string{}, io.Discard); err == nil {
		t.Fatal("expected restore-backup usage error")
	}
	if err := restoreBackupCommand(context.Background(), []string{"--input", backupPath, "--recovery-passphrase", "backup-passphrase", "--master-password", "restored-password"}, io.Discard); err != nil {
		t.Fatalf("restore-backup command: %v", err)
	}

	var stdout bytes.Buffer
	starter := newDaemonTestStarter(t)
	if err := pingCommand(context.Background(), &stdout, starter); err != nil {
		t.Fatalf("ping command: %v", err)
	}
	if err := statusCommand(context.Background(), &stdout, starter); err != nil {
		t.Fatalf("status command: %v", err)
	}
	if err := daemonCommand(context.Background(), []string{}, io.Discard, starter); err == nil {
		t.Fatal("expected daemon usage error")
	}
	if err := sessionCommand(context.Background(), []string{}, io.Discard, starter); err == nil {
		t.Fatal("expected session usage error")
	}
}
