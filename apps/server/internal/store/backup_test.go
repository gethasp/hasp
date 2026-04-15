package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestExportAndRestoreBackup(t *testing.T) {
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, filepath.Join(baseDir, "home"))

	store, err := New(newMemoryKeyring())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.Init(context.Background(), "master-password"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "master-password")
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("secret-value"), ItemMetadata{Policy: PolicySession}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}

	backupPath := filepath.Join(baseDir, "export", "hasp.backup.json")
	checkpoint, err := handle.ExportBackup(context.Background(), backupPath, "backup-passphrase")
	if err != nil {
		t.Fatalf("export backup: %v", err)
	}
	if checkpoint.Sequence < 0 {
		t.Fatalf("unexpected checkpoint: %+v", checkpoint)
	}

	restoreHome := filepath.Join(baseDir, "restore-home")
	t.Setenv(paths.EnvHome, restoreHome)
	restoreStore, err := New(newMemoryKeyring())
	if err != nil {
		t.Fatalf("new restore store: %v", err)
	}
	if _, err := restoreStore.RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored-password"); err != nil {
		t.Fatalf("restore backup: %v", err)
	}
	restoredHandle, err := restoreStore.OpenWithPassword(context.Background(), "restored-password")
	if err != nil {
		t.Fatalf("open restored handle: %v", err)
	}
	item, err := restoredHandle.GetItem("api_token")
	if err != nil {
		t.Fatalf("get restored item: %v", err)
	}
	if string(item.Value) != "secret-value" {
		t.Fatalf("restored value = %q", string(item.Value))
	}
}
