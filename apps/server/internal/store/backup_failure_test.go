package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestoreBackupRejectsWrongPassphrase(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("abc123"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	backupPath := t.TempDir() + "/backup.json"
	if _, err := handle.ExportBackup(context.Background(), backupPath, "backup-passphrase"); err != nil {
		t.Fatalf("export backup: %v", err)
	}
	restoreStore := newTestStore(t)
	if _, err := restoreStore.RestoreBackup(context.Background(), backupPath, "wrong-passphrase", "restored-password"); err == nil {
		t.Fatal("expected wrong-passphrase restore failure")
	}
}

func TestBackupCommandsRejectMissingSecrets(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := handle.ExportBackup(context.Background(), filepath.Join(t.TempDir(), "backup.json"), ""); err == nil {
		t.Fatal("expected missing backup passphrase failure")
	}
	if _, err := store.RestoreBackup(context.Background(), filepath.Join(t.TempDir(), "missing.json"), "", "restored-password"); err == nil {
		t.Fatal("expected missing backup passphrase restore failure")
	}
	if _, err := store.RestoreBackup(context.Background(), filepath.Join(t.TempDir(), "missing.json"), "backup-passphrase", ""); err == nil {
		t.Fatal("expected missing master password restore failure")
	}
}

func TestRestoreBackupRejectsTamperedPayload(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("abc123"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	backupPath := t.TempDir() + "/backup.json"
	if _, err := handle.ExportBackup(context.Background(), backupPath, "backup-passphrase"); err != nil {
		t.Fatalf("export backup: %v", err)
	}
	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	var file BackupFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("decode backup: %v", err)
	}
	file.Integrity = strings.Repeat("0", len(file.Integrity))
	tampered, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("encode backup: %v", err)
	}
	if err := os.WriteFile(backupPath, tampered, 0o600); err != nil {
		t.Fatalf("write tampered backup: %v", err)
	}
	restoreStore := newTestStore(t)
	if _, err := restoreStore.RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored-password"); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("expected integrity failure, got %v", err)
	}
}

func TestExportBackupRejectsUnwritableLocationAndNilStoreAudit(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	handle.store.audit = nil
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("abc123"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}

	blocker := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocker, []byte("file"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	if _, err := handle.ExportBackup(context.Background(), filepath.Join(blocker, "backup.json"), "backup-passphrase"); err == nil {
		t.Fatal("expected export backup location failure")
	}
}

func TestRestoreBackupRejectsMalformedFileAndPayload(t *testing.T) {
	restoreStore := newTestStore(t)
	badPath := filepath.Join(t.TempDir(), "backup.json")
	if err := os.WriteFile(badPath, []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("write malformed backup file: %v", err)
	}
	if _, err := restoreStore.RestoreBackup(context.Background(), badPath, "backup-passphrase", "restored-password"); err == nil {
		t.Fatal("expected malformed backup file failure")
	}

	kdf, wrapKey, err := derivePasswordWrap("backup-passphrase")
	if err != nil {
		t.Fatalf("derive wrap key: %v", err)
	}
	payload := []byte("not-json")
	sealed, err := sealBytes(wrapKey, payload)
	if err != nil {
		t.Fatalf("seal payload: %v", err)
	}
	file := BackupFile{
		Version:    backupFormatVersion,
		KDF:        kdf,
		Payload:    sealed,
		Integrity:  integrityDigest(payload),
		ExportedAt: newTestStore(t).now(),
	}
	data, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("encode backup file: %v", err)
	}
	if err := os.WriteFile(badPath, data, 0o600); err != nil {
		t.Fatalf("write sealed malformed payload backup: %v", err)
	}
	if _, err := restoreStore.RestoreBackup(context.Background(), badPath, "backup-passphrase", "restored-password"); err == nil || !strings.Contains(err.Error(), "decode backup payload") {
		t.Fatalf("expected malformed payload decode failure, got %v", err)
	}
}
