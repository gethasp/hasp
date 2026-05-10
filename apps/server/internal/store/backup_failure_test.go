package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/paths"
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
	configureBackupSigningForTest(t)
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
	if _, err := restoreStore.RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored-password"); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature failure, got %v", err)
	}
}

func TestRestoreBackupRejectsTamperedSignature(t *testing.T) {
	configureBackupSigningForTest(t)
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
	backupPath := filepath.Join(t.TempDir(), "backup.hasp-backup")
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
	file.Signature.Value = strings.Repeat("A", len(file.Signature.Value))
	tampered, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("encode tampered backup: %v", err)
	}
	if err := os.WriteFile(backupPath, tampered, 0o600); err != nil {
		t.Fatalf("write tampered backup: %v", err)
	}
	restoreStore := newTestStore(t)
	if _, err := restoreStore.RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored-password"); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature failure, got %v", err)
	}
}

func TestRestoreBackupAllowsLegacyUnsignedBackup(t *testing.T) {
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
	backupPath := filepath.Join(t.TempDir(), "legacy.hasp-backup")
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
	file.Signature = BackupSignature{}
	legacy, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("encode legacy backup: %v", err)
	}
	if err := os.WriteFile(backupPath, legacy, 0o600); err != nil {
		t.Fatalf("write legacy backup: %v", err)
	}
	restoreStore := newTestStore(t)
	if _, err := restoreStore.RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored-password"); err != nil {
		t.Fatalf("restore unsigned legacy backup: %v", err)
	}
}

func TestRestoreBackupRejectsUnsignedBackupWhenTrustRootsConfigured(t *testing.T) {
	configureBackupSigningForTest(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	backupPath := filepath.Join(t.TempDir(), "unsigned.hasp-backup")
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
	file.Signature = BackupSignature{}
	legacy, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("encode legacy backup: %v", err)
	}
	if err := os.WriteFile(backupPath, legacy, 0o600); err != nil {
		t.Fatalf("write legacy backup: %v", err)
	}
	restoreStore := newTestStore(t)
	if _, err := restoreStore.RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored-password"); err == nil || !strings.Contains(err.Error(), "signature is required") {
		t.Fatalf("expected required signature failure, got %v", err)
	}
}

func TestRestoreBackupRollsBackWhenRestoreAuditAppendCannotStart(t *testing.T) {
	sourceHome := t.TempDir()
	t.Setenv(paths.EnvHome, sourceHome)
	sourceStore, err := New(newMemoryKeyring())
	if err != nil {
		t.Fatalf("new source store: %v", err)
	}
	if err := sourceStore.Init(context.Background(), "source master password"); err != nil {
		t.Fatalf("init source store: %v", err)
	}
	sourceHandle, err := sourceStore.OpenWithPassword(context.Background(), "source master password")
	if err != nil {
		t.Fatalf("open source store: %v", err)
	}
	if _, err := sourceHandle.UpsertItem("new_token", ItemKindKV, []byte("new-secret"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert source item: %v", err)
	}
	backupPath := filepath.Join(t.TempDir(), "backup.hasp-backup")
	if _, err := sourceHandle.ExportBackup(context.Background(), backupPath, "backup-passphrase"); err != nil {
		t.Fatalf("export backup: %v", err)
	}

	targetHome := t.TempDir()
	t.Setenv(paths.EnvHome, targetHome)
	targetStore, err := New(newMemoryKeyring())
	if err != nil {
		t.Fatalf("new target store: %v", err)
	}
	if err := targetStore.Init(context.Background(), "target master password"); err != nil {
		t.Fatalf("init target store: %v", err)
	}
	targetHandle, err := targetStore.OpenWithPassword(context.Background(), "target master password")
	if err != nil {
		t.Fatalf("open target store: %v", err)
	}
	if _, err := targetHandle.UpsertItem("old_token", ItemKindKV, []byte("old-secret"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert target item: %v", err)
	}

	origNewAudit := newAuditLogFn
	t.Cleanup(func() { newAuditLogFn = origNewAudit })
	newAuditLogFn = func() (*audit.Log, error) {
		return nil, errors.New("audit init failure")
	}
	if _, err := targetStore.RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored master password"); err == nil || !strings.Contains(err.Error(), "audit init failure") {
		t.Fatalf("expected audit init failure, got %v", err)
	}

	restoredOld, err := targetStore.OpenWithPassword(context.Background(), "target master password")
	if err != nil {
		t.Fatalf("open rolled-back target store: %v", err)
	}
	item, err := restoredOld.GetItem("old_token")
	if err != nil {
		t.Fatalf("get rolled-back old item: %v", err)
	}
	if string(item.Value) != "old-secret" {
		t.Fatalf("rolled-back value = %q", item.Value)
	}
	if _, err := targetStore.OpenWithPassword(context.Background(), "restored master password"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("restored password open err = %v, want ErrInvalidPassword", err)
	}
	matches, err := filepath.Glob(filepath.Join(targetHome, ".pre-restore-*"))
	if err != nil {
		t.Fatalf("glob pre-restore: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected pre-restore snapshot directory")
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
