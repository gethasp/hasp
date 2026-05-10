package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestExportAndRestoreBackup(t *testing.T) {
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, filepath.Join(baseDir, "home"))
	configureBackupSigningForTest(t)

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
	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	var backup BackupFile
	if err := json.Unmarshal(data, &backup); err != nil {
		t.Fatalf("decode backup: %v", err)
	}
	if backup.Signature.Algorithm != "Ed25519" || backup.Signature.PublicKey == "" || backup.Signature.Value == "" {
		t.Fatalf("missing backup signature: %+v", backup.Signature)
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
	restoredPaths, err := paths.Resolve()
	if err != nil {
		t.Fatalf("resolve restored paths: %v", err)
	}
	restoredLog := audit.NewForPaths(restoredPaths).WithKey(restoredHandle.AuditHMACKey())
	if err := restoredLog.Verify(); err != nil {
		t.Fatalf("verify restored audit chain: %v", err)
	}
	events, err := restoredLog.Events()
	if err != nil {
		t.Fatalf("read restored audit events: %v", err)
	}
	if len(events) == 0 || events[len(events)-1].Type != "restore" || events[len(events)-1].Scheme != audit.SchemeHMACSHA256V1 {
		t.Fatalf("restore event was not keyed at end of chain: %+v", events)
	}
	restoredAudit, err := os.ReadFile(filepath.Join(restoreHome, "audit.jsonl"))
	if err != nil {
		t.Fatalf("read restored audit: %v", err)
	}
	for _, want := range []string{`"type":"init"`, `"type":"restore"`} {
		if !strings.Contains(string(restoredAudit), want) {
			t.Fatalf("restored audit missing %s: %s", want, restoredAudit)
		}
	}
}

func TestRestoreLegacyBackupAppendsKeyedRestoreEvent(t *testing.T) {
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, filepath.Join(baseDir, "home"))
	configureBackupSigningForTest(t)

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

	backupPath := filepath.Join(baseDir, "export", "legacy.backup.json")
	if _, err := handle.ExportBackup(context.Background(), backupPath, "backup-passphrase"); err != nil {
		t.Fatalf("export backup: %v", err)
	}
	rewriteBackupPayload(t, backupPath, "backup-passphrase", func(payload *backupPayload) {
		payload.VaultKey = nil
		payload.AuditJSONL = nil
	})

	restoreHome := filepath.Join(baseDir, "restore-home")
	t.Setenv(paths.EnvHome, restoreHome)
	restoreStore, err := New(newMemoryKeyring())
	if err != nil {
		t.Fatalf("new restore store: %v", err)
	}
	if _, err := restoreStore.RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored-password"); err != nil {
		t.Fatalf("restore legacy backup: %v", err)
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
	restoredPaths, err := paths.Resolve()
	if err != nil {
		t.Fatalf("resolve restored paths: %v", err)
	}
	restoredLog := audit.NewForPaths(restoredPaths).WithKey(restoredHandle.AuditHMACKey())
	if err := restoredLog.Verify(); err != nil {
		t.Fatalf("verify restored legacy audit chain: %v", err)
	}
	events, err := restoredLog.Events()
	if err != nil {
		t.Fatalf("read restored events: %v", err)
	}
	if len(events) != 1 || events[0].Type != "restore" || events[0].Scheme != audit.SchemeHMACSHA256V1 {
		t.Fatalf("legacy restore event was not keyed single-event chain: %+v", events)
	}
}

func configureBackupSigningForTest(t *testing.T) ed25519.PublicKey {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate backup signing key: %v", err)
	}
	t.Setenv("HASP_BACKUP_SIGNING_KEY_B64", base64.StdEncoding.EncodeToString(privateKey))
	t.Setenv("HASP_BACKUP_TRUST_ROOTS_HEX", hex.EncodeToString(publicKey))
	return publicKey
}

func rewriteBackupPayload(t *testing.T, path string, passphrase string, edit func(*backupPayload)) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	var file BackupFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("decode backup: %v", err)
	}
	key, err := deriveFromSpec(passphrase, file.KDF)
	if err != nil {
		t.Fatalf("derive backup key: %v", err)
	}
	plaintext, err := openBytes(key, file.Payload)
	if err != nil {
		t.Fatalf("open backup payload: %v", err)
	}
	var payload backupPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		t.Fatalf("decode backup payload: %v", err)
	}
	edit(&payload)
	plaintext, err = json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode backup payload: %v", err)
	}
	sealed, err := sealBytes(key, plaintext)
	if err != nil {
		t.Fatalf("seal backup payload: %v", err)
	}
	file.Payload = sealed
	file.Integrity = integrityDigest(plaintext)
	file.Signature = BackupSignature{}
	if err := signBackupFile(&file); err != nil {
		t.Fatalf("resign backup: %v", err)
	}
	data, err = json.Marshal(file)
	if err != nil {
		t.Fatalf("encode backup: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write backup: %v", err)
	}
}
