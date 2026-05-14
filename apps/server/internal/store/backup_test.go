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
	"time"

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
	if backup.VaultID == "" || backup.VaultID != handle.BackupVaultID() {
		t.Fatalf("backup vault id = %q, want current vault id %q", backup.VaultID, handle.BackupVaultID())
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

func TestPruneBackupDirectorySkipsOtherVaultIDs(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 5, 10, 9, 0, 0, 0, time.UTC)
	currentVaultID := strings.Repeat("a", 64)
	otherVaultID := strings.Repeat("b", 64)

	currentOld := writeBackupCandidate(t, dir, "current-old.hasp-backup", currentVaultID, now.Add(-4*time.Hour))
	currentMid := writeBackupCandidate(t, dir, "current-mid.hasp-backup", currentVaultID, now.Add(-3*time.Hour))
	currentNew := writeBackupCandidate(t, dir, "current-new.hasp-backup", currentVaultID, now.Add(-2*time.Hour))
	otherOld := writeBackupCandidate(t, dir, "other-old.hasp-backup", otherVaultID, now.Add(-24*time.Hour))
	legacyOld := writeBackupCandidate(t, dir, "legacy-old.hasp-backup", "", now.Add(-48*time.Hour))

	if err := PruneBackupDirectory(dir, 2, currentVaultID); err != nil {
		t.Fatalf("prune backup dir: %v", err)
	}
	if fileExists(currentOld) {
		t.Fatalf("oldest current-vault backup survived pruning: %s", currentOld)
	}
	for _, path := range []string{currentMid, currentNew, otherOld, legacyOld} {
		if !fileExists(path) {
			t.Fatalf("backup %s was pruned unexpectedly", path)
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

func TestBackupSignatureStatusReportsTrustAndFileErrors(t *testing.T) {
	unsigned, err := BackupSignatureStatusForBackupFile(BackupFile{})
	if err != nil {
		t.Fatalf("unsigned status: %v", err)
	}
	if unsigned.Signed || unsigned.Required || unsigned.Error != "" {
		t.Fatalf("unexpected unsigned status without trust roots: %+v", unsigned)
	}

	publicKey := configureBackupSigningForTest(t)
	requiredUnsigned, err := BackupSignatureStatusForBackupFile(BackupFile{})
	if err != nil {
		t.Fatalf("required unsigned status: %v", err)
	}
	if !requiredUnsigned.Required || requiredUnsigned.Error != "backup signature is required" {
		t.Fatalf("required unsigned status = %+v", requiredUnsigned)
	}

	invalidAlgorithm, err := BackupSignatureStatusForBackupFile(BackupFile{Signature: BackupSignature{
		Algorithm: "RSA",
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		Value:     "signature",
	}})
	if err != nil {
		t.Fatalf("invalid algorithm status: %v", err)
	}
	if !invalidAlgorithm.Signed || invalidAlgorithm.Error != "backup signature algorithm is unsupported" {
		t.Fatalf("invalid algorithm status = %+v", invalidAlgorithm)
	}

	invalidKey, err := BackupSignatureStatusForBackupFile(BackupFile{Signature: BackupSignature{
		Algorithm: "Ed25519",
		PublicKey: "not-base64",
		Value:     "signature",
	}})
	if err != nil {
		t.Fatalf("invalid key status: %v", err)
	}
	if invalidKey.Error != "backup signature public key is invalid" {
		t.Fatalf("invalid key status = %+v", invalidKey)
	}

	trusted, err := BackupSignatureStatusForBackupFile(BackupFile{Signature: BackupSignature{
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		Value:     "signature",
	}})
	if err != nil {
		t.Fatalf("trusted status: %v", err)
	}
	if !trusted.Signed || !trusted.Trusted || trusted.SignerFingerprint == "" || trusted.Error != "" {
		t.Fatalf("trusted status = %+v", trusted)
	}

	path := filepath.Join(t.TempDir(), "backup.json")
	if _, err := BackupSignatureStatusForFile(path); err == nil {
		t.Fatal("expected read error for missing backup")
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatalf("write invalid backup: %v", err)
	}
	if _, err := BackupSignatureStatusForFile(path); err == nil {
		t.Fatal("expected decode error for malformed backup")
	}
	data, err := json.Marshal(BackupFile{Signature: BackupSignature{
		Algorithm: "Ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		Value:     "signature",
	}})
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write backup: %v", err)
	}
	if _, err := BackupSignatureStatusForFile(path); err != nil {
		t.Fatalf("status for file: %v", err)
	}
}

func TestBackupSigningAndPruneEdgeBranches(t *testing.T) {
	if err := signBackupFile(nil); err == nil {
		t.Fatal("nil backup file should fail signing")
	}
	var unsigned BackupFile
	if err := signBackupFile(&unsigned); err != nil {
		t.Fatalf("sign without configured key should be a no-op: %v", err)
	}
	t.Setenv("HASP_BACKUP_SIGNING_KEY_B64", "not-base64")
	if _, _, err := backupSigningPrivateKey(); err == nil {
		t.Fatal("invalid base64 signing key should fail")
	}
	t.Setenv("HASP_BACKUP_SIGNING_KEY_B64", base64.StdEncoding.EncodeToString([]byte("short")))
	if _, _, err := backupSigningPrivateKey(); err == nil {
		t.Fatal("short base64 signing key should fail")
	}
	t.Setenv("HASP_BACKUP_SIGNING_KEY_B64", "")
	t.Setenv("HASP_BACKUP_SIGNING_KEY_HEX", "not-hex")
	if _, _, err := backupSigningPrivateKey(); err == nil {
		t.Fatal("invalid hex signing key should fail")
	}
	t.Setenv("HASP_BACKUP_SIGNING_KEY_HEX", hex.EncodeToString([]byte("short")))
	if _, _, err := backupSigningPrivateKey(); err == nil {
		t.Fatal("short hex signing key should fail")
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	otherPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate other signing key: %v", err)
	}
	t.Setenv("HASP_BACKUP_SIGNING_KEY_HEX", hex.EncodeToString(privateKey))
	t.Setenv("HASP_BACKUP_TRUST_ROOTS_HEX", hex.EncodeToString(otherPublicKey))
	if err := signBackupFile(&BackupFile{Version: backupFormatVersion}); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("untrusted signing key err = %v", err)
	}
	t.Setenv("HASP_BACKUP_TRUST_ROOTS_HEX", "not-hex")
	if _, _, err := backupTrustedPublicKeys(); err == nil {
		t.Fatal("invalid trust root hex should fail")
	}
	t.Setenv("HASP_BACKUP_TRUST_ROOTS_HEX", hex.EncodeToString([]byte("short")))
	if _, _, err := backupTrustedPublicKeys(); err == nil {
		t.Fatal("short trust root should fail")
	}
	t.Setenv("HASP_BACKUP_TRUST_ROOTS_HEX", " , ")
	if _, _, err := backupTrustedPublicKeys(); err == nil {
		t.Fatal("empty trust root list should fail")
	}

	t.Setenv("HASP_BACKUP_TRUST_ROOTS_HEX", hex.EncodeToString(publicKey))
	file := BackupFile{Version: backupFormatVersion, VaultID: "vault", ExportedAt: time.Date(2026, 5, 10, 9, 0, 0, 0, time.UTC)}
	if err := signBackupFile(&file); err != nil {
		t.Fatalf("sign trusted backup: %v", err)
	}
	if err := verifyBackupFileSignature(file); err != nil {
		t.Fatalf("verify signed backup: %v", err)
	}
	noRoots := file
	t.Setenv("HASP_BACKUP_TRUST_ROOTS_HEX", "")
	if err := verifyBackupFileSignature(noRoots); err == nil || !strings.Contains(err.Error(), "trust roots") {
		t.Fatalf("signed backup without trust roots err = %v", err)
	}
	badSignature := file
	t.Setenv("HASP_BACKUP_TRUST_ROOTS_HEX", hex.EncodeToString(publicKey))
	badSignature.Signature.Value = base64.StdEncoding.EncodeToString([]byte("short"))
	if err := verifyBackupFileSignature(badSignature); err == nil || !strings.Contains(err.Error(), "signature is invalid") {
		t.Fatalf("short signature err = %v", err)
	}
	badPayload := file
	badPayload.VaultID = "changed"
	if err := verifyBackupFileSignature(badPayload); err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("bad payload signature err = %v", err)
	}

	if err := PruneBackupDirectory("", 0, ""); err != nil {
		t.Fatalf("empty prune should no-op: %v", err)
	}
	if err := PruneBackupDirectory(filepath.Join(t.TempDir(), "missing"), 1, ""); err != nil {
		t.Fatalf("missing prune dir should no-op: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.hasp-backup"), []byte("{"), 0o600); err != nil {
		t.Fatalf("write bad backup: %v", err)
	}
	if err := PruneBackupDirectory(dir, 1, "vault"); err == nil {
		t.Fatal("pruning with vault filter should fail on malformed backup identity")
	}
	if _, err := readBackupVaultID(filepath.Join(dir, "missing.hasp-backup")); err == nil {
		t.Fatal("missing backup vault id read should fail")
	}
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

func writeBackupCandidate(t *testing.T, dir string, name string, vaultID string, modTime time.Time) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data, err := json.Marshal(BackupFile{Version: backupFormatVersion, VaultID: vaultID})
	if err != nil {
		t.Fatalf("encode backup candidate: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write backup candidate: %v", err)
	}
	if err := os.Chtimes(path, modTime, modTime); err != nil {
		t.Fatalf("set backup candidate time: %v", err)
	}
	return path
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
