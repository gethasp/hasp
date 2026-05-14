package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestBackupResidualExportSignatureAndStatusBranches(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	auditDir := filepath.Join(t.TempDir(), "audit-dir")
	if err := os.Mkdir(auditDir, 0o700); err != nil {
		t.Fatalf("mkdir audit dir: %v", err)
	}
	handle.store.paths.AuditPath = auditDir
	if _, err := handle.ExportBackup(context.Background(), filepath.Join(t.TempDir(), "backup.hasp-backup"), "backup-passphrase"); err == nil || !strings.Contains(err.Error(), "read audit chain") {
		t.Fatalf("expected audit read failure, got %v", err)
	}
	handle.store.paths.AuditPath = filepath.Join(t.TempDir(), "audit.jsonl")

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	otherPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate other signing key: %v", err)
	}
	t.Setenv("HASP_BACKUP_SIGNING_KEY_B64", "not-base64")
	if err := signBackupFile(&BackupFile{}); err == nil {
		t.Fatal("expected direct signing key decode failure")
	}
	t.Setenv("HASP_BACKUP_SIGNING_KEY_B64", base64.StdEncoding.EncodeToString(privateKey))
	t.Setenv("HASP_BACKUP_TRUST_ROOTS_HEX", "not-hex")
	if _, err := handle.ExportBackup(context.Background(), filepath.Join(t.TempDir(), "backup.hasp-backup"), "backup-passphrase"); err == nil {
		t.Fatal("expected export signing failure")
	}
	t.Setenv("HASP_BACKUP_TRUST_ROOTS_HEX", "not-hex")
	if err := signBackupFile(&BackupFile{}); err == nil {
		t.Fatal("expected signing trust-root decode failure")
	}
	if _, err := BackupSignatureStatusForBackupFile(BackupFile{}); err == nil {
		t.Fatal("expected status trust-root decode failure")
	}
	if err := verifyBackupFileSignature(BackupFile{}); err == nil {
		t.Fatal("expected unsigned verify trust-root decode failure")
	}

	t.Setenv("HASP_BACKUP_TRUST_ROOTS_HEX", hex.EncodeToString(otherPublicKey))
	status, err := BackupSignatureStatusForBackupFile(BackupFile{Signature: BackupSignature{
		Algorithm: "Ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		Value:     base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}})
	if err != nil || !status.Signed || status.Trusted || status.Error != "backup signature signer is not trusted" {
		t.Fatalf("untrusted status=%+v err=%v", status, err)
	}
	if err := verifyBackupFileSignature(BackupFile{Signature: BackupSignature{Algorithm: "RSA", PublicKey: "x", Value: "x"}}); err == nil {
		t.Fatal("expected unsupported signature algorithm")
	}
	if err := verifyBackupFileSignature(BackupFile{Signature: BackupSignature{Algorithm: "Ed25519", PublicKey: "not-base64", Value: "x"}}); err == nil {
		t.Fatal("expected invalid public key")
	}
	if err := verifyBackupFileSignature(BackupFile{Signature: BackupSignature{
		Algorithm: "Ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		Value:     base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}}); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("expected untrusted signer, got %v", err)
	}

	t.Setenv("HASP_BACKUP_TRUST_ROOTS_HEX", hex.EncodeToString(publicKey))
	file := BackupFile{Version: backupFormatVersion}
	if err := signBackupFile(&file); err != nil {
		t.Fatalf("sign file: %v", err)
	}
	t.Setenv("HASP_BACKUP_TRUST_ROOTS_HEX", "not-hex")
	if err := verifyBackupFileSignature(file); err == nil {
		t.Fatal("expected signed verify trust-root decode failure")
	}
	t.Setenv("HASP_BACKUP_TRUST_ROOTS_HEX", hex.EncodeToString(publicKey))
	oldMarshal := jsonMarshalFn
	jsonMarshalFn = func(any) ([]byte, error) { return nil, errors.New("marshal backup signature") }
	if err := signBackupFile(&BackupFile{Version: backupFormatVersion}); err == nil {
		t.Fatal("expected signing payload marshal failure")
	}
	if err := verifyBackupFileSignature(file); err == nil {
		t.Fatal("expected verify payload marshal failure")
	}
	if _, err := backupSigningPayload(file); err == nil {
		t.Fatal("expected direct signing payload marshal failure")
	}
	jsonMarshalFn = oldMarshal
	t.Cleanup(func() { jsonMarshalFn = oldMarshal })
}

func TestBackupResidualRestoreAndFilesystemBranches(t *testing.T) {
	source := newTestStore(t)
	if err := source.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init source: %v", err)
	}
	sourceHandle, err := source.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open source: %v", err)
	}
	backupPath := filepath.Join(t.TempDir(), "backup.hasp-backup")
	if _, err := sourceHandle.ExportBackup(context.Background(), backupPath, "backup-passphrase"); err != nil {
		t.Fatalf("export backup: %v", err)
	}

	t.Run("restore rejects integrity mismatch", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad-integrity.hasp-backup")
		copyFileForTest(t, backupPath, path)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read backup: %v", err)
		}
		var file BackupFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatalf("decode backup: %v", err)
		}
		file.Signature = BackupSignature{}
		file.Integrity = strings.Repeat("0", len(file.Integrity))
		data, err = json.Marshal(file)
		if err != nil {
			t.Fatalf("encode backup: %v", err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write backup: %v", err)
		}
		if _, err := newTestStore(t).RestoreBackup(context.Background(), path, "backup-passphrase", "restored password"); err == nil || !strings.Contains(err.Error(), "integrity") {
			t.Fatalf("expected integrity failure, got %v", err)
		}
	})

	t.Run("restore rejects invalid vault key", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad-key.hasp-backup")
		copyFileForTest(t, backupPath, path)
		rewriteBackupPayload(t, path, "backup-passphrase", func(payload *backupPayload) {
			payload.VaultKey = []byte("short")
		})
		if _, err := newTestStore(t).RestoreBackup(context.Background(), path, "backup-passphrase", "restored password"); err == nil || !strings.Contains(err.Error(), "vault key") {
			t.Fatalf("expected vault key failure, got %v", err)
		}
	})

	t.Run("restore covers legacy random derive and seal failures", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "legacy.hasp-backup")
		copyFileForTest(t, backupPath, path)
		rewriteBackupPayload(t, path, "backup-passphrase", func(payload *backupPayload) {
			payload.VaultKey = nil
		})
		oldRandom := randomBytesFn
		randomBytesFn = func(int) ([]byte, error) { return nil, errors.New("random failed") }
		if _, err := newTestStore(t).RestoreBackup(context.Background(), path, "backup-passphrase", "restored password"); err == nil {
			t.Fatal("expected random failure")
		}
		randomBytesFn = oldRandom
		oldDerive := deriveWrapFn
		deriveWrapFn = func(string) (kdfSpec, []byte, error) { return kdfSpec{}, nil, errors.New("derive failed") }
		if _, err := newTestStore(t).RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored password"); err == nil {
			t.Fatal("expected derive failure")
		}
		deriveWrapFn = oldDerive
		oldSeal := sealBytesFn
		sealBytesFn = func([]byte, []byte) (sealedBlob, error) { return sealedBlob{}, errors.New("seal failed") }
		if _, err := newTestStore(t).RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored password"); err == nil {
			t.Fatal("expected seal failure")
		}
		sealBytesFn = oldSeal
		t.Cleanup(func() {
			randomBytesFn = oldRandom
			deriveWrapFn = oldDerive
			sealBytesFn = oldSeal
		})
	})

	t.Run("restore covers write and audit failures", func(t *testing.T) {
		oldMarshal := jsonMarshalFn
		jsonMarshalFn = func(any) ([]byte, error) { return nil, errors.New("write envelope failed") }
		if _, err := newTestStore(t).RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored password"); err == nil {
			t.Fatal("expected write envelope failure")
		}
		jsonMarshalFn = oldMarshal

		target := newTestStore(t)
		auditDir := filepath.Dir(target.paths.AuditPath)
		oldMkdir := backupMkdirAll
		backupMkdirAll = func(path string, perm os.FileMode) error {
			if path == auditDir {
				return errors.New("audit mkdir failed")
			}
			return oldMkdir(path, perm)
		}
		if _, err := target.RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored password"); err == nil || !strings.Contains(err.Error(), "create audit dir") {
			t.Fatalf("expected audit mkdir failure, got %v", err)
		}
		backupMkdirAll = oldMkdir

		oldWrite := backupWriteFile
		backupWriteFile = func(path string, data []byte, perm os.FileMode) error {
			if path == target.paths.AuditPath {
				return errors.New("audit write failed")
			}
			return oldWrite(path, data, perm)
		}
		if _, err := target.RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored password"); err == nil || !strings.Contains(err.Error(), "restore audit chain") {
			t.Fatalf("expected audit write failure, got %v", err)
		}
		backupWriteFile = oldWrite

		oldAudit := newAuditLogFn
		newAuditLogFn = func() (*audit.Log, error) {
			return audit.NewForPaths(paths.Paths{AuditPath: t.TempDir()}), nil
		}
		if _, err := target.RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored password"); err == nil || !strings.Contains(err.Error(), "append restore audit") {
			t.Fatalf("expected append audit failure, got %v", err)
		}
		newAuditLogFn = oldAudit
		t.Cleanup(func() {
			jsonMarshalFn = oldMarshal
			backupMkdirAll = oldMkdir
			backupWriteFile = oldWrite
			newAuditLogFn = oldAudit
		})
	})

	origReadFile := backupReadFile
	origWriteFile := backupWriteFile
	origMkdirAll := backupMkdirAll
	origRemove := backupRemove
	origReadDir := backupReadDir
	t.Cleanup(func() {
		backupReadFile = origReadFile
		backupWriteFile = origWriteFile
		backupMkdirAll = origMkdirAll
		backupRemove = origRemove
		backupReadDir = origReadDir
	})

	target := newTestStore(t)
	backupMkdirAll = func(string, os.FileMode) error { return errors.New("mkdir failed") }
	if _, err := target.createPreRestoreSnapshot(); err == nil {
		t.Fatal("expected snapshot mkdir failure")
	}
	backupMkdirAll = origMkdirAll

	if err := os.MkdirAll(filepath.Dir(target.paths.StatePath), 0o700); err != nil {
		t.Fatalf("mkdir target state dir: %v", err)
	}
	if err := os.WriteFile(target.paths.StatePath, []byte("state"), 0o600); err != nil {
		t.Fatalf("write target state: %v", err)
	}
	backupWriteFile = func(string, []byte, os.FileMode) error { return errors.New("write snapshot failed") }
	if _, err := target.createPreRestoreSnapshot(); err == nil {
		t.Fatal("expected snapshot write failure")
	}
	backupWriteFile = origWriteFile

	if err := target.restorePreRestoreSnapshot(preRestoreSnapshot{}); err != nil {
		t.Fatalf("empty snapshot restore: %v", err)
	}
	backupReadFile = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	backupRemove = func(string) error { return errors.New("remove failed") }
	if err := target.restorePreRestoreSnapshot(preRestoreSnapshot{Dir: "snapshot"}); err == nil {
		t.Fatal("expected restore remove failure")
	}
	backupReadFile = func(string) ([]byte, error) { return nil, errors.New("read snapshot failed") }
	if err := target.restorePreRestoreSnapshot(preRestoreSnapshot{Dir: "snapshot"}); err == nil {
		t.Fatal("expected restore read failure")
	}
	backupReadFile = func(string) ([]byte, error) { return []byte("snapshot"), nil }
	backupMkdirAll = func(string, os.FileMode) error { return errors.New("restore mkdir failed") }
	if err := target.restorePreRestoreSnapshot(preRestoreSnapshot{Dir: "snapshot"}); err == nil {
		t.Fatal("expected restore mkdir failure")
	}
	backupMkdirAll = origMkdirAll
	backupWriteFile = func(string, []byte, os.FileMode) error { return errors.New("restore write failed") }
	if err := target.restorePreRestoreSnapshot(preRestoreSnapshot{Dir: "snapshot"}); err == nil {
		t.Fatal("expected restore write failure")
	}
	backupReadFile = origReadFile
	backupWriteFile = origWriteFile

	backupReadDir = func(string) ([]os.DirEntry, error) { return nil, errors.New("read dir failed") }
	if err := PruneBackupDirectory(t.TempDir(), 1, ""); err == nil {
		t.Fatal("expected prune read dir failure")
	}
	now := time.Now()
	backupReadDir = func(string) ([]os.DirEntry, error) {
		return []os.DirEntry{
			fakeBackupDirEntry{name: "subdir", dir: true, modTime: now},
			fakeBackupDirEntry{name: "notes.txt", modTime: now},
		}, nil
	}
	if err := PruneBackupDirectory(t.TempDir(), 1, ""); err != nil {
		t.Fatalf("skip non-candidates: %v", err)
	}
	backupReadDir = func(string) ([]os.DirEntry, error) {
		return []os.DirEntry{
			fakeBackupDirEntry{name: "old.hasp-backup", modTime: now.Add(-time.Hour)},
			fakeBackupDirEntry{name: "new.hasp-backup", modTime: now},
		}, nil
	}
	backupRemove = func(string) error { return errors.New("remove stale failed") }
	if err := PruneBackupDirectory(t.TempDir(), 1, ""); err == nil {
		t.Fatal("expected stale remove failure")
	}
	backupReadDir = func(string) ([]os.DirEntry, error) {
		return []os.DirEntry{fakeBackupDirEntry{name: "stat.hasp-backup", infoErr: errors.New("stat failed")}}, nil
	}
	backupRemove = origRemove
	if err := PruneBackupDirectory(t.TempDir(), 1, ""); err == nil {
		t.Fatal("expected stat failure")
	}
}

func copyFileForTest(t *testing.T, source string, target string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read %s: %v", source, err)
	}
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", target, err)
	}
}

type fakeBackupDirEntry struct {
	name    string
	dir     bool
	modTime time.Time
	infoErr error
}

func (e fakeBackupDirEntry) Name() string      { return e.name }
func (e fakeBackupDirEntry) IsDir() bool       { return e.dir }
func (e fakeBackupDirEntry) Type() fs.FileMode { return 0 }
func (e fakeBackupDirEntry) Info() (fs.FileInfo, error) {
	if e.infoErr != nil {
		return nil, e.infoErr
	}
	return fakeBackupFileInfo{name: e.name, modTime: e.modTime}, nil
}

type fakeBackupFileInfo struct {
	name    string
	modTime time.Time
}

func (i fakeBackupFileInfo) Name() string       { return i.name }
func (i fakeBackupFileInfo) Size() int64        { return 1 }
func (i fakeBackupFileInfo) Mode() fs.FileMode  { return 0 }
func (i fakeBackupFileInfo) ModTime() time.Time { return i.modTime }
func (i fakeBackupFileInfo) IsDir() bool        { return false }
func (i fakeBackupFileInfo) Sys() any           { return nil }
