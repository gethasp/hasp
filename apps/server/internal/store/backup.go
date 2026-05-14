package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

const backupFormatVersion = 1

var (
	backupReadFile  = os.ReadFile
	backupWriteFile = os.WriteFile
	backupMkdirAll  = os.MkdirAll
	backupRemove    = os.Remove
	backupReadDir   = os.ReadDir
)

type BackupFile struct {
	Version         int             `json:"version"`
	VaultID         string          `json:"vault_id,omitempty"`
	ExportedAt      time.Time       `json:"exported_at"`
	KDF             kdfSpec         `json:"kdf"`
	Payload         sealedBlob      `json:"payload"`
	Integrity       string          `json:"integrity"`
	AuditCheckpoint AuditCheckpoint `json:"audit_checkpoint"`
	Signature       BackupSignature `json:"signature,omitempty"`
}

type AuditCheckpoint struct {
	Sequence int64  `json:"sequence"`
	Hash     string `json:"hash"`
}

type BackupSignature struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	Value     string `json:"value"`
}

type BackupSignatureStatus struct {
	Signed            bool   `json:"signed"`
	Trusted           bool   `json:"trusted"`
	Required          bool   `json:"required"`
	TrustRootCount    int    `json:"trust_root_count"`
	SignerFingerprint string `json:"signer_fingerprint,omitempty"`
	Error             string `json:"error,omitempty"`
}

type backupPayload struct {
	State      persistedState `json:"state"`
	VaultKey   []byte         `json:"vault_key,omitempty"`
	AuditJSONL []byte         `json:"audit_jsonl,omitempty"`
}

func (h *Handle) ExportBackup(_ context.Context, outputPath string, recoveryPassphrase string) (AuditCheckpoint, error) {
	if recoveryPassphrase == "" {
		return AuditCheckpoint{}, fmt.Errorf("backup passphrase is required")
	}
	log, err := newAuditLogFn()
	if err != nil {
		return AuditCheckpoint{}, err
	}
	sequence, hash, err := log.Checkpoint()
	if err != nil {
		return AuditCheckpoint{}, err
	}

	payload := backupPayload{
		State:    h.state,
		VaultKey: append([]byte(nil), h.vaultKey...),
	}
	if auditJSONL, err := backupReadFile(h.store.paths.AuditPath); err == nil {
		payload.AuditJSONL = auditJSONL
	} else if !os.IsNotExist(err) {
		return AuditCheckpoint{}, fmt.Errorf("read audit chain: %w", err)
	}
	plaintext, err := jsonMarshalFn(payload)
	if err != nil {
		return AuditCheckpoint{}, fmt.Errorf("encode backup payload: %w", err)
	}
	kdf, wrapKey, err := deriveWrapFn(recoveryPassphrase)
	if err != nil {
		return AuditCheckpoint{}, err
	}
	sealed, err := sealBytesFn(wrapKey, plaintext)
	if err != nil {
		return AuditCheckpoint{}, err
	}
	file := BackupFile{
		Version:         backupFormatVersion,
		VaultID:         h.BackupVaultID(),
		ExportedAt:      h.store.now(),
		KDF:             kdf,
		Payload:         sealed,
		Integrity:       integrityDigest(plaintext),
		AuditCheckpoint: AuditCheckpoint{Sequence: sequence, Hash: hash},
	}
	if err := signBackupFile(&file); err != nil {
		return AuditCheckpoint{}, err
	}
	data, err := jsonMarshalIndentFn(file, "", "  ")
	if err != nil {
		return AuditCheckpoint{}, fmt.Errorf("encode backup file: %w", err)
	}
	if err := backupMkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return AuditCheckpoint{}, fmt.Errorf("create backup dir: %w", err)
	}
	if err := backupWriteFile(outputPath, data, 0o600); err != nil {
		return AuditCheckpoint{}, fmt.Errorf("write backup file: %w", err)
	}
	h.store.appendAuditBestEffort(audit.EventOverride, "user", map[string]any{
		"action":           "backup.export",
		"output_path":      outputPath,
		"audit_sequence":   sequence,
		"audit_checkpoint": hash,
	})
	return file.AuditCheckpoint, nil
}

func (h *Handle) BackupVaultID() string {
	return backupVaultID(h.vaultKey)
}

func backupVaultID(vaultKey []byte) string {
	sum := sha256.Sum256(vaultKey)
	return hex.EncodeToString(sum[:])
}

func (s *Store) RestoreBackup(ctx context.Context, backupPath string, recoveryPassphrase string, masterPassword string) (AuditCheckpoint, error) {
	if recoveryPassphrase == "" {
		return AuditCheckpoint{}, fmt.Errorf("backup passphrase is required")
	}
	if masterPassword == "" {
		return AuditCheckpoint{}, fmt.Errorf("master password is required")
	}
	data, err := backupReadFile(backupPath)
	if err != nil {
		return AuditCheckpoint{}, fmt.Errorf("read backup file: %w", err)
	}
	var file BackupFile
	if err := json.Unmarshal(data, &file); err != nil {
		return AuditCheckpoint{}, fmt.Errorf("decode backup file: %w", err)
	}
	if err := verifyBackupFileSignature(file); err != nil {
		return AuditCheckpoint{}, err
	}
	key, err := deriveFromSpec(recoveryPassphrase, file.KDF)
	if err != nil {
		return AuditCheckpoint{}, err
	}
	plaintext, err := openBytes(key, file.Payload)
	if err != nil {
		return AuditCheckpoint{}, fmt.Errorf("decrypt backup payload: %w", err)
	}
	if integrityDigest(plaintext) != file.Integrity {
		return AuditCheckpoint{}, fmt.Errorf("backup integrity check failed")
	}
	var payload backupPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return AuditCheckpoint{}, fmt.Errorf("decode backup payload: %w", err)
	}
	vaultKey := append([]byte(nil), payload.VaultKey...)
	if len(vaultKey) == 0 {
		vaultKey, err = randomBytesFn(keyLength)
		if err != nil {
			return AuditCheckpoint{}, err
		}
	} else if len(vaultKey) != keyLength {
		return AuditCheckpoint{}, fmt.Errorf("backup vault key is invalid")
	}
	kdf, wrapKey, err := deriveWrapFn(masterPassword)
	if err != nil {
		return AuditCheckpoint{}, err
	}
	passwordWrap, err := sealBytesFn(wrapKey, vaultKey)
	if err != nil {
		return AuditCheckpoint{}, err
	}
	snapshot, err := s.createPreRestoreSnapshot()
	if err != nil {
		return AuditCheckpoint{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = s.restorePreRestoreSnapshot(snapshot)
		}
	}()
	if err := s.writeEnvelope(vaultKey, payload.State, envelopeHeader{
		Version:      formatVersion,
		CreatedAt:    s.now(),
		UpdatedAt:    s.now(),
		KDF:          kdf,
		PasswordWrap: passwordWrap,
	}); err != nil {
		return AuditCheckpoint{}, err
	}
	if len(payload.AuditJSONL) > 0 {
		if err := backupMkdirAll(filepath.Dir(s.paths.AuditPath), 0o700); err != nil {
			return AuditCheckpoint{}, fmt.Errorf("create audit dir: %w", err)
		}
		if err := backupWriteFile(s.paths.AuditPath, payload.AuditJSONL, 0o600); err != nil {
			return AuditCheckpoint{}, fmt.Errorf("restore audit chain: %w", err)
		}
	}
	log, err := newAuditLogFn()
	if err != nil {
		return AuditCheckpoint{}, err
	}
	if len(vaultKey) > 0 {
		log = log.WithKey((&Handle{vaultKey: vaultKey}).AuditHMACKey())
	}
	if _, err := log.Append("restore", "user", map[string]any{
		"source_path":      backupPath,
		"checkpoint_hash":  file.AuditCheckpoint.Hash,
		"checkpoint_seq":   file.AuditCheckpoint.Sequence,
		"new_append_chain": true,
	}); err != nil {
		return AuditCheckpoint{}, fmt.Errorf("append restore audit event: %w", err)
	}
	committed = true
	if handle, err := s.OpenWithPassword(ctx, masterPassword); err == nil {
		_ = handle.EnableConvenienceUnlock(ctx)
	}
	return file.AuditCheckpoint, nil
}

func integrityDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func signBackupFile(file *BackupFile) error {
	if file == nil {
		return fmt.Errorf("backup file is required")
	}
	privateKey, ok, err := backupSigningPrivateKey()
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if trusted, _, err := backupTrustedPublicKeys(); err != nil {
		return err
	} else if len(trusted) > 0 && !slices.ContainsFunc(trusted, func(candidate ed25519.PublicKey) bool {
		return string(candidate) == string(publicKey)
	}) {
		return fmt.Errorf("backup signing key is not trusted")
	}
	payload, err := backupSigningPayload(*file)
	if err != nil {
		return err
	}
	file.Signature = BackupSignature{
		Algorithm: "Ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}
	return nil
}

func BackupSignatureStatusForFile(path string) (BackupSignatureStatus, error) {
	data, err := backupReadFile(path)
	if err != nil {
		return BackupSignatureStatus{}, fmt.Errorf("read backup file: %w", err)
	}
	var file BackupFile
	if err := json.Unmarshal(data, &file); err != nil {
		return BackupSignatureStatus{}, fmt.Errorf("decode backup file: %w", err)
	}
	return BackupSignatureStatusForBackupFile(file)
}

func BackupSignatureStatusForBackupFile(file BackupFile) (BackupSignatureStatus, error) {
	trusted, required, err := backupTrustedPublicKeys()
	if err != nil {
		return BackupSignatureStatus{}, err
	}
	status := BackupSignatureStatus{
		Required:       required,
		TrustRootCount: len(trusted),
	}
	if file.Signature.Value == "" && file.Signature.PublicKey == "" {
		if required {
			status.Error = "backup signature is required"
		}
		return status, nil
	}
	status.Signed = true
	if !strings.EqualFold(strings.TrimSpace(file.Signature.Algorithm), "Ed25519") {
		status.Error = "backup signature algorithm is unsupported"
		return status, nil
	}
	publicKey, err := base64.StdEncoding.DecodeString(file.Signature.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		status.Error = "backup signature public key is invalid"
		return status, nil
	}
	fingerprint := sha256.Sum256(publicKey)
	status.SignerFingerprint = hex.EncodeToString(fingerprint[:])
	status.Trusted = slices.ContainsFunc(trusted, func(candidate ed25519.PublicKey) bool {
		return string(candidate) == string(publicKey)
	})
	if required && !status.Trusted {
		status.Error = "backup signature signer is not trusted"
	}
	return status, nil
}

func verifyBackupFileSignature(file BackupFile) error {
	if file.Signature.Value == "" && file.Signature.PublicKey == "" {
		_, required, err := backupTrustedPublicKeys()
		if err != nil {
			return err
		}
		if required {
			return fmt.Errorf("backup signature is required")
		}
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(file.Signature.Algorithm), "Ed25519") {
		return fmt.Errorf("backup signature algorithm is unsupported")
	}
	publicKey, err := base64.StdEncoding.DecodeString(file.Signature.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("backup signature public key is invalid")
	}
	signature, err := base64.StdEncoding.DecodeString(file.Signature.Value)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("backup signature is invalid")
	}
	trusted, required, err := backupTrustedPublicKeys()
	if err != nil {
		return err
	}
	if !required {
		return fmt.Errorf("backup signature trust roots are not configured")
	}
	if !slices.ContainsFunc(trusted, func(candidate ed25519.PublicKey) bool {
		return string(candidate) == string(publicKey)
	}) {
		return fmt.Errorf("backup signature signer is not trusted")
	}
	payload, err := backupSigningPayload(file)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		return fmt.Errorf("backup signature verification failed")
	}
	return nil
}

func backupSigningPayload(file BackupFile) ([]byte, error) {
	file.Signature = BackupSignature{}
	data, err := jsonMarshalFn(file)
	if err != nil {
		return nil, fmt.Errorf("encode backup signature payload: %w", err)
	}
	return data, nil
}

type preRestoreSnapshot struct {
	Dir string
}

func (s *Store) createPreRestoreSnapshot() (preRestoreSnapshot, error) {
	dir := filepath.Join(s.paths.HomeDir, fmt.Sprintf(".pre-restore-%d", s.now().UnixNano()))
	if err := backupMkdirAll(dir, 0o700); err != nil {
		return preRestoreSnapshot{}, fmt.Errorf("create pre-restore snapshot: %w", err)
	}
	for _, file := range []struct {
		source string
		name   string
	}{
		{source: s.paths.StatePath, name: "vault.json"},
		{source: s.paths.AuditPath, name: "audit.jsonl"},
	} {
		data, err := backupReadFile(file.source)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return preRestoreSnapshot{}, fmt.Errorf("snapshot %s: %w", file.name, err)
		}
		if err := backupWriteFile(filepath.Join(dir, file.name), data, 0o600); err != nil {
			return preRestoreSnapshot{}, fmt.Errorf("write pre-restore %s: %w", file.name, err)
		}
	}
	return preRestoreSnapshot{Dir: dir}, nil
}

func (s *Store) restorePreRestoreSnapshot(snapshot preRestoreSnapshot) error {
	if snapshot.Dir == "" {
		return nil
	}
	for _, file := range []struct {
		target string
		name   string
	}{
		{target: s.paths.StatePath, name: "vault.json"},
		{target: s.paths.AuditPath, name: "audit.jsonl"},
	} {
		snapshotPath := filepath.Join(snapshot.Dir, file.name)
		data, err := backupReadFile(snapshotPath)
		if err != nil {
			if os.IsNotExist(err) {
				if removeErr := backupRemove(file.target); removeErr != nil && !os.IsNotExist(removeErr) {
					return fmt.Errorf("remove restored %s: %w", file.name, removeErr)
				}
				continue
			}
			return fmt.Errorf("read pre-restore %s: %w", file.name, err)
		}
		if err := backupMkdirAll(filepath.Dir(file.target), 0o700); err != nil {
			return fmt.Errorf("create restore dir for %s: %w", file.name, err)
		}
		if err := backupWriteFile(file.target, data, 0o600); err != nil {
			return fmt.Errorf("restore %s: %w", file.name, err)
		}
	}
	return nil
}

func backupSigningPrivateKey() (ed25519.PrivateKey, bool, error) {
	raw := strings.TrimSpace(os.Getenv("HASP_BACKUP_SIGNING_KEY_B64"))
	if raw != "" {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, false, fmt.Errorf("decode HASP_BACKUP_SIGNING_KEY_B64: %w", err)
		}
		if len(key) != ed25519.PrivateKeySize {
			return nil, false, fmt.Errorf("HASP_BACKUP_SIGNING_KEY_B64 must decode to %d bytes", ed25519.PrivateKeySize)
		}
		return ed25519.PrivateKey(key), true, nil
	}
	raw = strings.TrimSpace(os.Getenv("HASP_BACKUP_SIGNING_KEY_HEX"))
	if raw == "" {
		return nil, false, nil
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, false, fmt.Errorf("decode HASP_BACKUP_SIGNING_KEY_HEX: %w", err)
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, false, fmt.Errorf("HASP_BACKUP_SIGNING_KEY_HEX must decode to %d bytes", ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(key), true, nil
}

func backupTrustedPublicKeys() ([]ed25519.PublicKey, bool, error) {
	raw := strings.TrimSpace(os.Getenv("HASP_BACKUP_TRUST_ROOTS_HEX"))
	if raw == "" {
		return nil, false, nil
	}
	parts := strings.Split(raw, ",")
	keys := make([]ed25519.PublicKey, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, err := hex.DecodeString(part)
		if err != nil {
			return nil, true, fmt.Errorf("decode HASP_BACKUP_TRUST_ROOTS_HEX: %w", err)
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, true, fmt.Errorf("HASP_BACKUP_TRUST_ROOTS_HEX keys must be %d bytes", ed25519.PublicKeySize)
		}
		keys = append(keys, ed25519.PublicKey(key))
	}
	if len(keys) == 0 {
		return nil, true, fmt.Errorf("HASP_BACKUP_TRUST_ROOTS_HEX does not contain a key")
	}
	return keys, true, nil
}

func PruneBackupDirectory(dir string, keep int, vaultID string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" || keep < 1 {
		return nil
	}
	vaultID = strings.TrimSpace(vaultID)
	entries, err := backupReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read backup dir: %w", err)
	}
	type candidate struct {
		path    string
		modTime time.Time
	}
	candidates := make([]candidate, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".hasp-backup") {
			continue
		}
		path := filepath.Join(dir, name)
		if vaultID != "" {
			fileVaultID, err := readBackupVaultID(path)
			if err != nil {
				return fmt.Errorf("read backup %s identity: %w", name, err)
			}
			if fileVaultID != vaultID {
				continue
			}
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat backup %s: %w", name, err)
		}
		candidates = append(candidates, candidate{
			path:    path,
			modTime: info.ModTime(),
		})
	}
	slices.SortFunc(candidates, func(a, b candidate) int {
		return b.modTime.Compare(a.modTime)
	})
	if len(candidates) <= keep {
		return nil
	}
	for _, stale := range candidates[keep:] {
		if err := backupRemove(stale.path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale backup: %w", err)
		}
	}
	return nil
}

func readBackupVaultID(path string) (string, error) {
	data, err := backupReadFile(path)
	if err != nil {
		return "", err
	}
	var file BackupFile
	if err := json.Unmarshal(data, &file); err != nil {
		return "", err
	}
	return strings.TrimSpace(file.VaultID), nil
}
