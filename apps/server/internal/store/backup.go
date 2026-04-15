package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

const backupFormatVersion = 1

type BackupFile struct {
	Version         int             `json:"version"`
	ExportedAt      time.Time       `json:"exported_at"`
	KDF             kdfSpec         `json:"kdf"`
	Payload         sealedBlob      `json:"payload"`
	Integrity       string          `json:"integrity"`
	AuditCheckpoint AuditCheckpoint `json:"audit_checkpoint"`
}

type AuditCheckpoint struct {
	Sequence int64  `json:"sequence"`
	Hash     string `json:"hash"`
}

type backupPayload struct {
	State persistedState `json:"state"`
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

	payload := backupPayload{State: h.state}
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
		ExportedAt:      h.store.now(),
		KDF:             kdf,
		Payload:         sealed,
		Integrity:       integrityDigest(plaintext),
		AuditCheckpoint: AuditCheckpoint{Sequence: sequence, Hash: hash},
	}
	data, err := jsonMarshalIndentFn(file, "", "  ")
	if err != nil {
		return AuditCheckpoint{}, fmt.Errorf("encode backup file: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return AuditCheckpoint{}, fmt.Errorf("create backup dir: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0o600); err != nil {
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

func (s *Store) RestoreBackup(ctx context.Context, backupPath string, recoveryPassphrase string, masterPassword string) (AuditCheckpoint, error) {
	if recoveryPassphrase == "" {
		return AuditCheckpoint{}, fmt.Errorf("backup passphrase is required")
	}
	if masterPassword == "" {
		return AuditCheckpoint{}, fmt.Errorf("master password is required")
	}
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return AuditCheckpoint{}, fmt.Errorf("read backup file: %w", err)
	}
	var file BackupFile
	if err := json.Unmarshal(data, &file); err != nil {
		return AuditCheckpoint{}, fmt.Errorf("decode backup file: %w", err)
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

	vaultKey, err := randomBytesFn(keyLength)
	if err != nil {
		return AuditCheckpoint{}, err
	}
	kdf, wrapKey, err := deriveWrapFn(masterPassword)
	if err != nil {
		return AuditCheckpoint{}, err
	}
	passwordWrap, err := sealBytesFn(wrapKey, vaultKey)
	if err != nil {
		return AuditCheckpoint{}, err
	}
	if err := s.writeEnvelope(vaultKey, payload.State, envelopeHeader{
		Version:      formatVersion,
		CreatedAt:    s.now(),
		UpdatedAt:    s.now(),
		KDF:          kdf,
		PasswordWrap: passwordWrap,
	}); err != nil {
		return AuditCheckpoint{}, err
	}
	log, err := newAuditLogFn()
	if err != nil {
		return AuditCheckpoint{}, err
	}
	_, _ = log.Append("restore", "user", map[string]any{
		"source_path":      backupPath,
		"checkpoint_hash":  file.AuditCheckpoint.Hash,
		"checkpoint_seq":   file.AuditCheckpoint.Sequence,
		"new_append_chain": true,
	})
	if handle, err := s.OpenWithPassword(ctx, masterPassword); err == nil {
		_ = handle.EnableConvenienceUnlock(ctx)
	}
	return file.AuditCheckpoint, nil
}

func integrityDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
