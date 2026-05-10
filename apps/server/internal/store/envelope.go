package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

const envelopePrevSuffix = ".prev"

var (
	jsonMarshalFn        = json.Marshal
	jsonMarshalIndentFn  = json.MarshalIndent
	mkdirEnvelopeDirFn   = os.MkdirAll
	readEnvelopeFileFn   = os.ReadFile
	writeEnvelopeFileFn  = os.WriteFile
	openEnvelopeFileFn   = os.Open
	statEnvelopeFileFn   = os.Stat
	renameEnvelopeFn     = os.Rename
	removeEnvelopeFileFn = os.Remove

	// fsyncFileFn is called on the temp file after writing, before rename.
	// Tests swap this to verify ordering and simulate failures.
	fsyncFileFn func(*os.File) error = (*os.File).Sync

	// fsyncDirFn is called on the parent directory after rename to flush
	// the directory entry. Tests swap this to verify ordering and simulate failures.
	fsyncDirFn func(string) error = defaultFsyncDir
)

func defaultFsyncDir(dir string) error {
	f, err := openEnvelopeFileFn(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (s *Store) writeEnvelope(vaultKey []byte, state persistedState, header envelopeHeader) error {
	data, err := sealState(vaultKey, state)
	if err != nil {
		return err
	}
	return s.writeEnvelopeFile(fileEnvelope{Header: header, Data: data})
}

// readEnvelopeStrict reads the main envelope file with no .prev fallback.
// Used by persist() so that a corrupt main file surfaces as an error.
func (s *Store) readEnvelopeStrict() (fileEnvelope, error) {
	data, err := readEnvelopeFileFn(s.paths.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return fileEnvelope{}, ErrVaultNotInitialized
	}
	if err != nil {
		return fileEnvelope{}, fmt.Errorf("read vault: %w", err)
	}
	var envelope fileEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fileEnvelope{}, fmt.Errorf("decode vault: %w", err)
	}
	return envelope, nil
}

// readEnvelope reads the main envelope, falling back to .prev when main is
// missing or corrupt. Used by open operations where crash-safety recovery is desired.
func (s *Store) readEnvelope() (fileEnvelope, error) {
	data, err := readEnvelopeFileFn(s.paths.StatePath)
	origErr := err
	var envelope fileEnvelope

	if err == nil {
		jsonErr := json.Unmarshal(data, &envelope)
		if jsonErr == nil {
			return envelope, nil
		}
		// JSON decode failed — treat as original error for fallback reporting.
		origErr = fmt.Errorf("decode vault: %w", jsonErr)
	} else if !errors.Is(err, os.ErrNotExist) {
		origErr = fmt.Errorf("read vault: %w", err)
	}

	// Attempt fallback to .prev.
	prevPath := s.paths.StatePath + envelopePrevSuffix
	prevData, prevErr := readEnvelopeFileFn(prevPath)
	if prevErr != nil {
		// .prev also missing/unreadable — return original error.
		if errors.Is(origErr, os.ErrNotExist) {
			return fileEnvelope{}, ErrVaultNotInitialized
		}
		return fileEnvelope{}, origErr
	}
	var prevEnvelope fileEnvelope
	if jsonErr := json.Unmarshal(prevData, &prevEnvelope); jsonErr != nil {
		// .prev is also corrupt — return original error.
		if errors.Is(origErr, os.ErrNotExist) {
			return fileEnvelope{}, ErrVaultNotInitialized
		}
		return fileEnvelope{}, origErr
	}

	// Fallback succeeded — record degraded-state audit event.
	s.appendAuditBestEffort(audit.EventDeny, "system", map[string]any{
		"action":     "vault.envelope.fallback_to_prev",
		"state_path": s.paths.StatePath,
		"prev_path":  prevPath,
	})
	return prevEnvelope, nil
}

func (s *Store) writeEnvelopeFile(envelope fileEnvelope) error {
	if err := mkdirEnvelopeDirFn(filepath.Dir(s.paths.StatePath), 0o700); err != nil {
		return fmt.Errorf("create vault dir: %w", err)
	}
	data, err := jsonMarshalIndentFn(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("encode vault: %w", err)
	}

	tmp := s.paths.StatePath + ".tmp"
	if err := writeEnvelopeFileFn(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write temp vault: %w", err)
	}

	// Open the temp file to fsync it before rename.
	f, err := openEnvelopeFileFn(tmp)
	if err != nil {
		_ = removeEnvelopeFileFn(tmp)
		return fmt.Errorf("open temp vault for fsync: %w", err)
	}
	if err := fsyncFileFn(f); err != nil {
		_ = f.Close()
		_ = removeEnvelopeFileFn(tmp)
		return fmt.Errorf("fsync temp vault: %w", err)
	}
	_ = f.Close()

	// Copy current main to .prev before rename (fail-closed if copy fails).
	if _, statErr := statEnvelopeFileFn(s.paths.StatePath); statErr == nil {
		existing, readErr := readEnvelopeFileFn(s.paths.StatePath)
		if readErr != nil {
			_ = removeEnvelopeFileFn(tmp)
			return fmt.Errorf("read vault for rotation: %w", readErr)
		}
		prevPath := s.paths.StatePath + envelopePrevSuffix
		if writeErr := writeEnvelopeFileFn(prevPath, existing, 0o600); writeErr != nil {
			_ = removeEnvelopeFileFn(tmp)
			return fmt.Errorf("write prev vault: %w", writeErr)
		}
	}

	// Atomic rename of temp to main.
	if err := renameEnvelopeFn(tmp, s.paths.StatePath); err != nil {
		return fmt.Errorf("rename vault: %w", err)
	}

	// Fsync the parent directory to flush the directory entry.
	if err := fsyncDirFn(filepath.Dir(s.paths.StatePath)); err != nil {
		return fmt.Errorf("fsync vault dir: %w", err)
	}

	return nil
}

func sealState(vaultKey []byte, state persistedState) (sealedBlob, error) {
	if state.Items == nil {
		state.Items = map[string]Item{}
	}
	data, err := jsonMarshalFn(state)
	if err != nil {
		return sealedBlob{}, fmt.Errorf("marshal state: %w", err)
	}
	return sealBytes(vaultKey, data)
}

func readState(vaultKey []byte, blob sealedBlob) (persistedState, error) {
	data, err := openBytes(vaultKey, blob)
	if err != nil {
		return persistedState{}, err
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return persistedState{}, fmt.Errorf("decode state: %w", err)
	}
	if state.Items == nil {
		state.Items = map[string]Item{}
	}
	if state.Bindings == nil {
		state.Bindings = map[string]Binding{}
	}
	if state.ProjectLeases == nil {
		state.ProjectLeases = map[string]ProjectLease{}
	}
	if state.SecretGrants == nil {
		state.SecretGrants = map[string]SecretGrant{}
	}
	if state.ConvenienceGrants == nil {
		state.ConvenienceGrants = map[string]ConvenienceGrant{}
	}
	if state.PlaintextGrants == nil {
		state.PlaintextGrants = map[string]PlaintextGrant{}
	}
	if state.MutationGrants == nil {
		state.MutationGrants = map[string]MutationGrant{}
	}
	if state.ManifestReviews == nil {
		state.ManifestReviews = map[string]ManifestReview{}
	}
	state.Policy = normalizePolicyDocument(state.Policy)
	state.Config = normalizeConfigDocument(state.Config)
	return state, nil
}
