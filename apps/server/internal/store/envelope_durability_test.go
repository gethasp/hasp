package store

// RED-phase tests for hasp-0nb: crash-safe vault envelope writes.
//
// This file references fsyncFileFn, fsyncDirFn, and envelopePrevSuffix which
// do NOT yet exist in the production code. The compile failure is the
// intended RED signal.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Test 1: f.Sync() is called on the temp file BEFORE rename completes.
// ---------------------------------------------------------------------------

func TestWriteEnvelopeFsyncsFileBeforeRename(t *testing.T) {
	lockStoreSeams(t)

	store := newTestStore(t)
	envelope := fileEnvelope{
		Header: envelopeHeader{Version: 1},
		Data:   sealedBlob{Nonce: "AA==", Ciphertext: "AA=="},
	}

	syncCalled := false
	origFsyncFile := fsyncFileFn
	defer func() { fsyncFileFn = origFsyncFile }()

	// Replace fsyncFileFn with a recorder that also verifies ordering: at the
	// moment Sync is called, the rename dest must NOT yet exist (i.e. the
	// atomic rename hasn't fired yet).
	fsyncFileFn = func(f *os.File) error {
		// If the destination already exists, the rename happened before Sync — fail hard.
		if _, err := os.Stat(store.paths.StatePath); err == nil {
			t.Errorf("fsyncFileFn: rename already completed before Sync was called")
		}
		syncCalled = true
		return nil
	}

	if err := store.writeEnvelopeFile(envelope); err != nil {
		t.Fatalf("writeEnvelopeFile: %v", err)
	}
	if !syncCalled {
		t.Fatal("expected fsyncFileFn to be called before rename, but it was not called")
	}
}

// ---------------------------------------------------------------------------
// Test 2: parent-dir fsync is called AFTER rename.
// ---------------------------------------------------------------------------

func TestWriteEnvelopeFsyncsParentDirAfterRename(t *testing.T) {
	lockStoreSeams(t)

	store := newTestStore(t)
	envelope := fileEnvelope{
		Header: envelopeHeader{Version: 1},
		Data:   sealedBlob{Nonce: "AA==", Ciphertext: "AA=="},
	}

	dirSyncCalled := false
	wantDir := filepath.Dir(store.paths.StatePath)

	origFsyncDir := fsyncDirFn
	defer func() { fsyncDirFn = origFsyncDir }()

	fsyncDirFn = func(dir string) error {
		// At this point the rename must already have happened.
		if _, err := os.Stat(store.paths.StatePath); err != nil {
			t.Errorf("fsyncDirFn: rename not yet completed when dir fsync was called: %v", err)
		}
		if dir != wantDir {
			t.Errorf("fsyncDirFn: called with dir %q, want %q", dir, wantDir)
		}
		dirSyncCalled = true
		return nil
	}

	if err := store.writeEnvelopeFile(envelope); err != nil {
		t.Fatalf("writeEnvelopeFile: %v", err)
	}
	if !dirSyncCalled {
		t.Fatal("expected fsyncDirFn to be called after rename, but it was not called")
	}
}

// ---------------------------------------------------------------------------
// Test 3: N-1 rotation — existing envelope is copied to .prev before overwrite.
// ---------------------------------------------------------------------------

func TestWriteEnvelopeRotatesPreviousToDotPrev(t *testing.T) {
	store := newTestStore(t)

	envelopeA := fileEnvelope{
		Header: envelopeHeader{Version: 1},
		Data:   sealedBlob{Nonce: "AAA=", Ciphertext: "AAA="},
	}
	envelopeB := fileEnvelope{
		Header: envelopeHeader{Version: 2},
		Data:   sealedBlob{Nonce: "BBB=", Ciphertext: "BBB="},
	}

	// Write A first.
	if err := store.writeEnvelopeFile(envelopeA); err != nil {
		t.Fatalf("write envelopeA: %v", err)
	}

	// Capture the raw bytes of A before overwriting.
	rawA, err := os.ReadFile(store.paths.StatePath)
	if err != nil {
		t.Fatalf("read envelopeA bytes: %v", err)
	}

	// Write B — this should rotate A to .prev.
	if err := store.writeEnvelopeFile(envelopeB); err != nil {
		t.Fatalf("write envelopeB: %v", err)
	}

	prevPath := store.paths.StatePath + envelopePrevSuffix

	// .prev must exist.
	info, err := os.Stat(prevPath)
	if err != nil {
		t.Fatalf(".prev file does not exist after second write: %v", err)
	}

	// .prev must have 0o600 permissions.
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf(".prev permissions = %04o, want 0600", mode)
	}

	// .prev contents must equal raw bytes of A.
	rawPrev, err := os.ReadFile(prevPath)
	if err != nil {
		t.Fatalf("read .prev: %v", err)
	}
	if string(rawPrev) != string(rawA) {
		t.Fatalf(".prev contents differ from envelopeA bytes")
	}
}

// ---------------------------------------------------------------------------
// Test 4: No .prev on the very first write (nothing to rotate).
// ---------------------------------------------------------------------------

func TestWriteEnvelopeRotationSkipsWhenNoPrior(t *testing.T) {
	store := newTestStore(t)

	envelope := fileEnvelope{
		Header: envelopeHeader{Version: 1},
		Data:   sealedBlob{Nonce: "AA==", Ciphertext: "AA=="},
	}

	if err := store.writeEnvelopeFile(envelope); err != nil {
		t.Fatalf("writeEnvelopeFile: %v", err)
	}

	prevPath := store.paths.StatePath + envelopePrevSuffix
	if _, err := os.Stat(prevPath); err == nil {
		t.Fatalf(".prev file exists after first (only) write — expected it to be absent")
	}
}

// ---------------------------------------------------------------------------
// Test 5: readEnvelope falls back to .prev when main file is corrupt.
// ---------------------------------------------------------------------------

func TestReadEnvelopeFallsBackToPrevWhenMainCorrupt(t *testing.T) {
	store := newTestStore(t)

	envelopeA := fileEnvelope{
		Header: envelopeHeader{Version: 1},
		Data:   sealedBlob{Nonce: "AAA=", Ciphertext: "AAA="},
	}
	envelopeB := fileEnvelope{
		Header: envelopeHeader{Version: 2},
		Data:   sealedBlob{Nonce: "BBB=", Ciphertext: "BBB="},
	}

	if err := store.writeEnvelopeFile(envelopeA); err != nil {
		t.Fatalf("write envelopeA: %v", err)
	}
	if err := store.writeEnvelopeFile(envelopeB); err != nil {
		t.Fatalf("write envelopeB: %v", err)
	}

	// Corrupt the main file so JSON unmarshal fails.
	if err := os.WriteFile(store.paths.StatePath, []byte("{corrupted garbage!!!"), 0o600); err != nil {
		t.Fatalf("corrupt main vault: %v", err)
	}

	got, err := store.readEnvelope()
	if err != nil {
		t.Fatalf("readEnvelope with corrupt main: expected fallback success, got error: %v", err)
	}
	if got.Header.Version != envelopeA.Header.Version {
		t.Fatalf("fallback envelope version = %d, want %d (envelopeA)", got.Header.Version, envelopeA.Header.Version)
	}
	if got.Data.Nonce != envelopeA.Data.Nonce {
		t.Fatalf("fallback envelope nonce = %q, want %q", got.Data.Nonce, envelopeA.Data.Nonce)
	}
}

// ---------------------------------------------------------------------------
// Test 6: readEnvelope falls back to .prev when main file is missing.
// ---------------------------------------------------------------------------

func TestReadEnvelopeFallsBackToPrevWhenMainMissing(t *testing.T) {
	store := newTestStore(t)

	envelopeA := fileEnvelope{
		Header: envelopeHeader{Version: 1},
		Data:   sealedBlob{Nonce: "AAA=", Ciphertext: "AAA="},
	}
	envelopeB := fileEnvelope{
		Header: envelopeHeader{Version: 2},
		Data:   sealedBlob{Nonce: "BBB=", Ciphertext: "BBB="},
	}

	if err := store.writeEnvelopeFile(envelopeA); err != nil {
		t.Fatalf("write envelopeA: %v", err)
	}
	if err := store.writeEnvelopeFile(envelopeB); err != nil {
		t.Fatalf("write envelopeB: %v", err)
	}

	// Remove the main file (keep .prev intact).
	if err := os.Remove(store.paths.StatePath); err != nil {
		t.Fatalf("remove main vault: %v", err)
	}

	got, err := store.readEnvelope()
	if err != nil {
		t.Fatalf("readEnvelope with missing main: expected fallback success, got error: %v", err)
	}
	if got.Header.Version != envelopeA.Header.Version {
		t.Fatalf("fallback envelope version = %d, want %d (envelopeA)", got.Header.Version, envelopeA.Header.Version)
	}
}

// ---------------------------------------------------------------------------
// Test 7: fsync-file error → writeEnvelopeFile returns error AND no rename.
// ---------------------------------------------------------------------------

func TestWriteEnvelopeFailsClosedOnFsyncFileError(t *testing.T) {
	lockStoreSeams(t)

	store := newTestStore(t)
	envelope := fileEnvelope{
		Header: envelopeHeader{Version: 1},
		Data:   sealedBlob{Nonce: "AA==", Ciphertext: "AA=="},
	}

	origFsyncFile := fsyncFileFn
	defer func() { fsyncFileFn = origFsyncFile }()

	fsyncFileFn = func(_ *os.File) error {
		return errors.New("simulated fsync-file failure")
	}

	err := store.writeEnvelopeFile(envelope)
	if err == nil {
		t.Fatal("expected writeEnvelopeFile to return error when fsyncFileFn fails")
	}

	// The rename must NOT have happened — StatePath must not exist.
	if _, statErr := os.Stat(store.paths.StatePath); statErr == nil {
		t.Fatal("StatePath exists after fsync-file failure — rename should not have occurred")
	}
}

// ---------------------------------------------------------------------------
// Test 8: fsync-dir error → writeEnvelopeFile returns error (fail-closed).
// ---------------------------------------------------------------------------

func TestWriteEnvelopeFailsClosedOnFsyncDirError(t *testing.T) {
	lockStoreSeams(t)

	store := newTestStore(t)
	envelope := fileEnvelope{
		Header: envelopeHeader{Version: 1},
		Data:   sealedBlob{Nonce: "AA==", Ciphertext: "AA=="},
	}

	origFsyncDir := fsyncDirFn
	defer func() { fsyncDirFn = origFsyncDir }()

	fsyncDirFn = func(_ string) error {
		return errors.New("simulated fsync-dir failure")
	}

	err := store.writeEnvelopeFile(envelope)
	if err == nil {
		t.Fatal("expected writeEnvelopeFile to return error when fsyncDirFn fails")
	}
}
