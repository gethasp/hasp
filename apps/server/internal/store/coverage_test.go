package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openedCoverageStore(t *testing.T) (*Store, *Handle) {
	t.Helper()
	s := newTestStore(t)
	if err := s.Init(context.Background(), "coverage-password"); err != nil {
		t.Fatalf("init: %v", err)
	}
	h, err := s.OpenWithPassword(context.Background(), "coverage-password")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s, h
}

func TestCoverageRandomIDAndSmallHelperBranches(t *testing.T) {
	lockStoreSeams(t)
	_, h := openedCoverageStore(t)
	if _, err := h.UpsertItem("api", ItemKindKV, []byte("secret"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}

	origRand := randReadFn
	randReadFn = func([]byte) (int, error) { return 0, errors.New("rand") }
	t.Cleanup(func() { randReadFn = origRand })

	if _, err := h.UpsertBinding(context.Background(), t.TempDir(), nil, PolicySession, false); err == nil || !strings.Contains(err.Error(), "mint binding id") {
		t.Fatalf("expected binding id error, got %v", err)
	}
	if _, err := h.BindItemAlias(context.Background(), t.TempDir(), "api"); err == nil || !strings.Contains(err.Error(), "mint binding id") {
		t.Fatalf("expected alias binding id error, got %v", err)
	}
	if _, err := h.GrantSecretUse("binding", "session", "api", GrantOnce, time.Minute, false); err == nil || !strings.Contains(err.Error(), "mint secret grant id") {
		t.Fatalf("expected secret grant id error, got %v", err)
	}
	expiresAt := h.store.now().Add(time.Hour)
	h.state.ProjectLeases[leaseKey("binding", "session")] = ProjectLease{
		ID:           "lease",
		BindingID:    "binding",
		SessionToken: "session",
		Scope:        GrantWindow,
		ExpiresAt:    &expiresAt,
	}
	if _, err := h.GrantConvenience("binding", "session", "/tmp/out", []string{"api"}, "agent", GrantOnce, time.Minute); err == nil || !strings.Contains(err.Error(), "mint convenience grant id") {
		t.Fatalf("expected convenience grant id error, got %v", err)
	}
	if _, err := h.GrantPlaintextUse("session", "api", PlaintextReveal, "agent", GrantOnce, time.Minute); err == nil || !strings.Contains(err.Error(), "mint plaintext grant id") {
		t.Fatalf("expected plaintext grant id error, got %v", err)
	}

	if uniformPassword("") {
		t.Fatal("empty password should not count as uniform")
	}
	if got := ((*Handle)(nil)).AuditHMACKey(); got != nil {
		t.Fatalf("nil handle audit key = %x", got)
	}
	emptyKeyHandle := &Handle{}
	if got := emptyKeyHandle.AuditHMACKey(); got != nil {
		t.Fatalf("empty handle audit key = %x", got)
	}
	keyed := &Handle{vaultKey: bytes.Repeat([]byte{7}, keyLength)}
	if got := keyed.AuditHMACKey(); len(got) != 32 {
		t.Fatalf("audit hmac key len = %d", len(got))
	}
}

func TestCoverageEnvelopeErrorBranches(t *testing.T) {
	lockStoreSeams(t)
	origMkdir := mkdirEnvelopeDirFn
	origRead := readEnvelopeFileFn
	origWrite := writeEnvelopeFileFn
	origOpen := openEnvelopeFileFn
	origStat := statEnvelopeFileFn
	origRename := renameEnvelopeFn
	origRemove := removeEnvelopeFileFn
	t.Cleanup(func() {
		mkdirEnvelopeDirFn = origMkdir
		readEnvelopeFileFn = origRead
		writeEnvelopeFileFn = origWrite
		openEnvelopeFileFn = origOpen
		statEnvelopeFileFn = origStat
		renameEnvelopeFn = origRename
		removeEnvelopeFileFn = origRemove
	})

	openEnvelopeFileFn = func(string) (*os.File, error) { return nil, errors.New("open") }
	if err := defaultFsyncDir(t.TempDir()); err == nil {
		t.Fatal("expected defaultFsyncDir open error")
	}
	openEnvelopeFileFn = origOpen

	s := newTestStore(t)
	if _, err := s.readEnvelopeStrict(); !errors.Is(err, ErrVaultNotInitialized) {
		t.Fatalf("expected strict missing vault error, got %v", err)
	}
	readEnvelopeFileFn = func(string) ([]byte, error) { return nil, errors.New("read") }
	if _, err := s.readEnvelopeStrict(); err == nil || !strings.Contains(err.Error(), "read vault") {
		t.Fatalf("expected strict read error, got %v", err)
	}
	readEnvelopeFileFn = origRead

	if err := os.MkdirAll(filepath.Dir(s.paths.StatePath), 0o700); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	if err := os.WriteFile(s.paths.StatePath+envelopePrevSuffix, []byte("{bad"), 0o600); err != nil {
		t.Fatalf("write prev: %v", err)
	}
	if _, err := s.readEnvelope(); !errors.Is(err, ErrVaultNotInitialized) {
		t.Fatalf("expected corrupt prev with missing main to report uninitialized, got %v", err)
	}
	if err := os.WriteFile(s.paths.StatePath, []byte("{bad-main"), 0o600); err != nil {
		t.Fatalf("write main: %v", err)
	}
	if _, err := s.readEnvelope(); err == nil || !strings.Contains(err.Error(), "decode vault") {
		t.Fatalf("expected corrupt main to win over corrupt prev, got %v", err)
	}

	env := fileEnvelope{Header: envelopeHeader{Version: formatVersion}}
	openEnvelopeFileFn = func(name string) (*os.File, error) {
		if strings.HasSuffix(name, ".tmp") {
			return nil, errors.New("open temp")
		}
		return origOpen(name)
	}
	if err := s.writeEnvelopeFile(env); err == nil || !strings.Contains(err.Error(), "open temp vault") {
		t.Fatalf("expected open temp error, got %v", err)
	}
	openEnvelopeFileFn = origOpen

	if err := os.WriteFile(s.paths.StatePath, []byte("existing"), 0o600); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	readEnvelopeFileFn = func(name string) ([]byte, error) {
		if name == s.paths.StatePath {
			return nil, errors.New("read rotate")
		}
		return origRead(name)
	}
	if err := s.writeEnvelopeFile(env); err == nil || !strings.Contains(err.Error(), "read vault for rotation") {
		t.Fatalf("expected rotation read error, got %v", err)
	}
	readEnvelopeFileFn = origRead

	writeEnvelopeFileFn = func(name string, data []byte, perm os.FileMode) error {
		if strings.HasSuffix(name, envelopePrevSuffix) {
			return errors.New("write prev")
		}
		return origWrite(name, data, perm)
	}
	if err := s.writeEnvelopeFile(env); err == nil || !strings.Contains(err.Error(), "write prev vault") {
		t.Fatalf("expected prev write error, got %v", err)
	}
	writeEnvelopeFileFn = origWrite

	renameEnvelopeFn = func(string, string) error { return errors.New("rename") }
	if err := s.writeEnvelopeFile(env); err == nil || !strings.Contains(err.Error(), "rename vault") {
		t.Fatalf("expected rename error, got %v", err)
	}
	renameEnvelopeFn = origRename

	mkdirEnvelopeDirFn = func(string, os.FileMode) error { return errors.New("mkdir") }
	if err := s.writeEnvelopeFile(env); err == nil || !strings.Contains(err.Error(), "create vault dir") {
		t.Fatalf("expected mkdir error, got %v", err)
	}
	mkdirEnvelopeDirFn = origMkdir
}

func TestCoverageRekdfAndRekeyErrorBranches(t *testing.T) {
	lockStoreSeams(t)
	origDeriveSpec := deriveSpecFn
	origDeriveWrap := deriveWrapFn
	origSeal := sealBytesFn
	origRead := readEnvelopeFileFn
	origFsyncDir := fsyncDirFn
	t.Cleanup(func() {
		deriveSpecFn = origDeriveSpec
		deriveWrapFn = origDeriveWrap
		sealBytesFn = origSeal
		readEnvelopeFileFn = origRead
		fsyncDirFn = origFsyncDir
	})

	t.Run("rekdf read error", func(t *testing.T) {
		_, h := openedCoverageStore(t)
		readEnvelopeFileFn = func(string) ([]byte, error) { return nil, errors.New("read") }
		if _, _, err := h.RekdfWithPassword(context.Background(), "coverage-password"); err == nil {
			t.Fatal("expected rekdf read error")
		}
		readEnvelopeFileFn = origRead
	})

	t.Run("rekdf empty legacy kdf name", func(t *testing.T) {
		s := newTestStore(t)
		legacySpec := kdfSpec{
			Name:       "",
			Salt:       base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)),
			Iterations: testPasswordIterations,
			KeyLength:  keyLength,
		}
		wrapKey, err := deriveFromSpec("legacy-password", legacySpec)
		if err != nil {
			t.Fatalf("derive legacy: %v", err)
		}
		vaultKey := bytes.Repeat([]byte{2}, keyLength)
		passwordWrap, err := sealBytes(wrapKey, vaultKey)
		if err != nil {
			t.Fatalf("seal wrap: %v", err)
		}
		if err := s.writeEnvelope(vaultKey, persistedState{}, envelopeHeader{Version: formatVersion, KDF: legacySpec, PasswordWrap: passwordWrap}); err != nil {
			t.Fatalf("write legacy: %v", err)
		}
		h, err := s.OpenWithPassword(context.Background(), "legacy-password")
		if err != nil {
			t.Fatalf("open legacy: %v", err)
		}
		oldKDF, _, err := h.RekdfWithPassword(context.Background(), "legacy-password")
		if err != nil {
			t.Fatalf("rekdf legacy: %v", err)
		}
		if oldKDF != "pbkdf2-sha256" {
			t.Fatalf("oldKDF = %q", oldKDF)
		}
	})

	t.Run("rekdf derivation and write failures", func(t *testing.T) {
		_, h := openedCoverageStore(t)
		deriveSpecFn = func(string, kdfSpec) ([]byte, error) { return nil, errors.New("derive old") }
		if _, _, err := h.RekdfWithPassword(context.Background(), "coverage-password"); err == nil {
			t.Fatal("expected old derive error")
		}
		deriveSpecFn = origDeriveSpec

		deriveWrapFn = func(string) (kdfSpec, []byte, error) { return kdfSpec{}, nil, errors.New("derive new") }
		if _, _, err := h.RekdfWithPassword(context.Background(), "coverage-password"); err == nil {
			t.Fatal("expected new derive error")
		}
		deriveWrapFn = origDeriveWrap

		sealBytesFn = func([]byte, []byte) (sealedBlob, error) { return sealedBlob{}, errors.New("seal") }
		if _, _, err := h.RekdfWithPassword(context.Background(), "coverage-password"); err == nil {
			t.Fatal("expected seal error")
		}
		sealBytesFn = origSeal

		fsyncDirFn = func(string) error { return errors.New("fsync") }
		if _, _, err := h.RekdfWithPassword(context.Background(), "coverage-password"); err == nil {
			t.Fatal("expected rekdf write error")
		}
		fsyncDirFn = origFsyncDir
	})

	t.Run("rekey validation and read errors", func(t *testing.T) {
		_, h := openedCoverageStore(t)
		if err := h.RekeyPassword(context.Background(), "", "new-password"); err == nil {
			t.Fatal("expected old password validation error")
		}
		readEnvelopeFileFn = func(string) ([]byte, error) { return nil, errors.New("read") }
		if err := h.RekeyPassword(context.Background(), "coverage-password", "new-password"); err == nil {
			t.Fatal("expected rekey read error")
		}
		readEnvelopeFileFn = origRead
	})

	t.Run("rekey derivation and write failures", func(t *testing.T) {
		_, h := openedCoverageStore(t)
		deriveSpecFn = func(string, kdfSpec) ([]byte, error) { return nil, errors.New("derive old") }
		if err := h.RekeyPassword(context.Background(), "coverage-password", "new-password"); err == nil {
			t.Fatal("expected rekey old derive error")
		}
		deriveSpecFn = origDeriveSpec

		deriveWrapFn = func(string) (kdfSpec, []byte, error) { return kdfSpec{}, nil, errors.New("derive new") }
		if err := h.RekeyPassword(context.Background(), "coverage-password", "new-password"); err == nil {
			t.Fatal("expected rekey new derive error")
		}
		deriveWrapFn = origDeriveWrap

		sealBytesFn = func([]byte, []byte) (sealedBlob, error) { return sealedBlob{}, errors.New("seal") }
		if err := h.RekeyPassword(context.Background(), "coverage-password", "new-password"); err == nil {
			t.Fatal("expected rekey seal error")
		}
		sealBytesFn = origSeal

		fsyncDirFn = func(string) error { return errors.New("fsync") }
		if err := h.RekeyPassword(context.Background(), "coverage-password", "new-password"); err == nil {
			t.Fatal("expected rekey write error")
		}
		fsyncDirFn = origFsyncDir
	})
}
