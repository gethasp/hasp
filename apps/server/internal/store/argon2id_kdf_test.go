package store

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestDefaultKDFNameIsArgon2id locks in the new vault default — without this,
// `derivePasswordWrap` is free to keep emitting pbkdf2 specs and silently leave
// new vaults on the weak primitive.
func TestDefaultKDFNameIsArgon2id(t *testing.T) {
	if got := DefaultKDFName(); got != "argon2id" {
		t.Fatalf("DefaultKDFName = %q, want argon2id", got)
	}
}

// TestDerivePasswordWrapEmitsArgon2idSpec verifies the on-disk kdfSpec a freshly
// initialised vault writes carries argon2id parameters, not pbkdf2-sha256.
func TestDerivePasswordWrapEmitsArgon2idSpec(t *testing.T) {
	lockStoreSeams(t)
	spec, key, err := derivePasswordWrap("correct horse battery staple")
	if err != nil {
		t.Fatalf("derivePasswordWrap: %v", err)
	}
	if spec.Name != "argon2id" {
		t.Fatalf("spec.Name = %q, want argon2id", spec.Name)
	}
	if spec.Time == 0 || spec.Memory == 0 || spec.Parallelism == 0 {
		t.Fatalf("argon2id spec missing tuning params: %+v", spec)
	}
	if spec.KeyLength != keyLength {
		t.Fatalf("spec.KeyLength = %d, want %d", spec.KeyLength, keyLength)
	}
	if len(key) != keyLength {
		t.Fatalf("derived key length = %d, want %d", len(key), keyLength)
	}
}

// TestNewVaultWritesArgon2idEnvelope walks the full Init path and asserts the
// envelope JSON on disk records KDF.Name == "argon2id". Without this, a future
// refactor to derivePasswordWrap could leave new vaults on pbkdf2 even though
// derivePasswordWrap returns an argon2id spec.
func TestNewVaultWritesArgon2idEnvelope(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	raw, err := os.ReadFile(store.paths.StatePath)
	if err != nil {
		t.Fatalf("read vault: %v", err)
	}
	var envelope fileEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if envelope.Header.KDF.Name != "argon2id" {
		t.Fatalf("envelope KDF.Name = %q, want argon2id", envelope.Header.KDF.Name)
	}
	if envelope.Header.KDF.Time == 0 || envelope.Header.KDF.Memory == 0 {
		t.Fatalf("envelope KDF missing argon2id params: %+v", envelope.Header.KDF)
	}
}

// TestOpenLegacyPbkdf2VaultStillWorks is the migration safety net: a vault
// initialised by an older binary (pbkdf2 spec on disk) MUST keep opening with
// the same master password after the argon2id rollout. Without this, every
// previously-initialised vault becomes unrecoverable on upgrade.
func TestOpenLegacyPbkdf2VaultStillWorks(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)

	// Hand-craft a pbkdf2 envelope by calling the legacy derive helper directly,
	// bypassing the new derivePasswordWrap path. This simulates what a vault
	// written by the previous binary contains: a pbkdf2-sha256 kdfSpec.
	legacySpec := kdfSpec{
		Name:       "pbkdf2-sha256",
		Salt:       "AAECAwQFBgcICQoLDA0ODw==", // 16-byte fixed salt for determinism
		Iterations: testPasswordIterations,
		KeyLength:  keyLength,
	}
	wrapKey, err := deriveFromSpec("legacy-password", legacySpec)
	if err != nil {
		t.Fatalf("legacy deriveFromSpec: %v", err)
	}
	vaultKey := make([]byte, keyLength)
	for i := range vaultKey {
		vaultKey[i] = byte(i + 1)
	}
	passwordWrap, err := sealBytes(wrapKey, vaultKey)
	if err != nil {
		t.Fatalf("seal wrap: %v", err)
	}
	state := persistedState{
		Items:             map[string]Item{},
		Bindings:          map[string]Binding{},
		ProjectLeases:     map[string]ProjectLease{},
		SecretGrants:      map[string]SecretGrant{},
		ConvenienceGrants: map[string]ConvenienceGrant{},
		PlaintextGrants:   map[string]PlaintextGrant{},
	}
	if err := store.writeEnvelope(vaultKey, state, envelopeHeader{
		Version:      formatVersion,
		KDF:          legacySpec,
		PasswordWrap: passwordWrap,
	}); err != nil {
		t.Fatalf("write legacy envelope: %v", err)
	}

	handle, err := store.OpenWithPassword(context.Background(), "legacy-password")
	if err != nil {
		t.Fatalf("open legacy pbkdf2 vault: %v", err)
	}
	if handle == nil {
		t.Fatal("nil handle from legacy unlock")
	}
}

// TestDeriveFromSpecRejectsUnknownKDF guards the dispatch table: an envelope
// with KDF.Name = "blake2bx" must error out instead of silently falling through
// to pbkdf2 (which would compute a key that fails AEAD auth and report
// "wrong password" to the operator instead of "vault is corrupt").
func TestDeriveFromSpecRejectsUnknownKDF(t *testing.T) {
	_, err := deriveFromSpec("password", kdfSpec{
		Name:      "blake2bx-fake",
		Salt:      "AAECAwQFBgcICQoLDA0ODw==",
		KeyLength: keyLength,
	})
	if err == nil {
		t.Fatal("expected unknown KDF to error")
	}
	if !strings.Contains(err.Error(), "kdf") && !strings.Contains(err.Error(), "KDF") {
		t.Fatalf("error should mention kdf, got %q", err.Error())
	}
}

// TestArgon2idSpecRoundtrip confirms a kdfSpec with argon2id params survives
// JSON marshal/unmarshal and re-derives the same key. Catches a regression where
// json tags omit the new Time/Memory/Parallelism fields and they unmarshal as
// zero values, producing a different key.
func TestArgon2idSpecRoundtrip(t *testing.T) {
	spec, key1, err := derivePasswordWrap("password")
	if err != nil {
		t.Fatalf("derivePasswordWrap: %v", err)
	}
	encoded, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	var decoded kdfSpec
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal spec: %v", err)
	}
	key2, err := deriveFromSpec("password", decoded)
	if err != nil {
		t.Fatalf("deriveFromSpec from roundtripped spec: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("argon2id spec round-trip produced a different key — Time/Memory/Parallelism likely missing from JSON")
	}
}

// TestDeriveFromSpecArgon2idBadParams refuses an argon2id spec with zeroed
// tuning params. Without this guard a corrupt envelope could push the runtime
// into argon2's "panic on memory<8" path, surfacing a panic instead of a clean
// "invalid kdf params" error.
func TestDeriveFromSpecArgon2idBadParams(t *testing.T) {
	_, err := deriveFromSpec("password", kdfSpec{
		Name:        "argon2id",
		Salt:        "AAECAwQFBgcICQoLDA0ODw==",
		KeyLength:   keyLength,
		Time:        0,
		Memory:      0,
		Parallelism: 0,
	})
	if err == nil {
		t.Fatal("expected argon2id with zero params to error")
	}
}

