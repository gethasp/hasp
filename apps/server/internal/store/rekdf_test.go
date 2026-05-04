package store

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

// TestRekdfPbkdf2ToArgon2id covers the upgrade path: a vault written with the
// pbkdf2-sha256 KDF must be rewritable to argon2id without changing the
// underlying vault key (so all stored items remain decryptable) and the same
// password must continue to unlock it.
func TestRekdfPbkdf2ToArgon2id(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)

	// Hand-craft a pbkdf2 envelope with a known vault key + a stored item we
	// will assert survives the rekdf cleanly.
	legacySpec := kdfSpec{
		Name:       "pbkdf2-sha256",
		Salt:       "AAECAwQFBgcICQoLDA0ODw==",
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
		Items: map[string]Item{
			"id-1": {ID: "id-1", Name: "API_TOKEN", Kind: ItemKindKV, Value: []byte("supersecret")},
		},
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
		t.Fatalf("open legacy vault: %v", err)
	}

	oldKDF, newKDF, err := handle.RekdfWithPassword(context.Background(), "legacy-password")
	if err != nil {
		t.Fatalf("RekdfWithPassword: %v", err)
	}
	if oldKDF != "pbkdf2-sha256" {
		t.Fatalf("oldKDF = %q, want pbkdf2-sha256", oldKDF)
	}
	if newKDF != "argon2id" {
		t.Fatalf("newKDF = %q, want argon2id", newKDF)
	}

	// Envelope on disk MUST now be argon2id.
	raw, err := os.ReadFile(store.paths.StatePath)
	if err != nil {
		t.Fatalf("read post-rekdf vault: %v", err)
	}
	var envelope fileEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode post-rekdf envelope: %v", err)
	}
	if envelope.Header.KDF.Name != "argon2id" {
		t.Fatalf("post-rekdf KDF.Name = %q, want argon2id", envelope.Header.KDF.Name)
	}
	if envelope.Header.KDF.Iterations != 0 {
		t.Fatalf("post-rekdf envelope still carries pbkdf2 Iterations = %d", envelope.Header.KDF.Iterations)
	}

	// Same password must still unlock the freshly-rewritten vault, and the
	// stored item value must be unchanged (vault key was preserved across the
	// rekdf, so all sealed-under-DEK material survives).
	reopened, err := store.OpenWithPassword(context.Background(), "legacy-password")
	if err != nil {
		t.Fatalf("reopen post-rekdf vault: %v", err)
	}
	got, err := reopened.GetItem("API_TOKEN")
	if err != nil {
		t.Fatalf("GetItem: %v", err)
	}
	if string(got.Value) != "supersecret" {
		t.Fatalf("item value = %q, want supersecret (vault key was rotated, items lost)", string(got.Value))
	}
}

// TestRekdfRejectsWrongPassword confirms the upgrade fails closed when the
// caller passes a password that doesn't currently unlock the vault — without
// this guard, a same-uid attacker could grind passwords by repeatedly calling
// rekdf with guesses (which would no-op silently if it didn't verify).
func TestRekdfRejectsWrongPassword(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, _, err := handle.RekdfWithPassword(context.Background(), "wrong"); err == nil {
		t.Fatal("expected RekdfWithPassword to reject wrong password")
	}
}

// TestRekdfNoOpOnSameKDF is a sanity guard: when the envelope already records
// the binary's current default KDF, rekdf still rewrites with a fresh salt
// (defensive — caller may want to re-randomise the salt) but reports
// oldKDF == newKDF == argon2id and a successful write.
func TestRekdfNoOpOnSameKDF(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	oldKDF, newKDF, err := handle.RekdfWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("rekdf same-kdf: %v", err)
	}
	if oldKDF != "argon2id" || newKDF != "argon2id" {
		t.Fatalf("same-kdf rekdf returned %q -> %q, want argon2id -> argon2id", oldKDF, newKDF)
	}
}

// TestRekdfWritesAuditEvent confirms the upgrade is recorded in the audit log
// so an operator reviewing what happened can correlate the on-disk KDF change
// with a specific moment.
func TestRekdfWritesAuditEvent(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)

	legacySpec := kdfSpec{
		Name:       "pbkdf2-sha256",
		Salt:       "AAECAwQFBgcICQoLDA0ODw==",
		Iterations: testPasswordIterations,
		KeyLength:  keyLength,
	}
	wrapKey, err := deriveFromSpec("p", legacySpec)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	vaultKey := make([]byte, keyLength)
	for i := range vaultKey {
		vaultKey[i] = byte(i + 1)
	}
	passwordWrap, err := sealBytes(wrapKey, vaultKey)
	if err != nil {
		t.Fatalf("seal wrap: %v", err)
	}
	if err := store.writeEnvelope(vaultKey, persistedState{
		Items:             map[string]Item{},
		Bindings:          map[string]Binding{},
		ProjectLeases:     map[string]ProjectLease{},
		SecretGrants:      map[string]SecretGrant{},
		ConvenienceGrants: map[string]ConvenienceGrant{},
		PlaintextGrants:   map[string]PlaintextGrant{},
	}, envelopeHeader{Version: formatVersion, KDF: legacySpec, PasswordWrap: passwordWrap}); err != nil {
		t.Fatalf("write legacy: %v", err)
	}

	handle, err := store.OpenWithPassword(context.Background(), "p")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, _, err := handle.RekdfWithPassword(context.Background(), "p"); err != nil {
		t.Fatalf("rekdf: %v", err)
	}

	events, err := store.audit.Events()
	if err != nil {
		t.Fatalf("audit events: %v", err)
	}
	saw := false
	for _, ev := range events {
		if ev.Type != audit.EventRekdf {
			continue
		}
		from, _ := ev.Details["from"].(string)
		to, _ := ev.Details["to"].(string)
		if from != "pbkdf2-sha256" || to != "argon2id" {
			t.Fatalf("rekdf audit event details: from=%q to=%q", from, to)
		}
		saw = true
	}
	if !saw {
		t.Fatal("expected an audit event of type 'rekdf' after RekdfWithPassword")
	}
}

// TestRekdfUpdatesEnvelopeUpdatedAt covers the timestamp side-effect so an
// operator running `hasp version --json` can correlate the recorded
// updated_at with their rekdf moment.
func TestRekdfUpdatesEnvelopeUpdatedAt(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "p"); err != nil {
		t.Fatalf("init: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "p")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	// Capture pre-rekdf timestamp.
	pre, err := store.readEnvelope()
	if err != nil {
		t.Fatalf("pre read: %v", err)
	}
	preUpdated := pre.Header.UpdatedAt

	// Force the next now() call to return a strictly-later timestamp.
	store.now = func() time.Time { return preUpdated.Add(1 * time.Second) }

	if _, _, err := handle.RekdfWithPassword(context.Background(), "p"); err != nil {
		t.Fatalf("rekdf: %v", err)
	}
	post, err := store.readEnvelope()
	if err != nil {
		t.Fatalf("post read: %v", err)
	}
	if !post.Header.UpdatedAt.After(preUpdated) {
		t.Fatalf("post UpdatedAt %s should be after pre %s", post.Header.UpdatedAt, preUpdated)
	}
}
