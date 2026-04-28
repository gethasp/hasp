package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// TestDisableConvenienceUnlockClearsEnvelopeWrapAndKeyringEntry locks in the
// hasp-hsq contract: a successful forget-device deletes BOTH the envelope's
// ConvenienceWrap (so OpenWithConvenienceUnlock cannot revive it) and the
// keychain item (so a same-UID attacker cannot read the wrapped key off
// disk and replay it). The first call returns "had wrap = true"; a
// subsequent call is idempotent and returns false without error.
func TestDisableConvenienceUnlockClearsEnvelopeWrapAndKeyringEntry(t *testing.T) {
	keyring := newMemoryKeyring()
	store := newTestStoreWithKeyring(t, keyring)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if err := handle.EnableConvenienceUnlock(context.Background()); err != nil {
		t.Fatalf("enable convenience unlock: %v", err)
	}
	if _, ok := keyring.values[keyringService+"|"+store.keyringAccount()]; !ok {
		t.Fatal("setup invariant: keychain entry should exist after EnableConvenienceUnlock")
	}

	hadWrap, err := handle.DisableConvenienceUnlock(context.Background())
	if err != nil {
		t.Fatalf("DisableConvenienceUnlock: %v", err)
	}
	if !hadWrap {
		t.Fatal("first DisableConvenienceUnlock should report hadWrap=true")
	}

	envelope, err := store.readEnvelope()
	if err != nil {
		t.Fatalf("read envelope: %v", err)
	}
	if envelope.Header.ConvenienceWrap != nil {
		t.Fatalf("expected ConvenienceWrap to be cleared, got %+v", envelope.Header.ConvenienceWrap)
	}
	if _, ok := keyring.values[keyringService+"|"+store.keyringAccount()]; ok {
		t.Fatal("expected keychain entry to be removed")
	}

	if _, err := store.OpenWithConvenienceUnlock(context.Background()); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("OpenWithConvenienceUnlock after forget-device: err=%v want ErrKeyringUnavailable", err)
	}

	hadWrap, err = handle.DisableConvenienceUnlock(context.Background())
	if err != nil {
		t.Fatalf("idempotent DisableConvenienceUnlock: %v", err)
	}
	if hadWrap {
		t.Fatal("second DisableConvenienceUnlock should report hadWrap=false")
	}
}

// TestDisableConvenienceUnlockSurvivesKeyringDeleteFailure ensures the envelope
// mutation still happens even when the keychain delete fails (e.g., user
// revoked keychain access). hasp-hsq is a security-leaning operation: the
// in-vault wrap MUST be cleared so future OpenWithConvenienceUnlock fails
// closed, and the keychain failure surfaces in the returned error so the
// caller can warn the operator about residual on-disk material.
func TestDisableConvenienceUnlockSurvivesKeyringDeleteFailure(t *testing.T) {
	lockStoreSeams(t)
	keyring := &failingDeleteKeyring{memoryKeyring: newMemoryKeyring(), deleteErr: errors.New("keychain refused")}
	store := newTestStoreWithKeyring(t, keyring)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if err := handle.EnableConvenienceUnlock(context.Background()); err != nil {
		t.Fatalf("enable convenience unlock: %v", err)
	}

	_, err = handle.DisableConvenienceUnlock(context.Background())
	if err == nil {
		t.Fatal("expected DisableConvenienceUnlock to surface keychain delete failure")
	}
	if !strings.Contains(err.Error(), "keychain refused") {
		t.Fatalf("error should propagate keychain reason, got %v", err)
	}

	envelope, err := store.readEnvelope()
	if err != nil {
		t.Fatalf("read envelope: %v", err)
	}
	if envelope.Header.ConvenienceWrap != nil {
		t.Fatal("envelope ConvenienceWrap must be cleared even when keychain delete fails")
	}
}

// TestDisableConvenienceUnlockIdempotentSkipsKeychainWhenNoWrap locks in the
// "skip Delete when there's nothing to forget" branch — otherwise vaults
// that never enabled convenience unlock would explode inside `hasp vault
// lock` because macOS returns "item not found" as a generic error.
func TestDisableConvenienceUnlockIdempotentSkipsKeychainWhenNoWrap(t *testing.T) {
	keyring := &countingDeleteKeyring{memoryKeyring: newMemoryKeyring()}
	store := newTestStoreWithKeyring(t, keyring)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}

	hadWrap, err := handle.DisableConvenienceUnlock(context.Background())
	if err != nil {
		t.Fatalf("DisableConvenienceUnlock on fresh vault: %v", err)
	}
	if hadWrap {
		t.Fatal("fresh vault must report hadWrap=false")
	}
	if keyring.deleteCalls != 0 {
		t.Fatalf("fresh vault must not call keychain Delete; saw %d calls", keyring.deleteCalls)
	}
}

// TestDisableConvenienceUnlockReadEnvelopeFailure surfaces a corrupted or
// missing envelope back to the caller instead of pretending the operation
// succeeded.
func TestDisableConvenienceUnlockReadEnvelopeFailure(t *testing.T) {
	lockStoreSeams(t)
	keyring := newMemoryKeyring()
	store := newTestStoreWithKeyring(t, keyring)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}

	if err := os.Remove(store.paths.StatePath); err != nil {
		t.Fatalf("remove state: %v", err)
	}
	if _, err := handle.DisableConvenienceUnlock(context.Background()); err == nil {
		t.Fatal("expected read-envelope failure to surface")
	}
}

// TestDisableConvenienceUnlockWriteEnvelopeFailureSurfaces forces the envelope
// persist step to fail after a wrap exists; the keychain Delete must not fire
// (fail-closed ordering) and the wrapped error must carry "clear convenience
// wrap" so operators can diagnose durability issues separately from keychain
// problems.
func TestDisableConvenienceUnlockWriteEnvelopeFailureSurfaces(t *testing.T) {
	lockStoreSeams(t)
	keyring := &countingDeleteKeyring{memoryKeyring: newMemoryKeyring()}
	store := newTestStoreWithKeyring(t, keyring)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if err := handle.EnableConvenienceUnlock(context.Background()); err != nil {
		t.Fatalf("enable convenience unlock: %v", err)
	}

	origMarshal := jsonMarshalIndentFn
	t.Cleanup(func() { jsonMarshalIndentFn = origMarshal })
	jsonMarshalIndentFn = func(any, string, string) ([]byte, error) {
		return nil, errors.New("marshal boom")
	}

	_, err = handle.DisableConvenienceUnlock(context.Background())
	if err == nil || !strings.Contains(err.Error(), "clear convenience wrap") {
		t.Fatalf("expected write-envelope failure wrapped with context, got %v", err)
	}
	if keyring.deleteCalls != 0 {
		t.Fatalf("write-envelope failure must short-circuit before keychain Delete; saw %d calls", keyring.deleteCalls)
	}
}

// TestDisableConvenienceUnlockTreatsUnavailableKeyringAsSuccess covers the
// ErrKeyringUnavailable branch: if the platform keyring is offline the
// envelope is still cleared and the operation reports success — the on-disk
// wrap is gone, which is the security-meaningful bit.
func TestDisableConvenienceUnlockTreatsUnavailableKeyringAsSuccess(t *testing.T) {
	lockStoreSeams(t)
	keyring := &failingDeleteKeyring{memoryKeyring: newMemoryKeyring(), deleteErr: ErrKeyringUnavailable}
	store := newTestStoreWithKeyring(t, keyring)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if err := handle.EnableConvenienceUnlock(context.Background()); err != nil {
		t.Fatalf("enable convenience unlock: %v", err)
	}

	hadWrap, err := handle.DisableConvenienceUnlock(context.Background())
	if err != nil {
		t.Fatalf("DisableConvenienceUnlock with unavailable keyring: %v", err)
	}
	if !hadWrap {
		t.Fatal("must still report hadWrap=true when envelope leg succeeded")
	}
	envelope, err := store.readEnvelope()
	if err != nil {
		t.Fatalf("read envelope: %v", err)
	}
	if envelope.Header.ConvenienceWrap != nil {
		t.Fatal("envelope must be cleared even when keychain is unavailable")
	}
}

type failingDeleteKeyring struct {
	*memoryKeyring
	deleteErr error
}

func (f *failingDeleteKeyring) Delete(service, account string) error {
	return f.deleteErr
}

type countingDeleteKeyring struct {
	*memoryKeyring
	deleteCalls int
}

func (c *countingDeleteKeyring) Delete(service, account string) error {
	c.deleteCalls++
	return c.memoryKeyring.Delete(service, account)
}
