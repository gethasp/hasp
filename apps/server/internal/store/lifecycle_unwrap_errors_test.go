package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestOpenWithPasswordCollapsesCipherAuthFailureFromReadState locks in the
// contract from hasp-00cp: when the data blob fails GCM authentication while
// being decrypted with the unwrapped vaultKey, the OpenWithPassword caller
// must see ErrInvalidPassword (not "decrypt state: cipher: message
// authentication failed"). Operationally that error mode is identical to the
// password-wrap-side auth failure: the user's response is "type your
// password again", not "the file is corrupt".
func TestOpenWithPasswordCollapsesCipherAuthFailureFromReadState(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	origReadState := readStateFn
	defer func() { readStateFn = origReadState }()
	readStateFn = func([]byte, sealedBlob) (persistedState, error) {
		return persistedState{}, fmt.Errorf("readState: %w", errCipherAuth)
	}

	_, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("OpenWithPassword on cipher-auth readState: err = %v, want ErrInvalidPassword", err)
	}
	if strings.Contains(err.Error(), "decrypt state") {
		t.Fatalf("OpenWithPassword leaked 'decrypt state' phrasing for an auth-tag failure: %v", err)
	}
}

// TestOpenWithConvenienceUnlockCollapsesCipherAuthFailureFromReadState mirrors
// the password path: a stale convenience key whose ciphertext re-auths the
// outer wrap but no longer authenticates the data blob is, from the user's
// perspective, "convenience unlock unavailable" — not a corrupted vault.
func TestOpenWithConvenienceUnlockCollapsesCipherAuthFailureFromReadState(t *testing.T) {
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
	if err := handle.EnableConvenienceUnlock(context.Background()); err != nil {
		t.Fatalf("enable convenience unlock: %v", err)
	}

	origReadState := readStateFn
	defer func() { readStateFn = origReadState }()
	readStateFn = func([]byte, sealedBlob) (persistedState, error) {
		return persistedState{}, fmt.Errorf("readState: %w", errCipherAuth)
	}

	_, err = store.OpenWithConvenienceUnlock(context.Background())
	if !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("OpenWithConvenienceUnlock on cipher-auth readState: err = %v, want ErrKeyringUnavailable", err)
	}
	if strings.Contains(err.Error(), "decrypt state") {
		t.Fatalf("OpenWithConvenienceUnlock leaked 'decrypt state' phrasing for an auth-tag failure: %v", err)
	}
}

// TestOpenWithPasswordPreservesShapeFailuresFromReadState ensures the
// normalization is NARROW: a JSON decode failure (or any non-auth-tag error)
// must still surface as "decrypt state: ..." so a genuinely corrupt vault is
// not misdiagnosed as a typo.
func TestOpenWithPasswordPreservesShapeFailuresFromReadState(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	origReadState := readStateFn
	defer func() { readStateFn = origReadState }()
	readStateFn = func([]byte, sealedBlob) (persistedState, error) {
		return persistedState{}, fmt.Errorf("decode state: bad json")
	}

	_, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err == nil {
		t.Fatal("expected error from corrupt envelope, got nil")
	}
	if errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("shape failure must NOT be collapsed to ErrInvalidPassword, got %v", err)
	}
	if !strings.Contains(err.Error(), "decrypt state") {
		t.Fatalf("shape failure should retain 'decrypt state' wrapping, got %v", err)
	}
}

// TestOpenBytesWrapsCipherAuthFailureWithSentinel locks in that the crypto
// layer marks GCM authentication failures with errCipherAuth so callers can
// errors.Is against it without resorting to string matching against
// 'cipher: message authentication failed'.
func TestOpenBytesWrapsCipherAuthFailureWithSentinel(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	envelope, err := store.readEnvelope()
	if err != nil {
		t.Fatalf("read envelope: %v", err)
	}

	wrongKey := make([]byte, keyLength)
	_, err = openBytes(wrongKey, envelope.Header.PasswordWrap)
	if err == nil {
		t.Fatal("openBytes with wrong key should fail")
	}
	if !errors.Is(err, errCipherAuth) {
		t.Fatalf("openBytes auth failure should errors.Is(errCipherAuth); got %v", err)
	}
}
