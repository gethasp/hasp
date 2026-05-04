package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// hasp-wlkm: randomHex previously panic'd on rand.Read failure, which
// turned a recoverable entropy hiccup into a daemon-crash. These tests
// pin the new contract: randomHex returns an error, and high-level
// operations that mint IDs (UpsertItem, GrantProjectLease, UpsertBinding)
// surface that error to the caller without panicking.

func TestRandomHexReturnsErrorOnEntropyFailure(t *testing.T) {
	lockStoreSeams(t)

	origRand := randReadFn
	defer func() { randReadFn = origRand }()
	randReadFn = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

	if _, err := randomHex(4); err == nil {
		t.Fatal("expected randomHex error when randReadFn fails")
	}
}

func TestUpsertItemPropagatesRandomHexError(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	origRand := randReadFn
	defer func() { randReadFn = origRand }()
	randReadFn = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("UpsertItem must not panic on entropy failure; recovered %v", r)
		}
	}()
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("abc123"), ItemMetadata{}); err == nil {
		t.Fatal("expected UpsertItem to surface randomHex error")
	}
}

func TestGrantProjectLeasePropagatesRandomHexError(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	origRand := randReadFn
	defer func() { randReadFn = origRand }()
	randReadFn = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("GrantProjectLease must not panic on entropy failure; recovered %v", r)
		}
	}()
	if _, err := handle.GrantProjectLease("binding-x", "session-y", GrantWindow, time.Minute); err == nil {
		t.Fatal("expected GrantProjectLease to surface randomHex error")
	}
}
