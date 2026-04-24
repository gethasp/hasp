package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPlaintextGrantLifecycleAndValidation(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	if got := NamedReference(""); got != "" {
		t.Fatalf("NamedReference empty = %q", got)
	}
	if got := NamedReference(" API_TOKEN "); got != "@API_TOKEN" {
		t.Fatalf("NamedReference trimmed = %q", got)
	}
	if plaintextGrantKey("session", "item", PlaintextReveal) != "session|item|reveal" {
		t.Fatal("unexpected plaintext grant key")
	}

	if _, err := handle.GrantPlaintextUse("", "API_TOKEN", PlaintextReveal, "user", GrantOnce, time.Second); err == nil {
		t.Fatal("expected missing session token failure")
	}
	if _, err := handle.GrantPlaintextUse("session", "", PlaintextReveal, "user", GrantOnce, time.Second); err == nil {
		t.Fatal("expected missing item failure")
	}
	if _, err := handle.GrantPlaintextUse("session", "API_TOKEN", PlaintextAction("bad"), "user", GrantOnce, time.Second); err == nil {
		t.Fatal("expected bad action failure")
	}
	if _, err := handle.GrantPlaintextUse("session", "API_TOKEN", PlaintextReveal, "user", GrantWindow, time.Second); err == nil {
		t.Fatal("expected bad scope failure")
	}
	if _, err := handle.GrantPlaintextUse("session", "API_TOKEN", PlaintextReveal, "user", GrantOnce, MaxPlaintextGrantTTL+time.Second); err == nil {
		t.Fatal("expected ttl limit failure")
	}

	grant, err := handle.GrantPlaintextUse("session", "API_TOKEN", PlaintextReveal, "user", GrantOnce, 0)
	if err != nil {
		t.Fatalf("grant plaintext default ttl: %v", err)
	}
	if grant.ExpiresAt == nil {
		t.Fatal("expected expiresAt on plaintext grant")
	}
	if !handle.PlaintextGrantActive("session", "API_TOKEN", PlaintextReveal) {
		t.Fatal("expected active plaintext grant")
	}
	if err := handle.ConsumePlaintextGrant("session", "API_TOKEN", PlaintextReveal); err != nil {
		t.Fatalf("consume plaintext grant: %v", err)
	}
	if handle.PlaintextGrantActive("session", "API_TOKEN", PlaintextReveal) {
		t.Fatal("expected consumed plaintext grant to be inactive")
	}
	if err := handle.ConsumePlaintextGrant("missing", "API_TOKEN", PlaintextReveal); err != nil {
		t.Fatalf("consume missing plaintext grant: %v", err)
	}

	handle.store.audit = nil
	grant, err = handle.GrantPlaintextUse("session-2", "API_TOKEN", PlaintextCopy, "user", GrantOnce, time.Second)
	if err != nil {
		t.Fatalf("grant plaintext copy with nil audit: %v", err)
	}
	if grant.ID == "" || !handle.PlaintextGrantActive("session-2", "API_TOKEN", PlaintextCopy) {
		t.Fatalf("expected active plaintext copy grant, got %+v", grant)
	}
	if err := handle.ConsumePlaintextGrant("session-2", "API_TOKEN", PlaintextCopy); err != nil {
		t.Fatalf("consume plaintext copy with nil audit: %v", err)
	}
	handle.state.PlaintextGrants[plaintextGrantKey("session-3", "API_TOKEN", PlaintextReveal)] = PlaintextGrant{
		ID:           "session-grant",
		SessionToken: "session-3",
		ItemName:     "API_TOKEN",
		Action:       PlaintextReveal,
		Scope:        GrantSession,
	}
	if err := handle.ConsumePlaintextGrant("session-3", "API_TOKEN", PlaintextReveal); err != nil {
		t.Fatalf("consume session-scope plaintext grant: %v", err)
	}
	if !handle.PlaintextGrantActive("session-3", "API_TOKEN", PlaintextReveal) {
		t.Fatal("expected session-scope plaintext grant to remain active")
	}

	projectRoot := t.TempDir()
	if _, err := handle.UpsertItem("db_url", ItemKindKV, []byte("postgres://db"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert db_url: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "db_url"}, PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	named, err := handle.ResolveReference(context.Background(), projectRoot, "secret_01")
	if err != nil {
		t.Fatalf("resolve alias reference: %v", err)
	}
	if named.NamedReference != "@db_url" {
		t.Fatalf("expected named reference, got %+v", named)
	}
	if _, err := handle.ResolveReference(context.Background(), projectRoot, "@"); !errors.Is(err, ErrReferenceNotFound) {
		t.Fatalf("expected blank named reference to fail, got %v", err)
	}
}
