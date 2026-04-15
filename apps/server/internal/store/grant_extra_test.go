package store

import (
	"context"
	"testing"
	"time"
)

func TestConsumeProjectLeaseOnce(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{}, PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, "session-token", GrantOnce, 0); err != nil {
		t.Fatalf("grant project lease: %v", err)
	}
	if err := handle.ConsumeProjectLease(binding.ID, "session-token"); err != nil {
		t.Fatalf("consume project lease: %v", err)
	}
	decision := handle.Authorize(AccessRequest{
		Operation:    OperationList,
		BindingID:    binding.ID,
		SessionToken: "session-token",
	})
	if !decision.RequiresPrompt {
		t.Fatalf("expected prompt after consuming once lease")
	}
}

func TestConsumeConvenienceGrantOnce(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := handle.UpsertItem("db_url", ItemKindKV, []byte("postgres://db"), ItemMetadata{Policy: PolicySession}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{"secret_01": "db_url"}, PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, "session-token", GrantSession, 0); err != nil {
		t.Fatalf("grant lease: %v", err)
	}
	if _, err := handle.GrantSecretUse(binding.ID, "session-token", "db_url", GrantSession, 0, false); err != nil {
		t.Fatalf("grant secret: %v", err)
	}
	if _, err := handle.GrantConvenience(binding.ID, "session-token", "/tmp/.env.local", []string{"db_url"}, "user", GrantOnce, time.Minute); err != nil {
		t.Fatalf("grant convenience: %v", err)
	}
	if err := handle.ConsumeConvenienceGrant(binding.ID, "/tmp/.env.local", []string{"db_url"}); err != nil {
		t.Fatalf("consume convenience: %v", err)
	}
	decision := handle.Authorize(AccessRequest{
		Operation:       OperationWriteEnv,
		BindingID:       binding.ID,
		SessionToken:    "session-token",
		ItemName:        "db_url",
		Policy:          PolicySession,
		DestinationPath: "/tmp/.env.local",
		Aliases:         []string{"db_url"},
	})
	if !decision.RequiresPrompt {
		t.Fatalf("expected prompt after consuming once convenience grant")
	}
}

func TestAccessWindowOverridePath(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("abc123"), ItemMetadata{Policy: PolicyAccess}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{"secret_01": "api_token"}, PolicyAccess, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, "session-token", GrantSession, 0); err != nil {
		t.Fatalf("grant lease: %v", err)
	}
	if _, err := handle.GrantSecretUse(binding.ID, "session-token", "api_token", GrantWindow, time.Minute, true); err != nil {
		t.Fatalf("grant secret: %v", err)
	}
	if !handle.secretGrantWindowActive(binding.ID, "session-token", "api_token") {
		t.Fatal("expected active window override")
	}
}

func TestGrantMutationEdgePaths(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{}, PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}

	if _, err := handle.GrantProjectLease(binding.ID, "session-token", GrantScope("bad"), 0); err == nil {
		t.Fatal("expected bad project lease scope failure")
	}
	if _, err := handle.GrantSecretUse(binding.ID, "session-token", "api_token", GrantScope("bad"), 0, false); err == nil {
		t.Fatal("expected bad secret grant scope failure")
	}
	if _, err := handle.GrantConvenience(binding.ID, "session-token", "/tmp/.env", nil, "user", GrantScope("bad"), 0); err == nil {
		t.Fatal("expected bad convenience scope failure")
	}
	if _, err := handle.GrantConvenience(binding.ID, "missing", "/tmp/.env", nil, "user", GrantSession, 0); err == nil {
		t.Fatal("expected active lease requirement")
	}

	if err := handle.ConsumeProjectLease("missing", "session-token"); err != nil {
		t.Fatalf("consume missing project lease: %v", err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, "session-token", GrantSession, 0); err != nil {
		t.Fatalf("grant session project lease: %v", err)
	}
	if err := handle.ConsumeProjectLease(binding.ID, "session-token"); err != nil {
		t.Fatalf("consume session project lease: %v", err)
	}

	if err := handle.ConsumeSecretGrant(binding.ID, "session-token", "api_token"); err != nil {
		t.Fatalf("consume missing secret grant: %v", err)
	}
	if _, err := handle.GrantSecretUse(binding.ID, "session-token", "api_token", GrantSession, 0, false); err != nil {
		t.Fatalf("grant session secret use: %v", err)
	}
	if err := handle.ConsumeSecretGrant(binding.ID, "session-token", "api_token"); err != nil {
		t.Fatalf("consume session secret grant: %v", err)
	}

	if err := handle.ConsumeConvenienceGrant(binding.ID, "/tmp/.env", nil); err != nil {
		t.Fatalf("consume missing convenience grant: %v", err)
	}
	if _, err := handle.GrantConvenience(binding.ID, "session-token", "/tmp/.env", nil, "user", GrantSession, 0); err != nil {
		t.Fatalf("grant session convenience: %v", err)
	}
	if err := handle.ConsumeConvenienceGrant(binding.ID, "/tmp/.env", nil); err != nil {
		t.Fatalf("consume session convenience grant: %v", err)
	}

	if err := handle.RevokeProjectLease("missing", "session-token"); err != nil {
		t.Fatalf("revoke missing project lease: %v", err)
	}
}

func TestGrantMutationsPersistFailureAndNilAudit(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{}, PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}

	handle.vaultKey = []byte("short")
	if _, err := handle.GrantProjectLease(binding.ID, "persist-project", GrantOnce, 0); err == nil {
		t.Fatal("expected project lease persist failure")
	}
	if _, err := handle.GrantSecretUse(binding.ID, "persist-secret", "api_token", GrantOnce, 0, false); err == nil {
		t.Fatal("expected secret grant persist failure")
	}
	handle.state.ProjectLeases[leaseKey(binding.ID, "persist-convenience")] = ProjectLease{
		ID:           "lease-id",
		BindingID:    binding.ID,
		SessionToken: "persist-convenience",
		Scope:        GrantSession,
	}
	if _, err := handle.GrantConvenience(binding.ID, "persist-convenience", "/tmp/.env", []string{"alias"}, "user", GrantOnce, time.Minute); err == nil {
		t.Fatal("expected convenience grant persist failure")
	}

	handle, err = store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	handle.store.audit = nil
	if _, err := handle.GrantProjectLease(binding.ID, "nil-audit-project", GrantOnce, 0); err != nil {
		t.Fatalf("grant project lease with nil audit: %v", err)
	}
	if err := handle.ConsumeProjectLease(binding.ID, "nil-audit-project"); err != nil {
		t.Fatalf("consume project lease with nil audit: %v", err)
	}
	if _, err := handle.GrantSecretUse(binding.ID, "nil-audit-secret", "api_token", GrantOnce, 0, false); err != nil {
		t.Fatalf("grant secret use with nil audit: %v", err)
	}
	if err := handle.ConsumeSecretGrant(binding.ID, "nil-audit-secret", "api_token"); err != nil {
		t.Fatalf("consume secret grant with nil audit: %v", err)
	}
	handle.state.ProjectLeases[leaseKey(binding.ID, "nil-audit-convenience")] = ProjectLease{
		ID:           "lease-nil-audit",
		BindingID:    binding.ID,
		SessionToken: "nil-audit-convenience",
		Scope:        GrantSession,
	}
	grant, err := handle.GrantConvenience(binding.ID, "nil-audit-convenience", "/tmp/.env.nil", []string{"alias"}, "user", GrantOnce, time.Minute)
	if err != nil {
		t.Fatalf("grant convenience with nil audit: %v", err)
	}
	if err := handle.ConsumeConvenienceGrant(binding.ID, "/tmp/.env.nil", []string{"alias"}); err != nil {
		t.Fatalf("consume convenience grant with nil audit: %v", err)
	}
	if grant.ID == "" {
		t.Fatal("expected persisted convenience grant id")
	}
	if err := handle.RevokeProjectLease(binding.ID, "nil-audit-convenience"); err != nil {
		t.Fatalf("revoke project lease with nil audit: %v", err)
	}
}
