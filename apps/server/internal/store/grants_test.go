package store

import (
	"context"
	"testing"
	"time"
)

func TestGrantAuthorizationFlow(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	item, err := handle.UpsertItem("api_token", ItemKindKV, []byte("secret-value"), ItemMetadata{Policy: PolicySession})
	if err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{"secret_01": item.Name}, PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}

	decision := handle.Authorize(AccessRequest{
		Operation:    OperationList,
		BindingID:    binding.ID,
		SessionToken: "session-token",
	})
	if !decision.RequiresPrompt {
		t.Fatalf("expected prompt without project lease")
	}

	if _, err := handle.GrantProjectLease(binding.ID, "session-token", GrantSession, 0); err != nil {
		t.Fatalf("grant project lease: %v", err)
	}
	decision = handle.Authorize(AccessRequest{
		Operation:    OperationList,
		BindingID:    binding.ID,
		SessionToken: "session-token",
	})
	if !decision.Allowed {
		t.Fatalf("expected scoped listing to be allowed after project lease")
	}

	decision = handle.Authorize(AccessRequest{
		Operation:    OperationRun,
		BindingID:    binding.ID,
		SessionToken: "session-token",
		ItemName:     item.Name,
		Policy:       PolicySession,
	})
	if !decision.RequiresPrompt {
		t.Fatalf("expected prompt for session-scoped secret before grant")
	}

	if _, err := handle.GrantSecretUse(binding.ID, "session-token", item.Name, GrantSession, 0, false); err != nil {
		t.Fatalf("grant secret use: %v", err)
	}
	decision = handle.Authorize(AccessRequest{
		Operation:    OperationRun,
		BindingID:    binding.ID,
		SessionToken: "session-token",
		ItemName:     item.Name,
		Policy:       PolicySession,
	})
	if !decision.Allowed {
		t.Fatalf("expected session secret to be allowed after grant")
	}
}

func TestRevokeGrantsForItemAndAllGrants(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	item, err := handle.UpsertItem("api_token", ItemKindKV, []byte("secret-value"), ItemMetadata{Policy: PolicySession})
	if err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	other, err := handle.UpsertItem("other_token", ItemKindKV, []byte("other-value"), ItemMetadata{Policy: PolicySession})
	if err != nil {
		t.Fatalf("upsert other item: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{"secret_01": item.Name}, PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if _, err := handle.GrantSecretUse(binding.ID, "session-token", item.Name, GrantSession, 0, false); err != nil {
		t.Fatalf("grant secret: %v", err)
	}
	if _, err := handle.GrantPlaintextUse("session-token", item.Name, PlaintextReveal, "user", GrantOnce, time.Minute); err != nil {
		t.Fatalf("grant plaintext: %v", err)
	}
	revoked, err := handle.RevokeGrantsForItem(item.Name)
	if err != nil || revoked != 2 {
		t.Fatalf("revoke item grants = %d err=%v", revoked, err)
	}
	if handle.Authorize(AccessRequest{Operation: OperationRun, BindingID: binding.ID, SessionToken: "session-token", ItemName: item.Name, Policy: PolicySession}).Allowed {
		t.Fatal("expected revoked item grant to deny")
	}
	if count, err := handle.RevokeGrantsForItem(item.Name); err != nil || count != 0 {
		t.Fatalf("second revoke item grants = %d err=%v", count, err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, "session-two", GrantSession, 0); err != nil {
		t.Fatalf("grant project lease: %v", err)
	}
	if _, err := handle.GrantSecretUse(binding.ID, "session-two", other.Name, GrantSession, 0, false); err != nil {
		t.Fatalf("grant other secret: %v", err)
	}
	if _, err := handle.GrantConvenience(binding.ID, "session-two", "/tmp/.env", []string{other.Name}, "user", GrantWindow, time.Minute); err != nil {
		t.Fatalf("grant convenience: %v", err)
	}
	if _, err := handle.GrantPlaintextUse("session-two", other.Name, PlaintextCopy, "user", GrantOnce, time.Minute); err != nil {
		t.Fatalf("grant other plaintext: %v", err)
	}
	revoked, err = handle.RevokeAllGrants()
	if err != nil || revoked != 4 {
		t.Fatalf("revoke all grants = %d err=%v", revoked, err)
	}
	if count, err := handle.RevokeAllGrants(); err != nil || count != 0 {
		t.Fatalf("second revoke all grants = %d err=%v", count, err)
	}
}

func TestConvenienceGrantMatchingAndRevocation(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{"secret_01": "db_url"}, PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, "session-token", GrantSession, 0); err != nil {
		t.Fatalf("grant project lease: %v", err)
	}
	if _, err := handle.GrantConvenience(binding.ID, "session-token", "/tmp/.env.local", []string{"secret_01"}, "user", GrantWindow, time.Minute); err != nil {
		t.Fatalf("grant convenience: %v", err)
	}

	decision := handle.Authorize(AccessRequest{
		Operation:       OperationWriteEnv,
		BindingID:       binding.ID,
		SessionToken:    "session-token",
		DestinationPath: "/tmp/.env.local",
		Aliases:         []string{"secret_01"},
	})
	if !decision.Allowed {
		t.Fatalf("expected convenience grant to allow write-env")
	}

	decision = handle.Authorize(AccessRequest{
		Operation:       OperationWriteEnv,
		BindingID:       binding.ID,
		SessionToken:    "session-token",
		DestinationPath: "/tmp/.env.other",
		Aliases:         []string{"secret_01"},
	})
	if !decision.RequiresPrompt {
		t.Fatalf("expected prompt when destination path changes")
	}

	if err := handle.RevokeProjectLease(binding.ID, "session-token"); err != nil {
		t.Fatalf("revoke project lease: %v", err)
	}
	decision = handle.Authorize(AccessRequest{
		Operation:       OperationWriteEnv,
		BindingID:       binding.ID,
		SessionToken:    "session-token",
		DestinationPath: "/tmp/.env.local",
		Aliases:         []string{"secret_01"},
	})
	if !decision.RequiresPrompt {
		t.Fatalf("expected prompt after enclosing project lease revoke")
	}
}

func TestWriteEnvStillRequiresUnderlyingSecretApproval(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if _, err := handle.UpsertItem("db_url", ItemKindKV, []byte("postgres://db"), ItemMetadata{Policy: PolicySession}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{"secret_01": "db_url"}, PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, "session-token", GrantSession, 0); err != nil {
		t.Fatalf("grant project lease: %v", err)
	}
	if _, err := handle.GrantConvenience(binding.ID, "session-token", "/tmp/.env.local", []string{"secret_01"}, "user", GrantWindow, time.Minute); err != nil {
		t.Fatalf("grant convenience: %v", err)
	}

	decision := handle.Authorize(AccessRequest{
		Operation:       OperationWriteEnv,
		BindingID:       binding.ID,
		SessionToken:    "session-token",
		ItemName:        "db_url",
		Policy:          PolicySession,
		DestinationPath: "/tmp/.env.local",
		Aliases:         []string{"secret_01"},
	})
	if !decision.RequiresPrompt {
		t.Fatalf("expected write-env to require underlying secret approval")
	}

	if _, err := handle.GrantSecretUse(binding.ID, "session-token", "db_url", GrantSession, 0, false); err != nil {
		t.Fatalf("grant secret use: %v", err)
	}
	decision = handle.Authorize(AccessRequest{
		Operation:       OperationWriteEnv,
		BindingID:       binding.ID,
		SessionToken:    "session-token",
		ItemName:        "db_url",
		Policy:          PolicySession,
		DestinationPath: "/tmp/.env.local",
		Aliases:         []string{"secret_01"},
	})
	if !decision.Allowed {
		t.Fatalf("expected write-env to be allowed after secret approval and convenience grant")
	}
}

func TestGrantOnceConsumption(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("secret-value"), ItemMetadata{Policy: PolicySession}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{"secret_01": "api_token"}, PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, "session-token", GrantSession, 0); err != nil {
		t.Fatalf("grant project lease: %v", err)
	}
	if _, err := handle.GrantSecretUse(binding.ID, "session-token", "api_token", GrantOnce, 0, false); err != nil {
		t.Fatalf("grant secret use: %v", err)
	}
	if err := handle.ConsumeSecretGrant(binding.ID, "session-token", "api_token"); err != nil {
		t.Fatalf("consume secret grant: %v", err)
	}
	decision := handle.Authorize(AccessRequest{
		Operation:    OperationRun,
		BindingID:    binding.ID,
		SessionToken: "session-token",
		ItemName:     "api_token",
		Policy:       PolicySession,
	})
	if !decision.RequiresPrompt {
		t.Fatalf("expected prompt after consuming once grant")
	}
}

func TestAccessPolicyWindowOverride(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("secret-value"), ItemMetadata{Policy: PolicyAccess}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{"secret_01": "api_token"}, PolicyAccess, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, "session-token", GrantSession, 0); err != nil {
		t.Fatalf("grant project lease: %v", err)
	}
	if _, err := handle.GrantSecretUse(binding.ID, "session-token", "api_token", GrantWindow, time.Minute, true); err != nil {
		t.Fatalf("grant secret use window: %v", err)
	}
	decision := handle.Authorize(AccessRequest{
		Operation:    OperationRun,
		BindingID:    binding.ID,
		SessionToken: "session-token",
		ItemName:     "api_token",
		Policy:       PolicyAccess,
	})
	if !decision.Allowed {
		t.Fatalf("expected access window override to allow run")
	}
}
