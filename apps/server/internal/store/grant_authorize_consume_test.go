package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthorizeAndConsumeConsumesOnceGrantsAtomically(t *testing.T) {
	s := newTestStore(t)
	if err := s.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := s.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("secret"), ItemMetadata{Policy: PolicySession}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{"secret_01": "api_token"}, PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, "session-token", GrantOnce, 0); err != nil {
		t.Fatalf("grant project: %v", err)
	}
	if _, err := handle.GrantSecretUse(binding.ID, "session-token", "api_token", GrantOnce, 0, false); err != nil {
		t.Fatalf("grant secret: %v", err)
	}
	if _, err := handle.GrantConvenience(binding.ID, "session-token", "/tmp/.env", []string{"secret_01"}, "user", GrantOnce, time.Minute); err != nil {
		t.Fatalf("grant convenience: %v", err)
	}

	decision, err := handle.AuthorizeAndConsume(AccessRequest{
		Operation:       OperationWriteEnv,
		BindingID:       binding.ID,
		SessionToken:    "session-token",
		ItemName:        "api_token",
		Policy:          PolicySession,
		DestinationPath: "/tmp/.env",
		Aliases:         []string{"secret_01"},
	})
	if err != nil {
		t.Fatalf("AuthorizeAndConsume: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("decision = %+v, want allowed", decision)
	}

	reopened, err := s.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	if reopened.projectLeaseActive(binding.ID, "session-token") {
		t.Fatal("once project lease should be consumed")
	}
	if reopened.secretGrantActive(binding.ID, "session-token", "api_token") {
		t.Fatal("once secret grant should be consumed")
	}
	if reopened.convenienceGrantActive(binding.ID, "/tmp/.env", []string{"secret_01"}) {
		t.Fatal("once convenience grant should be consumed")
	}
}

func TestAuthorizeAndConsumeReturnsDeniedWithoutPersisting(t *testing.T) {
	_, handle := openedCoverageStore(t)
	decision, err := handle.AuthorizeAndConsume(AccessRequest{Operation: OperationList, BindingID: "missing", SessionToken: "session"})
	if err != nil {
		t.Fatalf("AuthorizeAndConsume: %v", err)
	}
	if !decision.RequiresPrompt {
		t.Fatalf("decision = %+v, want prompt", decision)
	}
}

func TestAuthorizeAndConsumeAllowedWithoutOnceGrantsDoesNotPersist(t *testing.T) {
	s := newTestStore(t)
	if err := s.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := s.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{}, PolicyAuto, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, "session-token", GrantSession, 0); err != nil {
		t.Fatalf("grant project: %v", err)
	}
	decision, err := handle.AuthorizeAndConsume(AccessRequest{
		Operation:    OperationList,
		BindingID:    binding.ID,
		SessionToken: "session-token",
	})
	if err != nil {
		t.Fatalf("AuthorizeAndConsume: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("decision = %+v, want allowed", decision)
	}
}

func TestAuthorizeAndConsumeReturnsRefreshAndPersistErrors(t *testing.T) {
	lockStoreSeams(t)
	s := newTestStore(t)
	if err := s.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := s.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{}, PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, "session-token", GrantOnce, 0); err != nil {
		t.Fatalf("grant project: %v", err)
	}

	origRead := readStateFn
	readStateFn = func([]byte, sealedBlob) (persistedState, error) {
		return persistedState{}, errors.New("decrypt failed")
	}
	if _, err := handle.AuthorizeAndConsume(AccessRequest{Operation: OperationList, BindingID: binding.ID, SessionToken: "session-token"}); err == nil {
		t.Fatal("expected refresh error")
	}
	readStateFn = origRead

	origWrite := writeEnvelopeFileFn
	writeEnvelopeFileFn = func(string, []byte, os.FileMode) error { return errors.New("write failed") }
	t.Cleanup(func() { writeEnvelopeFileFn = origWrite })
	if _, err := handle.AuthorizeAndConsume(AccessRequest{Operation: OperationList, BindingID: binding.ID, SessionToken: "session-token"}); err == nil {
		t.Fatal("expected persist error")
	}

	handle.store.paths.StatePath = filepath.Join(t.TempDir(), "missing-vault.json")
	if err := handle.refreshStateUnlocked(); err == nil {
		t.Fatal("expected refresh read error")
	}
}

func TestConsumeOnceGrantInactiveBranches(t *testing.T) {
	_, handle := openedCoverageStore(t)
	now := handle.store.now().Add(-time.Hour)
	handle.state.ProjectLeases[leaseKey("binding", "used")] = ProjectLease{Scope: GrantOnce, UsedAt: &now}
	if handle.consumeProjectLeaseForRequest(AccessRequest{BindingID: "binding", SessionToken: "used"}, handle.store.now()) {
		t.Fatal("used project lease should not consume")
	}
	if handle.consumeSecretGrantForRequest(AccessRequest{BindingID: "binding", SessionToken: "used"}, handle.store.now()) {
		t.Fatal("blank item secret grant should not consume")
	}
	handle.state.SecretGrants[secretGrantKey("binding", "used", "api")] = SecretGrant{Scope: GrantOnce, UsedAt: &now}
	if handle.consumeSecretGrantForRequest(AccessRequest{BindingID: "binding", SessionToken: "used", ItemName: "api"}, handle.store.now()) {
		t.Fatal("used secret grant should not consume")
	}
	handle.state.ConvenienceGrants[convenienceGrantKey("binding", "/tmp/.env", []string{"api"})] = ConvenienceGrant{Scope: GrantOnce, UsedAt: &now}
	if handle.consumeConvenienceGrantForRequest(AccessRequest{BindingID: "binding", DestinationPath: "/tmp/.env", Aliases: []string{"api"}}, handle.store.now()) {
		t.Fatal("used convenience grant should not consume")
	}
}

func TestGrantOnceReturnsExistingActiveGrants(t *testing.T) {
	_, handle := openedCoverageStore(t)
	if _, err := handle.GrantProjectLease("binding", "session", GrantSession, 0); err != nil {
		t.Fatalf("grant project session: %v", err)
	}
	project, err := handle.GrantProjectLease("binding", "session", GrantOnce, 0)
	if err != nil {
		t.Fatalf("grant project once: %v", err)
	}
	if project.Scope != GrantSession {
		t.Fatalf("project scope = %q, want existing session", project.Scope)
	}

	if _, err := handle.GrantSecretUse("binding", "session", "api", GrantSession, 0, false); err != nil {
		t.Fatalf("grant secret session: %v", err)
	}
	secret, err := handle.GrantSecretUse("binding", "session", "api", GrantOnce, 0, false)
	if err != nil {
		t.Fatalf("grant secret once: %v", err)
	}
	if secret.Scope != GrantSession {
		t.Fatalf("secret scope = %q, want existing session", secret.Scope)
	}

	convenience, err := handle.GrantConvenience("binding", "session", "/tmp/.env", []string{"api"}, "user", GrantSession, 0)
	if err != nil {
		t.Fatalf("grant convenience session: %v", err)
	}
	again, err := handle.GrantConvenience("binding", "session", "/tmp/.env", []string{"api"}, "user", GrantOnce, time.Minute)
	if err != nil {
		t.Fatalf("grant convenience once: %v", err)
	}
	if again.ID != convenience.ID {
		t.Fatalf("convenience id = %q, want existing %q", again.ID, convenience.ID)
	}
}

func TestGrantConvenienceOnceFailsWhenRefreshedLeaseIsInactive(t *testing.T) {
	s := newTestStore(t)
	if err := s.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := s.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{}, PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, "session-token", GrantSession, 0); err != nil {
		t.Fatalf("grant project: %v", err)
	}
	other, err := s.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open other: %v", err)
	}
	if err := other.RevokeProjectLease(binding.ID, "session-token"); err != nil {
		t.Fatalf("revoke project: %v", err)
	}
	if _, err := handle.GrantConvenience(binding.ID, "session-token", "/tmp/.env", []string{"api"}, "user", GrantOnce, time.Minute); err == nil {
		t.Fatal("expected inactive refreshed project lease to reject convenience grant")
	}
}

func TestAccessDecisionRequiredActionFallbacks(t *testing.T) {
	tests := map[string]AccessRequirement{
		"project_lease_required":                    AccessRequirementProjectLease,
		"project_and_convenience_approval_required": AccessRequirementProjectAndConvenience,
		"convenience_approval_required":             AccessRequirementConvenience,
		"secret_session_grant_required":             AccessRequirementSecretGrant,
		"access_secret_prompt_required":             AccessRequirementSecretGrant,
		"write_grant_required":                      AccessRequirementWriteGrant,
		"unsupported_operation":                     AccessRequirementUnsupported,
		"unknown_policy":                            AccessRequirementUnsupported,
		"other":                                     AccessRequirementNone,
	}
	for reason, want := range tests {
		if got := (AccessDecision{Reason: reason}).RequiredAction(); got != want {
			t.Fatalf("RequiredAction(%q) = %q, want %q", reason, got, want)
		}
	}
	if got := (AccessDecision{Requirement: AccessRequirementSecretGrant, Reason: "project_lease_required"}).RequiredAction(); got != AccessRequirementSecretGrant {
		t.Fatalf("explicit requirement = %q", got)
	}
}
