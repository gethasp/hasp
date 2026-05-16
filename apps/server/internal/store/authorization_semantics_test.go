package store

import (
	"context"
	"testing"
	"time"
)

type authorizationRequirement string

const (
	requireAllowed                authorizationRequirement = "allowed"
	requireProjectLease           authorizationRequirement = "project lease"
	requireProjectAndConvenience  authorizationRequirement = "project lease and convenience grant"
	requireConvenienceGrant       authorizationRequirement = "convenience grant"
	requireSecretSessionGrant     authorizationRequirement = "secret session grant"
	requireAccessSecretPrompt     authorizationRequirement = "access secret prompt"
	requireCaptureWriteGrant      authorizationRequirement = "capture write grant"
	requireUnsupportedOperation   authorizationRequirement = "unsupported operation"
	requireAccessWindowGrantAllow authorizationRequirement = "access window grant allow"
)

func TestAuthorizationDecisionRequirements(t *testing.T) {
	handle, binding, sessionToken, sessionItem, accessItem := newAuthorizationSemanticsFixture(t)

	assertAuthorizationRequirement(t, handle.Authorize(AccessRequest{
		Operation:    OperationList,
		BindingID:    binding.ID,
		SessionToken: sessionToken,
	}), requireProjectLease)

	if _, err := handle.GrantProjectLease(binding.ID, sessionToken, GrantSession, 0); err != nil {
		t.Fatalf("grant project lease: %v", err)
	}

	assertAuthorizationRequirement(t, handle.Authorize(AccessRequest{
		Operation:       OperationWriteEnv,
		BindingID:       binding.ID,
		SessionToken:    sessionToken,
		DestinationPath: "/tmp/.env.local",
		Aliases:         []string{"secret_01"},
	}), requireConvenienceGrant)

	assertAuthorizationRequirement(t, handle.Authorize(AccessRequest{
		Operation:    OperationRun,
		BindingID:    binding.ID,
		SessionToken: sessionToken,
		ItemName:     sessionItem.Name,
		Policy:       PolicySession,
	}), requireSecretSessionGrant)

	assertAuthorizationRequirement(t, handle.Authorize(AccessRequest{
		Operation:    OperationRun,
		BindingID:    binding.ID,
		SessionToken: sessionToken,
		ItemName:     accessItem.Name,
		Policy:       PolicyAccess,
	}), requireAccessSecretPrompt)

	if _, err := handle.GrantSecretUse(binding.ID, sessionToken, accessItem.Name, GrantWindow, time.Minute, true); err != nil {
		t.Fatalf("grant relaxed access window: %v", err)
	}
	assertAuthorizationRequirement(t, handle.Authorize(AccessRequest{
		Operation:    OperationRun,
		BindingID:    binding.ID,
		SessionToken: sessionToken,
		ItemName:     accessItem.Name,
		Policy:       PolicyAccess,
	}), requireAccessWindowGrantAllow)

	assertAuthorizationRequirement(t, handle.Authorize(AccessRequest{
		Operation:    OperationCapture,
		BindingID:    binding.ID,
		SessionToken: sessionToken,
		CreatingNew:  true,
	}), requireCaptureWriteGrant)

	assertAuthorizationRequirement(t, handle.Authorize(AccessRequest{
		Operation: Operation("rotate"),
	}), requireUnsupportedOperation)
}

func TestAuthorizationDecisionRequiresProjectAndConvenienceBeforeWriteEnvExport(t *testing.T) {
	handle, binding, sessionToken, _, _ := newAuthorizationSemanticsFixture(t)

	assertAuthorizationRequirement(t, handle.Authorize(AccessRequest{
		Operation:       OperationWriteEnv,
		BindingID:       binding.ID,
		SessionToken:    sessionToken,
		DestinationPath: "/tmp/.env.local",
		Aliases:         []string{"secret_01"},
	}), requireProjectAndConvenience)
}

func TestAuthorizationDecisionWriteEnvStillRequiresUnderlyingSecretApproval(t *testing.T) {
	handle, binding, sessionToken, sessionItem, _ := newAuthorizationSemanticsFixture(t)
	if _, err := handle.GrantProjectLease(binding.ID, sessionToken, GrantSession, 0); err != nil {
		t.Fatalf("grant project lease: %v", err)
	}
	if _, err := handle.GrantConvenience(binding.ID, sessionToken, "/tmp/.env.local", []string{"secret_01"}, "user", GrantWindow, time.Minute); err != nil {
		t.Fatalf("grant convenience: %v", err)
	}

	assertAuthorizationRequirement(t, handle.Authorize(AccessRequest{
		Operation:       OperationWriteEnv,
		BindingID:       binding.ID,
		SessionToken:    sessionToken,
		ItemName:        sessionItem.Name,
		Policy:          PolicySession,
		DestinationPath: "/tmp/.env.local",
		Aliases:         []string{"secret_01"},
	}), requireSecretSessionGrant)

	if _, err := handle.GrantSecretUse(binding.ID, sessionToken, sessionItem.Name, GrantSession, 0, false); err != nil {
		t.Fatalf("grant secret use: %v", err)
	}
	assertAuthorizationRequirement(t, handle.Authorize(AccessRequest{
		Operation:       OperationWriteEnv,
		BindingID:       binding.ID,
		SessionToken:    sessionToken,
		ItemName:        sessionItem.Name,
		Policy:          PolicySession,
		DestinationPath: "/tmp/.env.local",
		Aliases:         []string{"secret_01"},
	}), requireAllowed)
}

func newAuthorizationSemanticsFixture(t *testing.T) (*Handle, Binding, string, Item, Item) {
	t.Helper()

	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	sessionItem, err := handle.UpsertItem("session_token", ItemKindKV, []byte("secret-value"), ItemMetadata{Policy: PolicySession})
	if err != nil {
		t.Fatalf("upsert session item: %v", err)
	}
	accessItem, err := handle.UpsertItem("access_token", ItemKindKV, []byte("access-value"), ItemMetadata{Policy: PolicyAccess})
	if err != nil {
		t.Fatalf("upsert access item: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{
		"secret_01": sessionItem.Name,
		"secret_02": accessItem.Name,
	}, PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	return handle, binding, "session-token", sessionItem, accessItem
}

func assertAuthorizationRequirement(t *testing.T, decision AccessDecision, want authorizationRequirement) {
	t.Helper()

	got := authorizationRequirementForDecision(decision)
	if got != want {
		t.Fatalf("authorization requirement = %q, want %q (decision=%+v)", got, want, decision)
	}
}

func authorizationRequirementForDecision(decision AccessDecision) authorizationRequirement {
	if decision.Allowed && decision.Reason == "access_window_override_allowed" {
		return requireAccessWindowGrantAllow
	}
	if decision.Allowed {
		return requireAllowed
	}
	switch decision.Reason {
	case "project_lease_required":
		return requireProjectLease
	case "project_and_convenience_approval_required":
		return requireProjectAndConvenience
	case "convenience_approval_required":
		return requireConvenienceGrant
	case "secret_session_grant_required":
		return requireSecretSessionGrant
	case "access_secret_prompt_required":
		return requireAccessSecretPrompt
	case "write_grant_required":
		return requireCaptureWriteGrant
	case "unsupported_operation":
		return requireUnsupportedOperation
	default:
		return authorizationRequirement("unexpected:" + decision.Reason)
	}
}
