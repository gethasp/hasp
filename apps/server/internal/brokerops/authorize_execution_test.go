package brokerops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestAuthorizeReferencesRejectsInvalidDeliveryAndGrants(t *testing.T) {
	for _, tc := range []struct {
		name, reference string
		operation       store.Operation
		project, secret store.GrantScope
		want            string
	}{
		{"file in env", "@file", store.OperationRun, store.GrantOnce, store.GrantOnce, "env delivery requires kv"},
		{"invalid project grant", "@one", store.OperationRun, "invalid", store.GrantOnce, "scope"},
		{"invalid secret grant", "@one", store.OperationRun, store.GrantOnce, "invalid", "scope"},
		{"unsupported operation", "@one", "invalid", store.GrantOnce, store.GrantOnce, "unsupported"},
		{"workspace write grant", "@one", store.OperationWriteEnv, store.GrantOnce, store.GrantOnce, "project lease"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := onceExecutionFixture(t, store.PolicySession)
			_, err := AuthorizeReferences(context.Background(), req.Handle, req.BindingID, req.ProjectRoot, req.SessionToken, []ReferenceAccess{{tc.reference, tc.operation}}, tc.project, tc.secret, time.Minute)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s: %v", tc.name, err)
			}
		})
	}
}

func TestAuthorizeReferencesPropagatesResolutionAndTransactionFailures(t *testing.T) {
	lockBrokeropsSeams(t)
	req := onceExecutionFixture(t, store.PolicySession)
	originalResolve, originalGet, originalBatch := resolveReferenceFn, getItemFn, authorizeBatchAndConsumeFn
	t.Cleanup(func() {
		resolveReferenceFn, getItemFn, authorizeBatchAndConsumeFn = originalResolve, originalGet, originalBatch
	})
	for _, step := range []string{"resolve", "read", "transaction"} {
		resolveReferenceFn, getItemFn, authorizeBatchAndConsumeFn = originalResolve, originalGet, originalBatch
		switch step {
		case "resolve":
			resolveReferenceFn = func(*store.Handle, context.Context, string, string) (store.ResolvedReference, error) {
				return store.ResolvedReference{}, os.ErrPermission
			}
		case "read":
			resolveReferenceFn = func(*store.Handle, context.Context, string, string) (store.ResolvedReference, error) {
				return store.ResolvedReference{ItemName: "removed"}, nil
			}
			getItemFn = func(*store.Handle, string) (store.Item, error) { return store.Item{}, os.ErrPermission }
		case "transaction":
			authorizeBatchAndConsumeFn = func(*store.Handle, []store.AccessRequest) ([]store.AccessDecision, error) {
				return nil, os.ErrPermission
			}
		}
		_, err := AuthorizeReferences(context.Background(), req.Handle, req.BindingID, req.ProjectRoot, req.SessionToken, []ReferenceAccess{{"@one", store.OperationRun}}, store.GrantOnce, store.GrantOnce, time.Minute)
		if !errors.Is(err, os.ErrPermission) {
			t.Fatalf("%s failed open: %v", step, err)
		}
	}
}

func TestExecuteRejectsIncompleteAuthorizationBeforeStartingChild(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	_, err := Execute(context.Background(), ExecutionRequest{
		Command: []string{"sh", "-c", `touch "$1"`, "sh", marker}, EnvRefs: map[string]string{"TOKEN": "@one"},
		Deps: ExecutionDeps{AuthorizeReferences: func(context.Context, *store.Handle, string, string, string, []ReferenceAccess, store.GrantScope, store.GrantScope, time.Duration) ([]store.Item, error) {
			return nil, nil
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "incomplete reference set") {
		t.Fatalf("incomplete authorization: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("unauthorized child started: %v", err)
	}
}

func TestAuthorizationHintsRequireSpecificApprovals(t *testing.T) {
	for _, tc := range []struct {
		reason, field, cli, mcp string
		consumed                bool
	}{
		{"unsupported_operation", "", "secret show", "through the CLI", false},
		{"write_grant_required", "grant_write", "--grant-write", "grant_write=true", false},
		{"convenience_approval_required", "grant_convenience", "--grant-convenience window", "through the CLI", true},
		{"secret_session_grant_required", "grant_secret", "fresh agent session", "fresh agent MCP session", true},
	} {
		err := NewAuthorizationError(nil, store.AccessRequest{Operation: store.OperationRun}, store.AccessDecision{Reason: tc.reason, RequiresPrompt: true})
		err.OnceConsumed = tc.consumed
		if err.GrantField() != tc.field || !strings.Contains(err.CLIHint(), tc.cli) || !strings.Contains(err.MCPHint(), tc.mcp) {
			t.Fatalf("%s: field=%q CLI=%q MCP=%q", tc.reason, err.GrantField(), err.CLIHint(), err.MCPHint())
		}
	}
}

func TestAuthorizeReferencesDoesNotGrantAfterDefinitiveDenial(t *testing.T) {
	lockBrokeropsSeams(t)
	req := onceExecutionFixture(t, store.PolicySession)
	originalBatch, originalProject, originalSecret := authorizeBatchAndConsumeFn, grantProjectLeaseFn, grantSecretUseFn
	t.Cleanup(func() {
		authorizeBatchAndConsumeFn, grantProjectLeaseFn, grantSecretUseFn = originalBatch, originalProject, originalSecret
	})
	authorizeBatchAndConsumeFn = func(_ *store.Handle, requests []store.AccessRequest) ([]store.AccessDecision, error) {
		if len(requests) != 1 || requests[0].ItemName != "one" {
			t.Fatalf("unexpected request: %+v", requests)
		}
		return []store.AccessDecision{{Reason: "definitive denial"}}, nil
	}
	grantProjectLeaseFn = func(*store.Handle, string, string, store.GrantScope, time.Duration) (store.ProjectLease, error) {
		t.Fatal("denial attempted a project grant")
		return store.ProjectLease{}, nil
	}
	grantSecretUseFn = func(*store.Handle, string, string, string, store.GrantScope, time.Duration, bool) (store.SecretGrant, error) {
		t.Fatal("denial attempted a secret grant")
		return store.SecretGrant{}, nil
	}
	_, err := AuthorizeReferences(context.Background(), req.Handle, req.BindingID, req.ProjectRoot, req.SessionToken, []ReferenceAccess{{"@one", store.OperationRun}}, store.GrantOnce, store.GrantOnce, time.Minute)
	var denied *AuthorizationError
	if !errors.As(err, &denied) || denied.Reason != "definitive denial" || denied.requiresPrompt {
		t.Fatalf("definitive denial changed: %v", err)
	}
}
