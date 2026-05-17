package brokerops

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestAuthorizeReferencePerformsRequiredGrantActions(t *testing.T) {
	tests := []struct {
		name        string
		decisions   []store.AccessDecision
		project     store.GrantScope
		secret      store.GrantScope
		convenience store.GrantScope
		wantActions []string
		wantErr     string
	}{
		{
			name: "project then convenience then consume",
			decisions: []store.AccessDecision{
				{RequiresPrompt: true, Reason: "project_and_convenience_approval_required"},
				{RequiresPrompt: true, Reason: "convenience_approval_required"},
				{Allowed: true, Reason: "auto_secret_allowed"},
			},
			project:     store.GrantWindow,
			convenience: store.GrantOnce,
			wantActions: []string{"project:window", "convenience:once", "consume"},
		},
		{
			name: "secret session grant",
			decisions: []store.AccessDecision{
				{RequiresPrompt: true, Reason: "secret_session_grant_required"},
				{Allowed: true, Reason: "session_secret_allowed"},
			},
			secret:      store.GrantSession,
			wantActions: []string{"secret:session:relaxed=false", "consume"},
		},
		{
			name: "access window grant is relaxed",
			decisions: []store.AccessDecision{
				{RequiresPrompt: true, Reason: "access_secret_prompt_required"},
				{Allowed: true, Reason: "access_window_override_allowed"},
			},
			secret:      store.GrantWindow,
			wantActions: []string{"secret:window:relaxed=true", "consume"},
		},
		{
			name: "missing project grant fails closed",
			decisions: []store.AccessDecision{
				{RequiresPrompt: true, Reason: "project_lease_required"},
			},
			wantErr: "project lease required",
		},
		{
			name: "capture write grant is not auto-granted for references",
			decisions: []store.AccessDecision{
				{RequiresPrompt: true, Reason: "write_grant_required"},
			},
			wantErr: "capture write grant required",
		},
		{
			name: "unsupported approval path fails closed",
			decisions: []store.AccessDecision{
				{RequiresPrompt: true, Reason: "unsupported_operation"},
			},
			wantErr: "unsupported approval path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actions, err := runAuthorizeReferenceWithDecisionScript(t, tt.decisions, store.PolicyAccess, tt.project, tt.secret, tt.convenience)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("AuthorizeReference error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("AuthorizeReference: %v", err)
			}
			if !reflect.DeepEqual(actions, tt.wantActions) {
				t.Fatalf("actions = %#v, want %#v", actions, tt.wantActions)
			}
		})
	}
}

func TestAuthorizeItemPerformsRequiredGrantActions(t *testing.T) {
	tests := []struct {
		name        string
		decisions   []store.AccessDecision
		project     store.GrantScope
		secret      store.GrantScope
		wantActions []string
		wantErr     string
	}{
		{
			name: "project lease grant",
			decisions: []store.AccessDecision{
				{RequiresPrompt: true, Reason: "project_lease_required"},
				{Allowed: true, Reason: "auto_secret_allowed"},
			},
			project:     store.GrantOnce,
			wantActions: []string{"project:once", "consume"},
		},
		{
			name: "secret grant",
			decisions: []store.AccessDecision{
				{RequiresPrompt: true, Reason: "secret_session_grant_required"},
				{Allowed: true, Reason: "session_secret_allowed"},
			},
			secret:      store.GrantSession,
			wantActions: []string{"secret:session:relaxed=false", "consume"},
		},
		{
			name: "access grant is relaxed for window approvals",
			decisions: []store.AccessDecision{
				{RequiresPrompt: true, Reason: "access_secret_prompt_required"},
				{Allowed: true, Reason: "access_window_override_allowed"},
			},
			secret:      store.GrantWindow,
			wantActions: []string{"secret:window:relaxed=true", "consume"},
		},
		{
			name: "missing secret grant fails closed",
			decisions: []store.AccessDecision{
				{RequiresPrompt: true, Reason: "secret_session_grant_required"},
			},
			wantErr: "secret approval required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actions, err := runAuthorizeItemWithDecisionScript(t, tt.decisions, store.PolicyAccess, tt.project, tt.secret)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("AuthorizeItem error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("AuthorizeItem: %v", err)
			}
			if !reflect.DeepEqual(actions, tt.wantActions) {
				t.Fatalf("actions = %#v, want %#v", actions, tt.wantActions)
			}
		})
	}
}

func TestAuthorizeReferenceAndItemPropagateConsumeErrors(t *testing.T) {
	actions := installAuthorizationActionSeams(t, []store.AccessDecision{{Allowed: true}}, store.PolicySession)
	origConsume := authorizeAndConsumeFn
	authorizeAndConsumeFn = func(*store.Handle, store.AccessRequest) (store.AccessDecision, error) {
		return store.AccessDecision{}, errors.New("consume failed")
	}
	t.Cleanup(func() { authorizeAndConsumeFn = origConsume })
	handle := newBrokeropsHandle(t)
	if _, err := AuthorizeReference(context.Background(), handle, "binding", t.TempDir(), "token", "secret_01", store.OperationRun, "", "", "", time.Minute, ""); err == nil || !strings.Contains(err.Error(), "consume failed") {
		t.Fatalf("expected reference consume failure, got %v actions=%v", err, *actions)
	}

	authorizeFn = func(*store.Handle, store.AccessRequest) store.AccessDecision {
		return store.AccessDecision{Allowed: true}
	}
	authorizeAndConsumeFn = func(*store.Handle, store.AccessRequest) (store.AccessDecision, error) {
		return store.AccessDecision{}, errors.New("consume failed")
	}
	if _, err := AuthorizeItem(handle, "binding", "token", store.Item{Name: "api_token", Metadata: store.ItemMetadata{Policy: store.PolicySession}}, store.OperationRun, "", "", time.Minute); err == nil || !strings.Contains(err.Error(), "consume failed") {
		t.Fatalf("expected item consume failure, got %v actions=%v", err, *actions)
	}
}

func runAuthorizeReferenceWithDecisionScript(t *testing.T, decisions []store.AccessDecision, policy store.SecretPolicy, projectGrant, secretGrant, convenienceGrant store.GrantScope) ([]string, error) {
	t.Helper()

	actions := installAuthorizationActionSeams(t, decisions, policy)
	handle := newBrokeropsHandle(t)
	_, err := AuthorizeReference(context.Background(), handle, "binding", t.TempDir(), "token", "secret_01", store.OperationWriteEnv, projectGrant, secretGrant, convenienceGrant, time.Minute, "/tmp/.env.local")
	return *actions, err
}

func runAuthorizeItemWithDecisionScript(t *testing.T, decisions []store.AccessDecision, policy store.SecretPolicy, projectGrant, secretGrant store.GrantScope) ([]string, error) {
	t.Helper()

	actions := installAuthorizationActionSeams(t, decisions, policy)
	handle := newBrokeropsHandle(t)
	item := store.Item{Name: "api_token", Metadata: store.ItemMetadata{Policy: policy}}
	_, err := AuthorizeItem(handle, "binding", "token", item, store.OperationRun, projectGrant, secretGrant, time.Minute)
	return *actions, err
}

func installAuthorizationActionSeams(t *testing.T, decisions []store.AccessDecision, policy store.SecretPolicy) *[]string {
	t.Helper()

	lockBrokeropsSeams(t)
	origResolve := resolveReferenceFn
	origGet := getItemFn
	origAuthorize := authorizeFn
	origAuthorizeAndConsume := authorizeAndConsumeFn
	origGrantProject := grantProjectLeaseFn
	origGrantSecret := grantSecretUseFn
	origGrantConvenience := grantConvenienceFn
	t.Cleanup(func() {
		resolveReferenceFn = origResolve
		getItemFn = origGet
		authorizeFn = origAuthorize
		authorizeAndConsumeFn = origAuthorizeAndConsume
		grantProjectLeaseFn = origGrantProject
		grantSecretUseFn = origGrantSecret
		grantConvenienceFn = origGrantConvenience
	})

	actions := make([]string, 0, len(decisions))
	authorizeCalls := 0
	resolveReferenceFn = func(*store.Handle, context.Context, string, string) (store.ResolvedReference, error) {
		return store.ResolvedReference{ItemName: "api_token"}, nil
	}
	getItemFn = func(*store.Handle, string) (store.Item, error) {
		return store.Item{Name: "api_token", Metadata: store.ItemMetadata{Policy: policy}}, nil
	}
	authorizeFn = func(*store.Handle, store.AccessRequest) store.AccessDecision {
		if authorizeCalls >= len(decisions) {
			return store.AccessDecision{RequiresPrompt: true, Reason: "unexpected_extra_authorize_call"}
		}
		decision := decisions[authorizeCalls]
		authorizeCalls++
		return decision
	}
	authorizeAndConsumeFn = func(*store.Handle, store.AccessRequest) (store.AccessDecision, error) {
		actions = append(actions, "consume")
		return store.AccessDecision{Allowed: true, Reason: "consumed"}, nil
	}
	grantProjectLeaseFn = func(_ *store.Handle, _, _ string, scope store.GrantScope, _ time.Duration) (store.ProjectLease, error) {
		actions = append(actions, "project:"+string(scope))
		return store.ProjectLease{}, nil
	}
	grantSecretUseFn = func(_ *store.Handle, _, _, _ string, scope store.GrantScope, _ time.Duration, relaxed bool) (store.SecretGrant, error) {
		actions = append(actions, "secret:"+string(scope)+":relaxed="+boolString(relaxed))
		return store.SecretGrant{}, nil
	}
	grantConvenienceFn = func(_ *store.Handle, _, _, _ string, _ []string, _ string, scope store.GrantScope, _ time.Duration) (store.ConvenienceGrant, error) {
		actions = append(actions, "convenience:"+string(scope))
		return store.ConvenienceGrant{}, nil
	}

	return &actions
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
