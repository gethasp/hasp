package mcp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/reposcan"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestCoverageMCPGrantParseAndAuthorizationEdges(t *testing.T) {
	lockMCPSeams(t)
	origEnsureSession := ensureSessionFn
	origAuthorizeAndConsume := authorizeAndConsumeMCPFn
	origGrantProject := grantProjectLeaseMCPFn
	origReposcan := reposcanScanMCPFn
	t.Cleanup(func() {
		ensureSessionFn = origEnsureSession
		authorizeAndConsumeMCPFn = origAuthorizeAndConsume
		grantProjectLeaseMCPFn = origGrantProject
		reposcanScanMCPFn = origReposcan
	})

	handle, projectRoot := newMCPCoverageHandle(t)
	ensureSessionFn = func(context.Context, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "session-token"}, nil
	}

	if _, err := callList(context.Background(), handle, toolCall{Name: "hasp_list", Arguments: map[string]any{"project_root": projectRoot, "grant_project": "later"}}); err == nil {
		t.Fatal("expected callList invalid grant_project")
	}

	grantProjectLeaseMCPFn = func(*store.Handle, string, string, store.GrantScope, time.Duration) (store.ProjectLease, error) {
		return store.ProjectLease{}, errors.New("grant failed")
	}
	if _, err := callList(context.Background(), handle, toolCall{Name: "hasp_list", Arguments: map[string]any{"project_root": projectRoot, "grant_project": "window"}}); err == nil || !strings.Contains(err.Error(), "grant failed") {
		t.Fatalf("expected callList grant failure, got %v", err)
	}
	grantProjectLeaseMCPFn = origGrantProject

	authorizeAndConsumeMCPFn = func(*store.Handle, store.AccessRequest) (store.AccessDecision, error) {
		return store.AccessDecision{}, errors.New("authorize failed")
	}
	if _, err := callList(context.Background(), handle, toolCall{Name: "hasp_list", Arguments: map[string]any{"project_root": projectRoot}}); err == nil || !strings.Contains(err.Error(), "authorize failed") {
		t.Fatalf("expected callList authorize failure, got %v", err)
	}
	authorizeAndConsumeMCPFn = func(*store.Handle, store.AccessRequest) (store.AccessDecision, error) {
		return store.AccessDecision{RequiresPrompt: true, Reason: "project_lease_required"}, nil
	}
	if _, err := callList(context.Background(), handle, toolCall{Name: "hasp_list", Arguments: map[string]any{"project_root": projectRoot}}); err == nil || !strings.Contains(err.Error(), "project_lease_required") {
		t.Fatalf("expected callList approval failure, got %v", err)
	}

	authorizeAndConsumeMCPFn = func(*store.Handle, store.AccessRequest) (store.AccessDecision, error) {
		return store.AccessDecision{Allowed: true}, nil
	}
	reposcanScanMCPFn = func(context.Context, string, []store.Item, int64, reposcan.Deps) (reposcan.Result, error) {
		return reposcan.Result{}, errors.New("scan failed")
	}
	if _, err := callCheck(context.Background(), handle, toolCall{Name: "hasp_check", Arguments: map[string]any{"project_root": projectRoot, "session_token": "session-token"}}); err == nil || !strings.Contains(err.Error(), "scan failed") {
		t.Fatalf("expected callCheck scan failure, got %v", err)
	}
	reposcanScanMCPFn = origReposcan
	if _, err := callTargets(context.Background(), handle, toolCall{Name: "hasp_targets", Arguments: map[string]any{"project_root": projectRoot, "session_token": "session-token"}}); err == nil {
		t.Fatal("expected callTargets missing manifest failure")
	}

	if _, err := callExecute(context.Background(), handle, toolCall{Name: "hasp_run", Arguments: map[string]any{"project_root": projectRoot, "command": []any{"true"}, "grant_project": "later"}}); err == nil {
		t.Fatal("expected callExecute invalid grant_project")
	}
	if _, err := callExecute(context.Background(), handle, toolCall{Name: "hasp_run", Arguments: map[string]any{"project_root": projectRoot, "command": []any{"true"}, "grant_secret": "later"}}); err == nil {
		t.Fatal("expected callExecute invalid grant_secret")
	}
	if _, err := callCapture(context.Background(), handle, toolCall{Name: "hasp_capture", Arguments: map[string]any{"project_root": projectRoot, "name": "api", "value": "x", "grant_project": "later"}}); err == nil {
		t.Fatal("expected callCapture invalid grant_project")
	}
	if _, err := callCapture(context.Background(), handle, toolCall{Name: "hasp_capture", Arguments: map[string]any{"project_root": projectRoot, "name": "api", "value": "x", "grant_secret": "later"}}); err == nil {
		t.Fatal("expected callCapture invalid grant_secret")
	}
}

func TestCoverageRequireMCPProjectAuthorizationEdges(t *testing.T) {
	lockMCPSeams(t)
	origAuthorizeAndConsume := authorizeAndConsumeMCPFn
	origGrantProject := grantProjectLeaseMCPFn
	t.Cleanup(func() {
		authorizeAndConsumeMCPFn = origAuthorizeAndConsume
		grantProjectLeaseMCPFn = origGrantProject
	})

	handle, projectRoot := newMCPCoverageHandle(t)
	authorizeAndConsumeMCPFn = func(*store.Handle, store.AccessRequest) (store.AccessDecision, error) {
		return store.AccessDecision{Allowed: true}, nil
	}

	if _, _, err := requireMCPProjectAuthorization(context.Background(), handle, toolCall{Arguments: map[string]any{"session_token": "session-token", "grant_project": "later"}}, projectRoot); err == nil {
		t.Fatal("expected invalid grant_project scope")
	}

	grantProjectLeaseMCPFn = func(*store.Handle, string, string, store.GrantScope, time.Duration) (store.ProjectLease, error) {
		return store.ProjectLease{}, errors.New("grant project failed")
	}
	if _, _, err := requireMCPProjectAuthorization(context.Background(), handle, toolCall{Arguments: map[string]any{"session_token": "session-token", "grant_project": "window"}}, projectRoot); err == nil || !strings.Contains(err.Error(), "grant project failed") {
		t.Fatalf("expected grant_project failure, got %v", err)
	}
	grantProjectLeaseMCPFn = origGrantProject

	authorizeAndConsumeMCPFn = func(*store.Handle, store.AccessRequest) (store.AccessDecision, error) {
		return store.AccessDecision{}, errors.New("consume failed")
	}
	if _, _, err := requireMCPProjectAuthorization(context.Background(), handle, toolCall{Arguments: map[string]any{"session_token": "session-token"}}, projectRoot); err == nil || !strings.Contains(err.Error(), "consume failed") {
		t.Fatalf("expected consume failure, got %v", err)
	}

	authorizeAndConsumeMCPFn = func(*store.Handle, store.AccessRequest) (store.AccessDecision, error) {
		return store.AccessDecision{RequiresPrompt: true, Reason: "project_lease_required"}, nil
	}
	if _, _, err := requireMCPProjectAuthorization(context.Background(), handle, toolCall{Arguments: map[string]any{"session_token": "session-token"}}, projectRoot); err == nil || !strings.Contains(err.Error(), "project_lease_required") {
		t.Fatalf("expected approval required, got %v", err)
	}
}

func TestCoverageSecretUpsertInvalidGrantScopes(t *testing.T) {
	lockMCPSeams(t)
	origEnsureSession := ensureSessionFn
	t.Cleanup(func() { ensureSessionFn = origEnsureSession })
	handle, projectRoot := newMCPCoverageHandle(t)
	ensureSessionFn = func(context.Context, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "session-token"}, nil
	}
	if _, err := callSecretUpsert(context.Background(), handle, toolCall{Name: "hasp_secret_add", Arguments: map[string]any{
		"project_root":  projectRoot,
		"name":          "NEW_TOKEN",
		"value":         "abc",
		"grant_project": "later",
	}}, false); err == nil {
		t.Fatal("expected invalid project grant")
	}
	if _, err := callSecretUpsert(context.Background(), handle, toolCall{Name: "hasp_secret_add", Arguments: map[string]any{
		"project_root": projectRoot,
		"name":         "OTHER_TOKEN",
		"value":        "abc",
		"grant_secret": "later",
	}}, false); err == nil {
		t.Fatal("expected invalid secret grant")
	}
}

func newMCPCoverageHandle(t *testing.T) (*store.Handle, string) {
	t.Helper()
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, filepath.Join(baseDir, "home"))
	vaultStore, err := store.New(nil)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "secret-password"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "secret-password")
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}
	projectRoot := filepath.Join(baseDir, "project")
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	if out, err := initTestGitRepo(projectRoot); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{Policy: store.PolicySession}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "api_token"}, store.PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, "session-token", store.GrantSession, 0); err != nil {
		t.Fatalf("grant project: %v", err)
	}
	return handle, projectRoot
}
