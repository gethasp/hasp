package mcp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestSecretToolEdgeBranches(t *testing.T) {
	lockMCPSeams(t)

	origEnsureSession := ensureSessionFn
	origLoadCLI := loadCLIConfigMCPFn
	origAudit := newMCPAuditLogFn
	origCanonical := canonicalProjectRootMCPFn
	origResolveBinding := resolveBindingViewMCPFn
	origUpsertItem := upsertItemMCPFn
	origBindAlias := bindItemAliasMCPFn
	origHideItem := hideItemMCPFn
	origUpsertBinding := upsertBindingMCPFn
	defer func() {
		ensureSessionFn = origEnsureSession
		loadCLIConfigMCPFn = origLoadCLI
		newMCPAuditLogFn = origAudit
		canonicalProjectRootMCPFn = origCanonical
		resolveBindingViewMCPFn = origResolveBinding
		upsertItemMCPFn = origUpsertItem
		bindItemAliasMCPFn = origBindAlias
		hideItemMCPFn = origHideItem
		upsertBindingMCPFn = origUpsertBinding
	}()

	baseDir := t.TempDir()
	homeDir := filepath.Join(baseDir, "home")
	gitRoot := filepath.Join(baseDir, "project")
	t.Setenv(paths.EnvHome, homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "secret-password")

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

	loadCLIConfigMCPFn = func() (paths.CLIConfig, error) { return paths.CLIConfig{}, nil }
	ensureSessionFn = func(context.Context, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "session-token"}, nil
	}

	if _, err := callTool(context.Background(), toolCall{Name: "hasp_secret_get", Arguments: map[string]any{"name": "missing"}}); err != nil {
		t.Fatalf("callTool secret_get missing should be handled, got %v", err)
	}
	if _, err := callTool(context.Background(), toolCall{Name: "unsupported_tool", Arguments: map[string]any{}}); err == nil {
		t.Fatal("expected unsupported tool error")
	}
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_capture", Arguments: map[string]any{"name": "captured", "value": "abc123"}}); err == nil || !strings.Contains(err.Error(), mcpEnvUnsafeWriteTools) {
		t.Fatalf("expected default capture refusal, got %v", err)
	}
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_secret_add", Arguments: map[string]any{"name": "API_TOKEN", "value": "abc123"}}); err == nil || !strings.Contains(err.Error(), mcpEnvUnsafeWriteTools) {
		t.Fatalf("expected default unsafe write-tool refusal, got %v", err)
	}
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_secret_update", Arguments: map[string]any{"name": "API_TOKEN", "value": "abc123"}}); err == nil || !strings.Contains(err.Error(), mcpEnvUnsafeWriteTools) {
		t.Fatalf("expected default update refusal, got %v", err)
	}
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_secret_delete", Arguments: map[string]any{"name": "API_TOKEN"}}); err == nil || !strings.Contains(err.Error(), mcpEnvUnsafeWriteTools) {
		t.Fatalf("expected default delete refusal, got %v", err)
	}
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_secret_expose", Arguments: map[string]any{"project_root": gitRoot, "name": "API_TOKEN"}}); err == nil || !strings.Contains(err.Error(), mcpEnvUnsafeWriteTools) {
		t.Fatalf("expected default expose refusal, got %v", err)
	}
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_secret_hide", Arguments: map[string]any{"project_root": gitRoot, "name": "API_TOKEN"}}); err == nil || !strings.Contains(err.Error(), mcpEnvUnsafeWriteTools) {
		t.Fatalf("expected default hide refusal, got %v", err)
	}
	t.Setenv(mcpEnvUnsafeWriteTools, "1")
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_secret_add", Arguments: map[string]any{"name": "API_TOKEN", "value": "abc123"}}); err != nil {
		t.Fatalf("callTool secret_add: %v", err)
	}
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_secret_update", Arguments: map[string]any{"name": "API_TOKEN", "value": "updated"}}); err != nil {
		t.Fatalf("callTool secret_update: %v", err)
	}
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_secret_get", Arguments: map[string]any{"name": "API_TOKEN"}}); err != nil {
		t.Fatalf("callTool secret_get existing: %v", err)
	}
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_secret_delete", Arguments: map[string]any{"name": "API_TOKEN"}}); err == nil || !strings.Contains(err.Error(), "project_root and name are required") {
		t.Fatalf("expected delete without project root to fail closed, got %v", err)
	}

	if _, err := callSecretAdd(context.Background(), handle, toolCall{Name: "hasp_secret_add", Arguments: map[string]any{}}); err == nil {
		t.Fatal("expected missing add args failure")
	}
	if _, err := callSecretAdd(context.Background(), handle, toolCall{Name: "hasp_secret_add", Arguments: map[string]any{"name": "NO_VALUE"}}); err == nil {
		t.Fatal("expected missing add value failure")
	}
	if _, err := callSecretUpdate(context.Background(), handle, toolCall{Name: "hasp_secret_update", Arguments: map[string]any{"name": "MISSING", "value": "abc"}}); !errors.Is(err, store.ErrItemNotFound) {
		t.Fatalf("expected update missing item failure, got %v", err)
	}
	resolveBindingViewMCPFn = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{}, nil, errors.New("resolve fail")
	}
	if _, err := callSecretAdd(context.Background(), handle, toolCall{Name: "hasp_secret_add", Arguments: map[string]any{"project_root": gitRoot, "name": "BROKEN_BINDING", "value": "abc", "grant_project": "window", "grant_write": true}}); err == nil || !strings.Contains(err.Error(), "resolve fail") {
		t.Fatalf("expected resolve binding failure, got %v", err)
	}
	resolveBindingViewMCPFn = origResolveBinding
	origGetItem := getItemMCPFn
	getItemMCPFn = func(*store.Handle, string) (store.Item, error) { return store.Item{}, errors.New("get item fail") }
	if _, err := callSecretAdd(context.Background(), handle, toolCall{Name: "hasp_secret_add", Arguments: map[string]any{"name": "BROKEN", "value": "abc"}}); err == nil || !strings.Contains(err.Error(), "get item fail") {
		t.Fatalf("expected get item failure, got %v", err)
	}
	getItemMCPFn = origGetItem
	if _, err := callSecretAdd(context.Background(), handle, toolCall{Name: "hasp_secret_add", Arguments: map[string]any{"name": "INLINE", "value": "abc"}}); err != nil {
		t.Fatalf("inline secret add: %v", err)
	}
	if _, err := callSecretAdd(context.Background(), handle, toolCall{Name: "hasp_secret_add", Arguments: map[string]any{"name": "INLINE", "value": "abc"}}); err == nil {
		t.Fatal("expected duplicate add failure")
	}
	if result, err := callSecretAdd(context.Background(), handle, toolCall{Name: "hasp_secret_add", Arguments: map[string]any{"name": "INLINE", "value": "abc", "on_conflict": "skip"}}); err != nil || result["outcome"] != "skipped" {
		t.Fatalf("expected skip collision result, got %+v err=%v", result, err)
	}
	if result, err := callSecretAdd(context.Background(), handle, toolCall{Name: "hasp_secret_add", Arguments: map[string]any{"name": "INLINE", "value": "rotated", "on_conflict": "replace"}}); err != nil || result["outcome"] != "updated" {
		t.Fatalf("expected replace collision result, got %+v err=%v", result, err)
	}
	upsertItemMCPFn = func(*store.Handle, string, store.ItemKind, []byte, store.ItemMetadata) (store.Item, error) {
		return store.Item{}, errors.New("upsert fail")
	}
	if _, err := callSecretAdd(context.Background(), handle, toolCall{Name: "hasp_secret_add", Arguments: map[string]any{"name": "UPSERT_FAIL", "value": "abc"}}); err == nil || !strings.Contains(err.Error(), "upsert fail") {
		t.Fatalf("expected inline upsert failure, got %v", err)
	}
	upsertItemMCPFn = origUpsertItem

	if got, err := callSecretGet(context.Background(), handle, toolCall{Name: "hasp_secret_get", Arguments: map[string]any{"name": "MISSING"}}); err != nil || got["exists"] != false {
		t.Fatalf("expected missing get result, got %+v err=%v", got, err)
	}
	getItemMCPFn = func(*store.Handle, string) (store.Item, error) { return store.Item{}, errors.New("get fail") }
	if _, err := callSecretGet(context.Background(), handle, toolCall{Name: "hasp_secret_get", Arguments: map[string]any{"name": "INLINE"}}); err == nil || !strings.Contains(err.Error(), "get fail") {
		t.Fatalf("expected get failure branch, got %v", err)
	}
	getItemMCPFn = origGetItem
	if got, err := callSecretGet(context.Background(), handle, toolCall{Name: "hasp_secret_get", Arguments: map[string]any{"name": "INLINE", "project_root": gitRoot}}); err == nil && got["available_in_project"] != false {
		t.Fatalf("expected non-exposed secret to be unavailable in project, got %+v", got)
	}
	if _, err := callSecretGet(context.Background(), handle, toolCall{Name: "hasp_secret_get", Arguments: map[string]any{}}); err == nil {
		t.Fatal("expected missing get name failure")
	}
	canonicalProjectRootMCPFn = func(context.Context, string) (string, error) { return "", errors.New("canonical fail") }
	if _, err := callSecretGet(context.Background(), handle, toolCall{Name: "hasp_secret_get", Arguments: map[string]any{"name": "INLINE", "project_root": "repo"}}); err == nil || !strings.Contains(err.Error(), "canonical fail") {
		t.Fatalf("expected canonical failure for project-scoped get, got %v", err)
	}
	canonicalProjectRootMCPFn = origCanonical
	if err := os.MkdirAll(gitRoot, 0o755); err != nil {
		t.Fatalf("mkdir git root: %v", err)
	}
	if out, err := initTestGitRepo(gitRoot); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	mutationBinding, err := handle.UpsertBinding(context.Background(), gitRoot, map[string]string{}, store.PolicySession, false)
	if err != nil {
		t.Fatalf("upsert mutation binding: %v", err)
	}
	if _, err := handle.GrantProjectLease(mutationBinding.ID, "session-token", store.GrantSession, 0); err != nil {
		t.Fatalf("grant mutation project lease: %v", err)
	}
	grantMutation := func(itemName string, action store.SecretMutationAction) {
		t.Helper()
		if _, err := handle.GrantSecretMutation(mutationBinding.ID, "session-token", itemName, action, "user", store.GrantOnce, store.DefaultMutationGrantTTL); err != nil {
			t.Fatalf("grant mutation %s/%s: %v", itemName, action, err)
		}
	}
	mutationArgs := func(values map[string]any) map[string]any {
		args := map[string]any{
			"project_root": gitRoot,
		}
		for key, value := range values {
			args[key] = value
		}
		return args
	}

	nonRepo := t.TempDir()
	if _, err := callSecretExpose(context.Background(), handle, toolCall{Name: "hasp_secret_expose", Arguments: map[string]any{"name": "INLINE"}}); err == nil {
		t.Fatal("expected expose missing args failure")
	}
	if _, err := callSecretExpose(context.Background(), handle, toolCall{Name: "hasp_secret_expose", Arguments: map[string]any{"project_root": nonRepo, "name": "INLINE"}}); err == nil {
		t.Fatal("expected expose on non-git root to fail")
	}
	if _, err := callSecretExpose(context.Background(), handle, toolCall{Name: "hasp_secret_expose", Arguments: map[string]any{"project_root": gitRoot, "name": "MISSING"}}); !errors.Is(err, store.ErrItemNotFound) {
		t.Fatalf("expected expose missing-item failure, got %v", err)
	}
	bindItemAliasMCPFn = func(*store.Handle, context.Context, string, string) (string, error) {
		return "", errors.New("bind fail")
	}
	grantMutation("INLINE", store.SecretMutationExpose)
	if _, err := callSecretExpose(context.Background(), handle, toolCall{Name: "hasp_secret_expose", Arguments: mutationArgs(map[string]any{"name": "INLINE"})}); err == nil || !strings.Contains(err.Error(), "bind fail") {
		t.Fatalf("expected expose bind failure, got %v", err)
	}
	bindItemAliasMCPFn = origBindAlias
	if _, err := callSecretHide(context.Background(), handle, toolCall{Name: "hasp_secret_hide", Arguments: map[string]any{"name": "INLINE"}}); err == nil {
		t.Fatal("expected hide missing args failure")
	}
	canonicalProjectRootMCPFn = func(context.Context, string) (string, error) { return "", errors.New("hide canonical fail") }
	grantMutation("INLINE", store.SecretMutationHide)
	if _, err := callSecretHide(context.Background(), handle, toolCall{Name: "hasp_secret_hide", Arguments: mutationArgs(map[string]any{"project_root": t.TempDir(), "name": "INLINE"})}); err == nil || !strings.Contains(err.Error(), "hide canonical fail") {
		t.Fatalf("expected hide canonical failure, got %v", err)
	}
	canonicalProjectRootMCPFn = origCanonical
	hideItemMCPFn = func(*store.Handle, context.Context, string, string) ([]string, error) {
		return nil, errors.New("hide fail")
	}
	grantMutation("INLINE", store.SecretMutationHide)
	if _, err := callSecretHide(context.Background(), handle, toolCall{Name: "hasp_secret_hide", Arguments: mutationArgs(map[string]any{"name": "INLINE"})}); err == nil || !strings.Contains(err.Error(), "hide fail") {
		t.Fatalf("expected hide store failure, got %v", err)
	}
	hideItemMCPFn = origHideItem
	grantMutation("INLINE", store.SecretMutationHide)
	if result, err := callSecretHide(context.Background(), handle, toolCall{Name: "hasp_secret_hide", Arguments: mutationArgs(map[string]any{"name": "INLINE"})}); err != nil || result["outcome"] != "already_hidden" {
		t.Fatalf("expected already_hidden result, got %+v err=%v", result, err)
	}

	grantMutation("INLINE", store.SecretMutationExpose)
	if _, err := callSecretExpose(context.Background(), handle, toolCall{Name: "hasp_secret_expose", Arguments: mutationArgs(map[string]any{"name": "INLINE", "host_label": "claude-code"})}); err != nil {
		t.Fatalf("secret expose: %v", err)
	}
	grantMutation("INLINE", store.SecretMutationExpose)
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_secret_expose", Arguments: mutationArgs(map[string]any{"name": "INLINE", "host_label": "claude-code"})}); err != nil {
		t.Fatalf("callTool secret_expose: %v", err)
	}
	grantMutation("INLINE", store.SecretMutationExpose)
	if result, err := callSecretExpose(context.Background(), handle, toolCall{Name: "hasp_secret_expose", Arguments: mutationArgs(map[string]any{"name": "INLINE", "host_label": "claude-code"})}); err != nil || result["outcome"] != "already_exposed" {
		t.Fatalf("expected already_exposed result, got %+v err=%v", result, err)
	}
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_secret_expose", Arguments: map[string]any{"project_root": gitRoot, "name": "INLINE", "grant_write": true}}); err == nil || !strings.Contains(err.Error(), "secret mutation grant required") {
		t.Fatalf("expected expose without grants to fail closed, got %v", err)
	}
	grantMutation("INLINE", store.SecretMutationHide)
	if result, err := callSecretHide(context.Background(), handle, toolCall{Name: "hasp_secret_hide", Arguments: mutationArgs(map[string]any{"name": "INLINE", "host_label": "claude-code"})}); err != nil || result["outcome"] != "hidden" {
		t.Fatalf("expected hidden result, got %+v err=%v", result, err)
	}
	grantMutation("INLINE", store.SecretMutationHide)
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_secret_hide", Arguments: mutationArgs(map[string]any{"name": "INLINE", "host_label": "claude-code"})}); err != nil {
		t.Fatalf("callTool secret_hide: %v", err)
	}
	grantMutation("INLINE", store.SecretMutationHide)
	if result, err := callSecretHide(context.Background(), handle, toolCall{Name: "hasp_secret_hide", Arguments: mutationArgs(map[string]any{"name": "INLINE", "host_label": "claude-code"})}); err != nil || result["outcome"] != "already_hidden" {
		t.Fatalf("expected already_hidden result, got %+v err=%v", result, err)
	}
	if _, err := callSecretDelete(context.Background(), handle, toolCall{Name: "hasp_secret_delete", Arguments: map[string]any{}}); err == nil {
		t.Fatal("expected delete missing args failure")
	}
	if _, err := callSecretDelete(context.Background(), handle, toolCall{Name: "hasp_secret_delete", Arguments: mutationArgs(map[string]any{"name": "MISSING"})}); !errors.Is(err, store.ErrItemNotFound) {
		t.Fatalf("expected delete missing secret failure, got %v", err)
	}
	grantMutation("INLINE", store.SecretMutationDelete)
	if _, err := callTool(context.Background(), toolCall{Name: "hasp_secret_delete", Arguments: mutationArgs(map[string]any{"name": "INLINE", "host_label": "claude-code"})}); err != nil {
		t.Fatalf("callTool secret_delete: %v", err)
	}

	if got := existingExposureReferenceMCP(nil, gitRoot); got != "" {
		t.Fatalf("expected empty existingExposureReferenceMCP, got %q", got)
	}
	if got := existingExposureReferenceMCP([]store.ItemExposure{{ProjectRoot: gitRoot, Reference: "secret_01"}}, gitRoot); got != "secret_01" {
		t.Fatalf("expected matching existing exposure ref, got %q", got)
	}

	newMCPAuditLogFn = func() (*audit.Log, error) { return nil, errors.New("audit fail") }
	appendSecretAuditMCP("secret.test", "agent", map[string]any{"action": "secret.test"})

	loadCLIConfigMCPFn = func() (paths.CLIConfig, error) { return paths.CLIConfig{}, errors.New("load fail") }
	unboundGitRoot := filepath.Join(baseDir, "unbound-project")
	if err := os.MkdirAll(unboundGitRoot, 0o755); err != nil {
		t.Fatalf("mkdir unbound git root: %v", err)
	}
	if out, err := initTestGitRepo(unboundGitRoot); err != nil {
		t.Fatalf("git init unbound project: %v: %s", err, out)
	}
	if _, _, err := ensureProjectBindingExplicitMCP(context.Background(), handle, unboundGitRoot); err == nil || !strings.Contains(err.Error(), "load fail") {
		t.Fatalf("expected load failure, got %v", err)
	}
	loadCLIConfigMCPFn = func() (paths.CLIConfig, error) { return paths.CLIConfig{}, nil }
	canonicalProjectRootMCPFn = func(context.Context, string) (string, error) { return "", errors.New("canonical fail") }
	if _, _, err := ensureProjectBindingExplicitMCP(context.Background(), handle, unboundGitRoot); err == nil || !strings.Contains(err.Error(), "canonical fail") {
		t.Fatalf("expected canonical failure, got %v", err)
	}
	canonicalProjectRootMCPFn = origCanonical
	upsertBindingMCPFn = func(*store.Handle, context.Context, string, map[string]string, store.SecretPolicy, bool) (store.Binding, error) {
		return store.Binding{}, errors.New("upsert binding fail")
	}
	if _, _, err := ensureProjectBindingExplicitMCP(context.Background(), handle, unboundGitRoot); err == nil || !strings.Contains(err.Error(), "upsert binding fail") {
		t.Fatalf("expected upsert binding failure, got %v", err)
	}
	upsertBindingMCPFn = origUpsertBinding
	if binding, _, err := ensureProjectBindingExplicitMCP(context.Background(), handle, gitRoot); err != nil || binding.ID == "" {
		t.Fatalf("expected existing binding to pass, got %+v err=%v", binding, err)
	}

	ensureSessionFn = func(context.Context, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{}, errors.New("session fail")
	}
	if _, err := callSecretAdd(context.Background(), handle, toolCall{Name: "hasp_secret_add", Arguments: map[string]any{"project_root": gitRoot, "name": "SESSION_FAIL", "value": "abc", "grant_project": "window", "grant_write": true}}); err == nil || !strings.Contains(err.Error(), "session fail") {
		t.Fatalf("expected session failure on repo add, got %v", err)
	}
	if _, err := callSecretUpdate(context.Background(), handle, toolCall{Name: "hasp_secret_update", Arguments: map[string]any{"project_root": gitRoot, "name": "INLINE", "value": "abc", "grant_project": "window", "grant_write": true}}); err == nil || !strings.Contains(err.Error(), "session fail") {
		t.Fatalf("expected session failure on repo update, got %v", err)
	}
	ensureSessionFn = origEnsureSession
	ensureSessionFn = func(context.Context, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "session-token"}, nil
	}
	if _, err := callSecretAdd(context.Background(), handle, toolCall{Name: "hasp_secret_add", Arguments: map[string]any{"project_root": gitRoot, "name": "NO_GRANT", "value": "abc", "grant_project": "window"}}); err == nil || !strings.Contains(err.Error(), "write grant") {
		t.Fatalf("expected authorize capture failure, got %v", err)
	}
	origCapture := captureMCPFn
	captureMCPFn = func(*store.Handle, context.Context, string, string, store.ItemKind, []byte, bool) (store.CaptureResult, error) {
		return store.CaptureResult{}, errors.New("capture fail")
	}
	if _, err := callSecretAdd(context.Background(), handle, toolCall{Name: "hasp_secret_add", Arguments: map[string]any{"project_root": gitRoot, "name": "CAPTURE_FAIL", "value": "abc", "grant_project": "window", "grant_write": true}}); err == nil || !strings.Contains(err.Error(), "capture fail") {
		t.Fatalf("expected capture failure, got %v", err)
	}
	captureMCPFn = origCapture
}

func TestProtocolNegotiationResidualBranches(t *testing.T) {
	if got := negotiateProtocolVersion(nil); got != currentProtocolVersion {
		t.Fatalf("expected nil params to use current protocol, got %q", got)
	}
	if got := negotiateProtocolVersion([]byte("{bad json")); got != currentProtocolVersion {
		t.Fatalf("expected invalid params to use current protocol, got %q", got)
	}
}
