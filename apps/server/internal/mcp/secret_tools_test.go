package mcp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestSecretToolsLifecycleAndMetadataOnlyGet(t *testing.T) {
	lockMCPSeams(t)

	origEnsureSession := ensureSessionFn
	origLoadCLI := loadCLIConfigMCPFn
	defer func() {
		ensureSessionFn = origEnsureSession
		loadCLIConfigMCPFn = origLoadCLI
	}()

	baseDir := t.TempDir()
	homeDir := filepath.Join(baseDir, "home")
	t.Setenv(paths.EnvHome, homeDir)

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
		t.Fatalf("mkdir project root: %v", err)
	}
	if out, err := initTestGitRepo(projectRoot); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	loadCLIConfigMCPFn = func() (paths.CLIConfig, error) {
		return paths.CLIConfig{}, nil
	}
	ensureSessionFn = func(context.Context, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "session-token"}, nil
	}

	added, err := callSecretAdd(context.Background(), handle, toolCall{Name: "hasp_secret_add", Arguments: map[string]any{
		"project_root":  projectRoot,
		"name":          "API_TOKEN",
		"value":         "abc123",
		"grant_project": "window",
		"grant_write":   true,
		"host_label":    "claude-code",
	}})
	if err != nil {
		t.Fatalf("secret add: %v", err)
	}
	if added["reference"] != "secret_01" || added["outcome"] != "created" {
		t.Fatalf("unexpected add result %+v", added)
	}
	if added["named_reference"] != "@API_TOKEN" {
		t.Fatalf("expected named reference in add result, got %+v", added)
	}
	binding, _, err := handle.ResolveBindingView(context.Background(), projectRoot)
	if err != nil {
		t.Fatalf("resolve binding: %v", err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, "session-token", store.GrantSession, 0); err != nil {
		t.Fatalf("grant project lease: %v", err)
	}
	t.Setenv(mcpEnvSessionToken, "session-token")
	grantMutation := func(action store.SecretMutationAction) {
		t.Helper()
		if _, err := handle.GrantSecretMutation(binding.ID, "session-token", "API_TOKEN", action, "user", store.GrantOnce, store.DefaultMutationGrantTTL); err != nil {
			t.Fatalf("grant mutation %s: %v", action, err)
		}
	}

	got, err := callSecretGet(context.Background(), handle, toolCall{Name: "hasp_secret_get", Arguments: map[string]any{
		"project_root": projectRoot,
		"name":         "API_TOKEN",
	}})
	if err != nil {
		t.Fatalf("secret get: %v", err)
	}
	if got["exists"] != true || got["available_in_project"] != true || got["reference"] != "secret_01" {
		t.Fatalf("unexpected secret get result %+v", got)
	}
	gotProjectRoot, ok := got["project_root"].(string)
	if !ok {
		t.Fatalf("expected project_root string in secret get result, got %+v", got)
	}
	wantProjectRoot, err := filepath.EvalSymlinks(projectRoot)
	if err != nil {
		t.Fatalf("resolve expected project root: %v", err)
	}
	resolvedGotProjectRoot, err := filepath.EvalSymlinks(gotProjectRoot)
	if err != nil {
		t.Fatalf("resolve returned project root: %v", err)
	}
	if resolvedGotProjectRoot != wantProjectRoot {
		t.Fatalf("expected canonical project root %q in secret get result, got %+v", wantProjectRoot, got)
	}
	if got["named_reference"] != "@API_TOKEN" {
		t.Fatalf("expected named reference metadata, got %+v", got)
	}
	recovery, ok := got["recovery"].(map[string]any)
	if !ok || recovery["status"] != "available" || recovery["mutation_protected"] != false {
		t.Fatalf("expected available recovery metadata, got %+v", got["recovery"])
	}
	if _, ok := got["value"]; ok {
		t.Fatalf("metadata-only secret get leaked raw value: %+v", got)
	}

	skipped, err := callSecretAdd(context.Background(), handle, toolCall{Name: "hasp_secret_add", Arguments: map[string]any{
		"project_root":  projectRoot,
		"name":          "API_TOKEN",
		"value":         "ignored",
		"grant_project": "window",
		"grant_write":   true,
		"on_conflict":   "skip",
	}})
	if err != nil {
		t.Fatalf("secret add skip collision: %v", err)
	}
	if skipped["outcome"] != "skipped" {
		t.Fatalf("expected skipped collision result, got %+v", skipped)
	}

	updated, err := callSecretUpdate(context.Background(), handle, toolCall{Name: "hasp_secret_update", Arguments: map[string]any{
		"project_root":  projectRoot,
		"name":          "API_TOKEN",
		"value":         "rotated",
		"grant_project": "window",
		"host_label":    "claude-code",
	}})
	if err != nil {
		t.Fatalf("secret update: %v", err)
	}
	if updated["outcome"] != "updated" {
		t.Fatalf("unexpected update result %+v", updated)
	}
	item, err := handle.GetItem("API_TOKEN")
	if err != nil || string(item.Value) != "rotated" {
		t.Fatalf("expected rotated secret value, got %+v err=%v", item, err)
	}

	grantMutation(store.SecretMutationHide)
	hidden, err := callSecretHide(context.Background(), handle, toolCall{Name: "hasp_secret_hide", Arguments: map[string]any{
		"project_root": projectRoot,
		"name":         "API_TOKEN",
		"host_label":   "claude-code",
	}})
	if err != nil {
		t.Fatalf("secret hide: %v", err)
	}
	if hidden["outcome"] != "hidden" {
		t.Fatalf("unexpected hide result %+v", hidden)
	}
	got, err = callSecretGet(context.Background(), handle, toolCall{Name: "hasp_secret_get", Arguments: map[string]any{
		"project_root": projectRoot,
		"name":         "API_TOKEN",
	}})
	if err != nil {
		t.Fatalf("secret get after hide: %v", err)
	}
	if got["available_in_project"] != false || got["reference"] != "" {
		t.Fatalf("expected hidden secret to be unavailable in repo, got %+v", got)
	}
	recovery, ok = got["recovery"].(map[string]any)
	if !ok {
		t.Fatalf("expected hidden secret metadata to include structured recovery metadata, got %+v", got)
	}
	if recovery["status"] != "not_exposed_in_project" || recovery["mutation_protected"] != true || recovery["unsafe_mcp_tool_required"] != true {
		t.Fatalf("unexpected hidden-secret recovery metadata %+v", recovery)
	}
	args, ok := recovery["cli_args"].([]string)
	if !ok || len(args) != 6 || strings.Join(args[:5], " ") != "hasp secret expose API_TOKEN --project-root" {
		t.Fatalf("unexpected hidden-secret recovery args %+v", recovery["cli_args"])
	}
	resolvedArgProjectRoot, err := filepath.EvalSymlinks(args[5])
	if err != nil {
		t.Fatalf("resolve recovery project root: %v", err)
	}
	if resolvedArgProjectRoot != wantProjectRoot {
		t.Fatalf("expected recovery project root %q, got args %+v", wantProjectRoot, args)
	}

	grantMutation(store.SecretMutationExpose)
	exposed, err := callSecretExpose(context.Background(), handle, toolCall{Name: "hasp_secret_expose", Arguments: map[string]any{
		"project_root": projectRoot,
		"name":         "API_TOKEN",
		"host_label":   "claude-code",
	}})
	if err != nil {
		t.Fatalf("secret expose: %v", err)
	}
	if exposed["reference"] != "secret_01" {
		t.Fatalf("expected stable ref on re-expose, got %+v", exposed)
	}
	if exposed["named_reference"] != "@API_TOKEN" {
		t.Fatalf("expected named reference on expose, got %+v", exposed)
	}

	grantMutation(store.SecretMutationDelete)
	deleted, err := callSecretDelete(context.Background(), handle, toolCall{Name: "hasp_secret_delete", Arguments: map[string]any{
		"project_root": projectRoot,
		"name":         "API_TOKEN",
		"host_label":   "claude-code",
	}})
	if err != nil {
		t.Fatalf("secret delete: %v", err)
	}
	if deleted["outcome"] != "deleted" {
		t.Fatalf("unexpected delete result %+v", deleted)
	}
	got, err = callSecretGet(context.Background(), handle, toolCall{Name: "hasp_secret_get", Arguments: map[string]any{
		"project_root": projectRoot,
		"name":         "API_TOKEN",
	}})
	if err != nil {
		t.Fatalf("secret get after delete: %v", err)
	}
	if got["exists"] != false {
		t.Fatalf("expected deleted secret to report missing, got %+v", got)
	}
	if got["named_reference"] != "@API_TOKEN" {
		t.Fatalf("expected missing lookup to keep named reference hint, got %+v", got)
	}
	recovery, ok = got["recovery"].(map[string]any)
	if !ok || recovery["status"] != "missing_in_vault" || recovery["mutation_protected"] != true {
		t.Fatalf("expected missing-secret recovery metadata, got %+v", got["recovery"])
	}

	auditData, err := os.ReadFile(filepath.Join(homeDir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(auditData), "secret.expose") || !strings.Contains(string(auditData), "secret.hide") {
		t.Fatalf("expected expose/hide actions in audit log, got %q", string(auditData))
	}
}

func TestSecretMutationAuthorizationFailureBranches(t *testing.T) {
	lockMCPSeams(t)

	origEnsureSession := ensureSessionFn
	origLoadCLI := loadCLIConfigMCPFn
	origGetItem := getItemMCPFn
	defer func() {
		ensureSessionFn = origEnsureSession
		loadCLIConfigMCPFn = origLoadCLI
		getItemMCPFn = origGetItem
	}()

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
	if _, err := handle.UpsertItem("API_TOKEN", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{Policy: store.PolicySession}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertItem("BAD_POLICY", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{Policy: store.SecretPolicy("bad")}); err != nil {
		t.Fatalf("upsert bad-policy item: %v", err)
	}

	projectRoot := filepath.Join(baseDir, "project")
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatalf("mkdir project root: %v", err)
	}
	if out, err := initTestGitRepo(projectRoot); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	loadCLIConfigMCPFn = func() (paths.CLIConfig, error) {
		return paths.CLIConfig{}, nil
	}
	ensureSessionFn = func(context.Context, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{}, errors.New("session fail")
	}
	if _, err := callSecretExpose(context.Background(), handle, toolCall{Name: "hasp_secret_expose", Arguments: map[string]any{
		"project_root":  projectRoot,
		"name":          "API_TOKEN",
		"grant_project": "window",
		"grant_secret":  "session",
		"grant_write":   true,
	}}); err == nil || !strings.Contains(err.Error(), "session fail") {
		t.Fatalf("expected mutation session failure, got %v", err)
	}

	ensureSessionFn = func(context.Context, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "session-token"}, nil
	}
	if _, err := callSecretDelete(context.Background(), handle, toolCall{Name: "hasp_secret_delete", Arguments: map[string]any{
		"project_root":  projectRoot,
		"name":          "API_TOKEN",
		"grant_project": "window",
		"grant_secret":  "session",
		"grant_write":   true,
	}}); err == nil || !strings.Contains(err.Error(), "secret mutation grant required") {
		t.Fatalf("expected grant_write-only mutation failure, got %v", err)
	}

	getItemMCPFn = func(*store.Handle, string) (store.Item, error) {
		return store.Item{Name: "PHANTOM", Kind: store.ItemKindKV, Metadata: store.ItemMetadata{Policy: store.PolicySession}}, nil
	}
	binding, _, err := handle.ResolveBindingView(context.Background(), projectRoot)
	if err != nil {
		t.Fatalf("resolve binding: %v", err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, "session-token", store.GrantSession, 0); err != nil {
		t.Fatalf("grant project lease: %v", err)
	}
	if _, err := handle.GrantSecretMutation(binding.ID, "session-token", "PHANTOM", store.SecretMutationDelete, "user", store.GrantOnce, store.DefaultMutationGrantTTL); err != nil {
		t.Fatalf("grant phantom mutation: %v", err)
	}
	if _, err := callSecretDelete(context.Background(), handle, toolCall{Name: "hasp_secret_delete", Arguments: map[string]any{
		"project_root": projectRoot,
		"name":         "PHANTOM",
	}}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected delete storage failure, got %v", err)
	}
}
