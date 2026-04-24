package mcp

import (
	"context"
	"os"
	"os/exec"
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
	if out, err := exec.Command("git", "-C", projectRoot, "init").CombinedOutput(); err != nil {
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
	if got["named_reference"] != "@API_TOKEN" {
		t.Fatalf("expected named reference metadata, got %+v", got)
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

	deleted, err := callSecretDelete(context.Background(), handle, toolCall{Name: "hasp_secret_delete", Arguments: map[string]any{
		"name":       "API_TOKEN",
		"host_label": "claude-code",
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

	auditData, err := os.ReadFile(filepath.Join(homeDir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(auditData), "secret.expose") || !strings.Contains(string(auditData), "secret.hide") {
		t.Fatalf("expected expose/hide actions in audit log, got %q", string(auditData))
	}
}
