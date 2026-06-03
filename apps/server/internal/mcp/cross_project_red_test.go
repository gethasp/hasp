package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func newMCPHandleForCrossProject(t *testing.T) (*store.Handle, string) {
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
	return handle, baseDir
}

func gitProject(t *testing.T, base, name string) string {
	t.Helper()
	root := filepath.Join(base, name)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", name, err)
	}
	if out, err := initTestGitRepo(root); err != nil {
		t.Fatalf("git init %s: %v: %s", name, err, out)
	}
	return root
}

// TestSecretGetDoesNotLeakOtherProjectExistence pins hasp-56ng: a caller
// authorized for project A must not learn that a secret bound only to project B
// exists. hasp_secret_get returns the not-found shape for it.
func TestSecretGetDoesNotLeakOtherProjectExistence(t *testing.T) {
	lockMCPSeams(t)
	origEnsureSession := ensureSessionFn
	origLoadCLI := loadCLIConfigMCPFn
	defer func() { ensureSessionFn = origEnsureSession; loadCLIConfigMCPFn = origLoadCLI }()
	loadCLIConfigMCPFn = func() (paths.CLIConfig, error) { return paths.CLIConfig{}, nil }
	ensureSessionFn = func(context.Context, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "session-token"}, nil
	}

	handle, base := newMCPHandleForCrossProject(t)
	projectA := gitProject(t, base, "project-a")
	projectB := gitProject(t, base, "project-b")

	// Secret bound only to project B.
	if _, err := callSecretAdd(context.Background(), handle, toolCall{Name: "hasp_secret_add", Arguments: map[string]any{
		"project_root": projectB, "name": "OTHER_PROJECT_SECRET", "value": "topsecret",
		"grant_project": "window", "grant_write": true, "host_label": "claude-code",
	}}); err != nil {
		t.Fatalf("secret add to project B: %v", err)
	}

	// Authorize project A (bound + active lease) so the get reaches the lookup.
	bindingA, err := handle.UpsertBinding(context.Background(), projectA, map[string]string{}, store.PolicySession, false)
	if err != nil {
		t.Fatalf("bind project A: %v", err)
	}
	if _, err := handle.GrantProjectLease(bindingA.ID, "session-token", store.GrantSession, 0); err != nil {
		t.Fatalf("grant project A lease: %v", err)
	}

	got, err := callSecretGet(context.Background(), handle, toolCall{Name: "hasp_secret_get", Arguments: map[string]any{
		"project_root": projectA, "name": "OTHER_PROJECT_SECRET", "session_token": "session-token",
	}})
	if err != nil {
		t.Fatalf("secret get from project A: %v", err)
	}
	if got["exists"] != false {
		t.Fatalf("cross-project oracle: project A learned project B's secret exists: %+v", got)
	}
	if _, leaked := got["kind"]; leaked {
		t.Fatalf("cross-project oracle leaked kind/metadata: %+v", got)
	}
}

// TestTargetExplainRequiresBoundProject pins hasp-adm3: explaining a manifest
// target requires the project to be hasp-managed; an unbound project_root is
// rejected before any manifest is read.
func TestTargetExplainRequiresBoundProject(t *testing.T) {
	lockMCPSeams(t)
	origEnsureSession := ensureSessionFn
	defer func() { ensureSessionFn = origEnsureSession }()
	ensureSessionFn = func(context.Context, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "session-token"}, nil
	}
	handle, base := newMCPHandleForCrossProject(t)
	unbound := gitProject(t, base, "unbound")

	if _, err := callTargetExplain(context.Background(), handle, toolCall{Name: "hasp_target_explain", Arguments: map[string]any{
		"project_root": unbound, "target": "build.config",
	}}); err == nil {
		t.Fatal("expected target_explain to reject an unbound project")
	}
}
