package mcp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/hooks"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestEnsureProjectBindingMCPReusesExistingBindingWithoutAutoAdoptChecks(t *testing.T) {
	lockMCPSeams(t)

	handle := newProjectContextMCPHandle(t)
	projectRoot := t.TempDir()
	binding, err := handle.UpsertBinding(context.Background(), projectRoot, nil, store.PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}

	origLoad := loadCLIConfigMCPFn
	origCanonical := canonicalProjectRootMCPFn
	defer func() {
		loadCLIConfigMCPFn = origLoad
		canonicalProjectRootMCPFn = origCanonical
	}()
	loadCLIConfigMCPFn = func() (paths.CLIConfig, error) {
		return paths.CLIConfig{}, errors.New("defaults should not load for existing binding")
	}
	canonicalProjectRootMCPFn = func(context.Context, string) (string, error) {
		return "", errors.New("canonicalization should not run for existing binding")
	}

	resolved, _, err := ensureProjectBindingMCP(context.Background(), handle, projectRoot)
	if err != nil {
		t.Fatalf("ensure project binding: %v", err)
	}
	if resolved.ID != binding.ID {
		t.Fatalf("binding id=%q, want %q", resolved.ID, binding.ID)
	}
}

func TestEnsureProjectBindingExplicitMCPRejectsNonGitRoot(t *testing.T) {
	lockMCPSeams(t)

	handle := newProjectContextMCPHandle(t)
	origLoad := loadCLIConfigMCPFn
	defer func() { loadCLIConfigMCPFn = origLoad }()
	loadCLIConfigMCPFn = func() (paths.CLIConfig, error) { return paths.CLIConfig{}, nil }

	if _, _, err := ensureProjectBindingExplicitMCP(context.Background(), handle, t.TempDir()); err == nil || !strings.Contains(err.Error(), "not a git repo") {
		t.Fatalf("expected non-git refusal, got %v", err)
	}
}

func TestEnsureProjectBindingExplicitMCPInstallsHookBeforeRecordingHookInstalled(t *testing.T) {
	lockMCPSeams(t)

	handle := newProjectContextMCPHandle(t)
	gitRoot := t.TempDir()
	if out, err := initTestGitRepo(gitRoot); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	origLoad := loadCLIConfigMCPFn
	defer func() { loadCLIConfigMCPFn = origLoad }()
	loadCLIConfigMCPFn = func() (paths.CLIConfig, error) { return paths.CLIConfig{}, nil }

	binding, _, err := ensureProjectBindingExplicitMCP(context.Background(), handle, gitRoot)
	if err != nil {
		t.Fatalf("ensure project binding explicit: %v", err)
	}
	if !binding.HookInstalled {
		t.Fatalf("binding=%+v, want HookInstalled true", binding)
	}
	plan, err := hooks.ResolveInstallPlan(gitRoot)
	if err != nil {
		t.Fatalf("resolve hooks path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(plan.HooksDir, "pre-commit")); err != nil {
		t.Fatalf("expected installed pre-commit hook: %v", err)
	}
}

func newProjectContextMCPHandle(t *testing.T) *store.Handle {
	t.Helper()
	t.Setenv(paths.EnvHome, t.TempDir())

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
	return handle
}
